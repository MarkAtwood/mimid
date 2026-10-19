//! Helpers for the three-provider end-to-end test: full provider stacks on
//! loopback, wired as `main.rs` wires them, behind a front that can script
//! `/notify` faults and keeps the port across a restart; raw reads of each
//! provider's follower log and captured outbox; and an agent's inbox,
//! reading a user's events through the follower API.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::FanoutMessage;
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::Directory;
use mimid_server::follower::Follower;
use mimid_server::follower::key_packages::KeyPackages;
use mimid_server::follower::relay::{LocalUser, Relay};
use mimid_server::http::router;
use mimid_server::hub::fanout::Fanout;
use mimid_server::hub::{Clock, Hub, SystemClock};
use mimid_server::peer::PeerClient;
use mimid_server::store::Store;
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tower::ServiceExt;

/// How long any wait in the end-to-end test may take. Fanout retries use
/// the real backoff (1 s, then 2 s), and the test may run under heavy
/// parallel load.
pub const WAIT: Duration = Duration::from_secs(60);

/// A scripted answer to one `/notify` request reaching the front.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Answer `503` without passing the request on.
    Refuse,
    /// Pass the request on, then answer `503` whatever the stack answered:
    /// the stack stored the fanout, but the hub never learns it.
    LoseResponse,
}

#[derive(Default)]
struct FrontState {
    /// The running stack's router; `None` while the provider is stopped.
    router: Option<Router>,
    /// Answers to the next `/notify` requests, in order.
    faults: VecDeque<Fault>,
    /// `/notify` requests received while a fault was scripted or the stack
    /// was stopped: how many got a `503`.
    refused: usize,
}

/// A loopback listener that forwards every request to the provider's
/// current router. While the provider is stopped it answers `503`, as a
/// load balancer in front of a restarting process would.
#[derive(Clone, Default)]
struct Front(Arc<Mutex<FrontState>>);

async fn forward(State(front): State<Front>, request: Request<Body>) -> Response {
    let is_notify = request.uri().path().starts_with("/v1/notify/");
    let (router, fault) = {
        let mut state = front.0.lock().unwrap();
        let fault = if is_notify {
            state.faults.pop_front()
        } else {
            None
        };
        if is_notify && (fault.is_some() || state.router.is_none()) {
            state.refused += 1;
        }
        (state.router.clone(), fault)
    };
    let unavailable = || StatusCode::SERVICE_UNAVAILABLE.into_response();
    match (router, fault) {
        (None, _) | (_, Some(Fault::Refuse)) => unavailable(),
        (Some(router), fault) => {
            let response = router.oneshot(request).await.unwrap();
            if fault == Some(Fault::LoseResponse) {
                assert_eq!(response.status(), StatusCode::CREATED, "forwarded /notify");
                unavailable()
            } else {
                response
            }
        }
    }
}

/// A running provider: what `main.rs` builds.
pub struct Stack {
    pub store: Store,
    pub hub: Arc<Hub>,
    pub follower: Arc<Follower>,
    pub key_packages: Arc<KeyPackages>,
}

/// One provider: its domain, database file, front and, while running, its
/// stack.
pub struct Provider {
    pub domain: Domain,
    pub base: BaseUrl,
    pub path: PathBuf,
    front: Front,
    stack: Option<Stack>,
}

impl Provider {
    /// Binds the provider's front on `127.0.0.1:0`; the stack starts with
    /// [`Provider::boot`].
    pub async fn bind(domain: &str, dir: &Path) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let front = Front::default();
        let app = Router::new().fallback(forward).with_state(front.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            domain: Domain::try_from(domain.to_owned()).unwrap(),
            base: BaseUrl::try_from(base).unwrap(),
            path: dir.join(format!("{domain}.sqlite")),
            front,
            stack: None,
        }
    }

    /// Starts the stack on the provider's database, as `main.rs` does, with
    /// `peers` as the configured peer map, and puts it behind the front.
    /// Before the hub starts, an outbox capture is installed
    /// ([`install_outbox_capture`]).
    pub async fn boot(&mut self, peers: &BTreeMap<Domain, BaseUrl>) {
        assert!(self.stack.is_none(), "{} already running", self.domain);
        let domain = &self.domain;
        let store = Store::open(&self.path, domain).await.unwrap();
        install_outbox_capture(&self.path).await;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let peer_client = || PeerClient::new(domain, peers.clone()).unwrap();
        let key_packages = Arc::new(KeyPackages::new(
            store.clone(),
            domain.clone(),
            Arc::clone(&clock),
        ));
        let follower = Arc::new(
            Follower::new(domain.clone(), store.clone(), Arc::clone(&clock))
                .with_peers(peer_client())
                .with_key_packages(Arc::clone(&key_packages)),
        );
        let fanout = Fanout::new(
            store.clone(),
            domain.clone(),
            peer_client(),
            Arc::clone(&follower),
            Arc::clone(&clock),
        )
        .spawn();
        let hub = Arc::new(
            Hub::open(store.clone(), domain.clone(), Arc::clone(&clock))
                .await
                .unwrap()
                .with_fanout(fanout)
                .with_peers(peer_client())
                .with_local_key_material(Arc::clone(&key_packages) as _),
        );
        follower
            .set_relay(Relay::new(Arc::clone(&hub), peer_client()))
            .unwrap();
        self.front.0.lock().unwrap().router = Some(router(
            Directory::new(&self.base),
            Arc::clone(&hub),
            Arc::clone(&follower),
        ));
        self.stack = Some(Stack {
            store,
            hub,
            follower,
            key_packages,
        });
    }

    /// Stops the stack, as a process exit would: the front answers `503`
    /// from now on and the store is closed. The stopped stack's fanout
    /// worker is abandoned, as `main.rs` abandons it; it holds no rows,
    /// since this provider must host no rooms.
    pub async fn stop(&mut self) {
        self.front.0.lock().unwrap().router = None;
        let stack = self.stack.take().expect("running");
        assert!(
            stack.store.rooms().await.unwrap().is_empty(),
            "hosts no rooms"
        );
        stack.store.close().await;
    }

    pub fn stack(&self) -> &Stack {
        self.stack.as_ref().expect("provider running")
    }

    pub fn follower(&self) -> &Follower {
        &self.stack().follower
    }

    pub fn user(&self, uri: &[u8]) -> LocalUser {
        LocalUser::authenticated(&self.domain, std::str::from_utf8(uri).unwrap()).unwrap()
    }

    /// Scripts the answers to the next `/notify` requests.
    pub fn script(&self, faults: &[Fault]) {
        self.front.0.lock().unwrap().faults.extend(faults);
    }

    /// The scripted faults not used yet, and how many `/notify` requests
    /// got a `503` so far.
    pub fn faults(&self) -> (Vec<Fault>, usize) {
        let state = self.front.0.lock().unwrap();
        (state.faults.iter().copied().collect(), state.refused)
    }

    /// Every FanoutMessage of `room_id` in the follower log, read from the
    /// database, as (seq, bytes), in seq order.
    pub async fn raw_log(&self, room_id: &str) -> Vec<(u64, Vec<u8>)> {
        let db = read_only(&self.path).await;
        let rows: Vec<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT seq, bytes FROM follower_event WHERE room_id = ? ORDER BY seq")
                .bind(room_id)
                .fetch_all(&db)
                .await
                .unwrap();
        db.close().await;
        rows.into_iter()
            .map(|(seq, bytes)| (seq.try_into().unwrap(), bytes))
            .collect()
    }

    /// Every outbox row this provider's hub ever enqueued for `room_id` and
    /// `destination`, as captured, in enqueue order.
    pub async fn captured_outbox(&self, room_id: &str, destination: &str) -> Vec<Vec<u8>> {
        let db = read_only(&self.path).await;
        let bodies = sqlx::query_scalar(
            "SELECT body FROM outbox_capture WHERE room_id = ? AND domain = ? ORDER BY id",
        )
        .bind(room_id)
        .bind(destination)
        .fetch_all(&db)
        .await
        .unwrap();
        db.close().await;
        bodies
    }

    /// Waits until this provider's outbox is empty: every row delivered.
    pub async fn drained(&self) {
        let store = &self.stack().store;
        tokio::time::timeout(WAIT, async {
            while !store.outbox_heads().await.unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("every fanout row delivered");
    }
}

/// Test instrumentation: the outbox deletes rows once delivered, so a
/// trigger copies every new outbox row into `outbox_capture`. It adds a
/// table and a trigger to the database and changes nothing the server
/// reads.
async fn install_outbox_capture(path: &Path) {
    let db = SqlitePool::connect_with(SqliteConnectOptions::new().filename(path))
        .await
        .unwrap();
    for statement in [
        "CREATE TABLE IF NOT EXISTS outbox_capture (id INTEGER PRIMARY KEY, \
         room_id TEXT NOT NULL, domain TEXT NOT NULL, body BLOB NOT NULL)",
        "CREATE TRIGGER IF NOT EXISTS outbox_capture AFTER INSERT ON outbox BEGIN \
         INSERT INTO outbox_capture (id, room_id, domain, body) \
         VALUES (NEW.id, NEW.room_id, NEW.domain, NEW.body); END",
    ] {
        sqlx::query(statement).execute(&db).await.unwrap();
    }
    db.close().await;
}

async fn read_only(path: &Path) -> SqlitePool {
    SqlitePool::connect_with(SqliteConnectOptions::new().filename(path).read_only(true))
        .await
        .unwrap()
}

/// One client's reading position in its user's events at its provider, as
/// the agent would keep it, and the seqs it has read.
pub struct Inbox {
    pub user: LocalUser,
    room_id: &'static str,
    after: u64,
    pub read: Vec<u64>,
}

impl Inbox {
    /// An inbox for `user` in `room_id` that reads events after `after`.
    pub fn new(user: LocalUser, room_id: &'static str, after: u64) -> Self {
        Self {
            user,
            room_id,
            after,
            read: Vec::new(),
        }
    }

    /// The last seq read, or the starting point.
    pub fn position(&self) -> u64 {
        self.after
    }

    /// The next event the user may see, waiting for it to arrive.
    pub async fn next(&mut self, provider: &Provider) -> FanoutMessage {
        let follower = provider.follower();
        let event = tokio::time::timeout(WAIT, async {
            loop {
                // Subscribed before reading, so an event stored in between
                // is announced.
                let mut announced = follower.subscribe();
                let events = follower
                    .events(&self.user, self.room_id, self.after, 1)
                    .await
                    .unwrap();
                if let Some(event) = events.into_iter().next() {
                    return event;
                }
                // Lagged or closed: read again.
                let _ = announced.recv().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("an event reaches {}", self.user.as_str()));
        self.after = event.seq;
        self.read.push(event.seq);
        FanoutMessage::tls_deserialize_exact(&event.bytes).unwrap()
    }

    /// Asserts that no further event is visible to the user now.
    pub async fn assert_empty(&self, provider: &Provider) {
        let events = provider
            .follower()
            .events(&self.user, self.room_id, self.after, 10)
            .await
            .unwrap();
        assert!(
            events.is_empty(),
            "{} has unread events {:?}",
            self.user.as_str(),
            events.iter().map(|event| event.seq).collect::<Vec<_>>()
        );
    }
}
