//! [`IrcFrontEnd`]: the loopback listener, the accept loop, and the front
//! end's part of every save.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use mimid_agent_store::{Change, Frontend, Store};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::conn::{Shared, run, stopped};
use crate::names::Names;
use crate::{IrcError, IrcOptions};
use mimid_agent_store::credentials::Credentials;

/// The IRC front end over one store, bound and not yet serving.
pub struct IrcFrontEnd {
    listener: TcpListener,
    local_addr: SocketAddr,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for IrcFrontEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrcFrontEnd")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

/// The front end's part of each save: names for the people and rooms the
/// save's changes name, kept in their records' `ext["irc"]`, and for the
/// pending invites ([`crate::names`]). It takes the state lock, then the names'.
struct IrcExt {
    names: Arc<Mutex<Names>>,
}

impl Frontend for IrcExt {
    fn before_save<'a>(
        &'a self,
        store: &'a Store,
        changes: &'a [Change],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let mut state = store.state();
            let mut names = self.names.lock().unwrap_or_else(PoisonError::into_inner);
            for change in changes {
                match change {
                    Change::PersonAdded(key) | Change::PersonChanged(key) => {
                        if let Some(person) = state.people.get_mut(key) {
                            names.note_person(person);
                        }
                    }
                    Change::RoomAdded(key) | Change::RoomChanged(key) | Change::RoomLeft(key) => {
                        if let Some(room) = state.rooms.get_mut(key) {
                            names.note_room(room);
                        }
                    }
                    Change::RoomForgotten { key, .. } => names.forget_room(key),
                    Change::InvitePending(number) => {
                        if let Some(invite) = state.invites.iter().find(|i| i.number == *number) {
                            names.invite_channel(invite);
                        }
                    }
                    _ => {}
                }
            }
            // After the rooms: a room joined from an invite in this sync
            // takes the name its invite held before the invite is
            // forgotten (§7.13).
            for change in changes {
                if let Change::InviteGone(number) = change {
                    names.forget_invite(*number);
                }
            }
            Ok(())
        })
    }
}

impl IrcFrontEnd {
    /// Binds `options.listen`, which must be loopback, and registers the
    /// front end on `store`: the names of every person and active room are
    /// read from the records, and those that have none are given one,
    /// written at the next save. A client logs in with one of
    /// `credentials`.
    ///
    /// # Errors
    ///
    /// [`IrcError::NotLoopback`], and [`IrcError::Bind`].
    pub async fn bind(
        store: Arc<Store>,
        options: IrcOptions,
        credentials: Arc<Credentials>,
    ) -> Result<Self, IrcError> {
        if !options.listen.ip().is_loopback() {
            return Err(IrcError::NotLoopback(options.listen));
        }
        let bind = |source| IrcError::Bind {
            addr: options.listen,
            source,
        };
        let listener = TcpListener::bind(options.listen).await.map_err(bind)?;
        let local_addr = listener.local_addr().map_err(bind)?;
        let mut names = Names::new(store.user());
        names.load(&mut store.state());
        let names = Arc::new(Mutex::new(names));
        store.add_frontend(Arc::new(IrcExt {
            names: Arc::clone(&names),
        }));
        let shared = Arc::new(Shared::new(store, names, options, credentials));
        Ok(Self {
            listener,
            local_addr,
            shared,
        })
    }

    /// The address it listens on (the port filled in if it was 0).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accepts connections until `stop` becomes true, then tells every
    /// connection the server is closing and waits for them to end.
    pub async fn serve(self, mut stop: watch::Receiver<bool>) {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                () = stopped(&mut stop) => break,
                accepted = self.listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        if !peer.ip().is_loopback() {
                            // The listener is on loopback; nothing else
                            // can reach it.
                            continue;
                        }
                        tracing::debug!(peer = %peer, "IRC connection");
                        connections.spawn(run(Arc::clone(&self.shared), stream, peer, stop.clone()));
                    }
                    Err(error) => tracing::warn!(
                        name: "agent_irc_accept_failed",
                        error = &error as &dyn std::error::Error,
                        "accepting an IRC connection failed"
                    ),
                },
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
        while connections.join_next().await.is_some() {}
    }
}
