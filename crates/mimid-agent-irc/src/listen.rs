//! [`IrcFrontEnd`]: the plain listener, the accept loop, and the front
//! end's part of every save.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use mimid_agent_store::{Change, Frontend, Store};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

use crate::conn::{Shared, run, stopped};
use crate::names::Names;
use crate::{IrcError, IrcOptions, WebPushError};
use mimid_agent_store::credentials::Credentials;

/// The IRC front end over one store, bound and not yet serving.
pub struct IrcFrontEnd {
    listener: TcpListener,
    local_addr: SocketAddr,
    /// The TLS listener, its address and its acceptor.
    tls: Option<(TcpListener, SocketAddr, TlsAcceptor)>,
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

/// Accepts on the TLS listener, or never without one.
async fn accept_tls(
    tls: Option<&(TcpListener, SocketAddr, TlsAcceptor)>,
) -> std::io::Result<(tokio::net::TcpStream, SocketAddr)> {
    match tls {
        Some((listener, _, _)) => listener.accept().await,
        None => std::future::pending().await,
    }
}

impl IrcFrontEnd {
    /// Binds `options.listen`, an address of any kind, and registers the
    /// front end on `store`: the names of every person and active room are
    /// read from the records, and those that have none are given one,
    /// written at the next save. A client logs in with one of
    /// `credentials`, on this listener as on the TLS one. With
    /// `options.listen_tls`, also binds that address, of any kind, for
    /// TLS with `tls`.
    ///
    /// Off loopback this listener's traffic is cleartext and the operator
    /// protects it (decision mimid-1wgh.92); nothing here refuses such an
    /// address.
    ///
    /// # Errors
    ///
    /// [`IrcError::Bind`], and [`IrcError::NoTls`] for `listen_tls`
    /// without `tls`.
    pub async fn bind(
        store: Arc<Store>,
        options: IrcOptions,
        credentials: Arc<Credentials>,
        tls: Option<Arc<ServerConfig>>,
    ) -> Result<Self, IrcError> {
        let bind = |source| IrcError::Bind {
            addr: options.listen,
            source,
        };
        let listener = TcpListener::bind(options.listen).await.map_err(bind)?;
        let local_addr = listener.local_addr().map_err(bind)?;
        let tls = match (options.listen_tls, tls) {
            (Some(addr), Some(config)) => {
                let bind = |source| IrcError::Bind { addr, source };
                let listener = TcpListener::bind(addr).await.map_err(bind)?;
                let local = listener.local_addr().map_err(bind)?;
                Some((listener, local, TlsAcceptor::from(config)))
            }
            (Some(addr), None) => return Err(IrcError::NoTls(addr)),
            (None, _) => None,
        };
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
            tls,
            shared,
        })
    }

    /// The address it listens on (the port filled in if it was 0).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The TLS listener's address, if any.
    #[must_use]
    pub fn tls_addr(&self) -> Option<SocketAddr> {
        self.tls.as_ref().map(|(_, addr, _)| *addr)
    }

    /// Switches on soju.im/webpush (docs/design/client-survey.md §10 S4;
    /// docs/design/agent-frontends.md §7.35) over `subscriptions`, the
    /// push tables of the agent's database: the capability and ISUPPORT
    /// `VAPID` are offered, the VAPID key is made if there is none, and
    /// [`IrcFrontEnd::serve`] pushes to the subscriptions. Call before
    /// serving; a second call changes nothing.
    ///
    /// # Errors
    ///
    /// [`WebPushError`] if the key cannot be read or made, or the HTTP
    /// client cannot be built.
    pub fn enable_web_push(
        &self,
        subscriptions: Arc<mimid_agent_store::push::PushSubscriptions>,
    ) -> Result<(), WebPushError> {
        let push = crate::webpush::WebPush::new(subscriptions)?;
        let _ = self.shared.web_push.set(Arc::new(push));
        Ok(())
    }

    /// Switches on tailnet identity (docs/design/frontend-auth.md §4.6):
    /// `identity` says who a peer is before any credential, and the
    /// rules behind it are the daemon's. Called once, before
    /// [`IrcFrontEnd::serve`]; a second call changes nothing.
    pub fn enable_peer_identity(&self, identity: Arc<dyn crate::PeerIdentity>) {
        let _ = self.shared.peer_identity.set(identity);
    }

    /// Accepts connections until `stop` becomes true, then tells every
    /// connection the server is closing and waits for them to end.
    pub async fn serve(self, mut stop: watch::Receiver<bool>) {
        let mut connections = JoinSet::new();
        if let Some(push) = self.shared.web_push() {
            connections.spawn(crate::webpush::run(
                Arc::clone(&self.shared),
                push,
                stop.clone(),
            ));
        }
        loop {
            tokio::select! {
                accepted = accept_tls(self.tls.as_ref()) => match accepted {
                    Ok((stream, peer)) => {
                        let Some((_, _, acceptor)) = &self.tls else { continue };
                        let acceptor = acceptor.clone();
                        let shared = Arc::clone(&self.shared);
                        let stop = stop.clone();
                        connections.spawn(async move {
                            match tokio::time::timeout(crate::HANDSHAKE_WITHIN, acceptor.accept(stream)).await {
                                Ok(Ok(stream)) => {
                                    tracing::debug!(peer = %peer, "IRC connection over TLS");
                                    run(shared, stream, peer, stop).await;
                                }
                                Ok(Err(error)) => tracing::debug!(
                                    peer = %peer,
                                    error = &error as &dyn std::error::Error,
                                    "IRC TLS handshake failed"
                                ),
                                Err(_) => tracing::debug!(peer = %peer, "IRC TLS handshake timed out"),
                            }
                        });
                    }
                    Err(error) => tracing::warn!(
                        name: "agent_irc_accept_failed",
                        error = &error as &dyn std::error::Error,
                        "accepting an IRC TLS connection failed"
                    ),
                },
                () = stopped(&mut stop) => break,
                accepted = self.listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        // Any peer that can reach the address is served;
                        // the credential check before registration ends
                        // is what guards the account (decision
                        // mimid-1wgh.92).
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
