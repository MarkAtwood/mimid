//! [`TlsListener`]: the HTTPS listener of `[jmap] listen_tls`
//! (docs/design/frontend-auth.md §4.2, §5.3; bead mimid-e13m.6).
//!
//! `axum::serve` takes any [`axum::serve::Listener`], so TLS is a listener
//! that hands it streams whose handshake is already done. The handshakes
//! run in their own tasks, at most [`MAX_HANDSHAKES`] at once and each
//! within [`HANDSHAKE_WITHIN`], and the finished streams arrive over a
//! channel of [`BACKLOG`]: a peer that opens a connection and then says
//! nothing therefore costs one task and one slot, and never blocks the
//! accept loop, which is what a single-threaded accept-then-handshake
//! would do to a listener facing the network.
//!
//! The certificate itself comes from [`crate::tls::Tls`], which every TLS
//! listener shares, so a renewal reaches this listener with no restart.
//!
//! # Limitations
//!
//! - No ALPN and no SNI routing: one certificate, one port per front end
//!   (docs/design/frontend-auth.md §5.3). HTTP/2 is not offered, so a
//!   client speaks HTTP/1.1 over TLS.
//! - A handshake that fails is logged at DEBUG and counted nowhere: the
//!   per-source slowdown of §7.1 counts failed *logins*, which is after
//!   TLS. A flood of unfinished handshakes is bounded by
//!   [`MAX_HANDSHAKES`] and nothing else.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;

use crate::http::stopped;

/// How long a TLS handshake may take, as mimid-agent-irc allows its own.
pub const HANDSHAKE_WITHIN: Duration = Duration::from_secs(10);

/// The most handshakes running at once. Past it the accept loop waits,
/// which is back pressure on the listener rather than unbounded tasks.
pub const MAX_HANDSHAKES: usize = 32;

/// How many finished streams wait to be served before the accept loop
/// waits for one to be taken.
pub const BACKLOG: usize = 16;

/// A listener that gives [`axum::serve`] streams whose TLS handshake is
/// done. See the module documentation.
pub(crate) struct TlsListener {
    local_addr: SocketAddr,
    accepted: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
}

impl TlsListener {
    /// Starts accepting on `listener` with `config`, until `stop` is true.
    pub(crate) fn spawn(
        listener: TcpListener,
        local_addr: SocketAddr,
        config: Arc<ServerConfig>,
        stop: watch::Receiver<bool>,
    ) -> Self {
        let (sender, accepted) = mpsc::channel(BACKLOG);
        tokio::spawn(accept_loop(listener, config, sender, stop));
        Self {
            local_addr,
            accepted,
        }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.accepted.recv().await {
            Some(accepted) => accepted,
            // The accept loop has ended, which happens only at shutdown:
            // the server is already stopping, so there is nothing to
            // hand it and no error to report.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

/// Accepts connections and sends the ones whose handshake finishes.
async fn accept_loop(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    sender: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)>,
    mut stop: watch::Receiver<bool>,
) {
    let acceptor = TlsAcceptor::from(config);
    let handshakes = Arc::new(tokio::sync::Semaphore::new(MAX_HANDSHAKES));
    loop {
        // A place for a handshake first, so a flood waits here rather
        // than in a task of its own.
        let permit = tokio::select! {
            () = stopped(&mut stop) => return,
            permit = Arc::clone(&handshakes).acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => return,
            },
        };
        let accepted = tokio::select! {
            () = stopped(&mut stop) => return,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(
                    name: "agent_https_accept_failed",
                    error = &error as &dyn std::error::Error,
                    "accepting an HTTPS connection failed"
                );
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let sender = sender.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(HANDSHAKE_WITHIN, acceptor.accept(stream)).await {
                Ok(Ok(stream)) => {
                    // The receiver is gone only once the server has
                    // stopped; dropping the stream closes it.
                    let _ = sender.send((stream, peer)).await;
                }
                Ok(Err(error)) => tracing::debug!(
                    peer = %peer,
                    error = &error as &dyn std::error::Error,
                    "an HTTPS TLS handshake failed"
                ),
                Err(_) => tracing::debug!(peer = %peer, "an HTTPS TLS handshake timed out"),
            }
        });
    }
}
