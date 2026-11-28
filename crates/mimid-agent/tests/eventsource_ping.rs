//! The agent's EventSource `ping` events (RFC 8620 §7.3), which a JMAP
//! Chat client asks for with the `ping` member of `eventSourceUrl` and
//! reads as "the agent is working".
//!
//! A ping is written only while the agent is free (decision
//! mimid-1wgh.132), so what this pins is that the evidence it now waits
//! for does not stop the ping arriving: an agent that syncs, tops up its
//! KeyPackages and idles still pings its client at the interval it
//! reported.
//!
//! The interval asked for here is 1 second, which the agent clamps up to
//! its shortest honoured interval, so the first ping is ten seconds in.
//! There is no deadline: the ping is the event waited for, and an agent
//! that stops pinging hangs the test rather than failing it on a loaded
//! machine.
//!
//! Oracle: RFC 8620 §7.3 -- the event is named `ping` and its data
//! states the interval in use, which is the clamped one and not the one
//! asked for.

#![forbid(unsafe_code)]

mod common;

use common::{ALICE, Running, config, server};

/// The shortest ping interval the agent honours, as its `http` module
/// states it; a shorter one asked for is clamped up to this.
const MIN_PING_SECS: u64 = 10;

/// An idle stream is pinged at the clamped interval, and the ping says
/// which interval that is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_stream_is_pinged_at_the_clamped_interval() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let alice = Running::start(&config(&server, ALICE, dir.path(), "any")).await;
    let client = alice.client().await;
    let mut events = client.events_pinged(1).await;

    assert_eq!(events.until_ping().await, MIN_PING_SECS);

    drop(events);
    alice.stop().await;
}
