//! A call as a room of its own: a room-policy-04 §5 parent-dependent room
//! under a chat, whose media key both sides derive from its own MLS group
//! with nothing sent (draft-atwood-mimi-calls §4; bead mimid-1wgh.108,
//! decisions mimid-1wgh.110 to mimid-1wgh.113), through a real mimid
//! server whose hub enforces §5.
//!
//! Oracles:
//!
//! - mls-extensions-11 §4.4: `SafeExportSecret(component_id)` is a
//!   function of the group, the epoch and the component, so the two
//!   members of the call room must derive the same bytes, and a new epoch
//!   must give others.
//! - room-policy-04 §5: a parent-dependent room names its parent, and its
//!   participants stay inside the parent's. The hub refuses a room that
//!   breaks either, and refuses it at creation (`hub/room.rs`), so a room
//!   this test gets back is one the hub agreed to host.

#![forbid(unsafe_code)]

mod common;

use common::{ALICE, BOB, device, poll_until, server};
use mimid_agent_core::{AgentError, Event, HostOptions};

/// alice hosts a chat and a call room under it, bob joins both, and both
/// derive the same media secret from the call room's group.
#[tokio::test]
async fn a_call_room_keys_itself_from_its_own_group() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = device(&server, ALICE, dir.path(), "alice").await;
    let mut bob = device(&server, BOB, dir.path(), "bob").await;
    bob.publish_key_packages(4).await.unwrap();

    // The chat, and bob in it.
    let chat = alice
        .host_room(&HostOptions::named("planning"))
        .await
        .unwrap();
    alice.invite(&chat, BOB).await.unwrap();
    let invite = poll_until(&mut bob, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    assert_eq!(bob.join(invite).unwrap(), chat);

    // The call, a parent-dependent room of the chat with the same people.
    let call = alice
        .host_room(&HostOptions::child_of(&chat, ""))
        .await
        .unwrap();
    assert_ne!(call, chat, "a call is its own room");
    assert_eq!(
        alice.parent_room(&call).unwrap().as_deref(),
        Some(chat.as_str()),
        "the call room names the chat as its parent"
    );
    assert_eq!(alice.parent_room(&chat).unwrap(), None);
    alice.invite(&call, BOB).await.unwrap();
    let invite = poll_until(&mut bob, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    assert_eq!(bob.join(invite).unwrap(), call);
    assert_eq!(
        bob.parent_room(&call).unwrap().as_deref(),
        Some(chat.as_str())
    );

    // The keying: both sides, nothing sent.
    let hers = alice.media_secret(&call).unwrap();
    let his = bob.media_secret(&call).unwrap();
    assert_eq!(
        hers.expose_secret(),
        his.expose_secret(),
        "both members of the call room derive the same media secret"
    );
    assert_eq!(hers.epoch(), his.epoch());
    assert!(!hers.expose_secret().is_empty());
    // Debug never shows it (AGENTS.md: secrets never reach logs).
    assert!(
        !format!("{hers:?}").contains("secret: ["),
        "{hers:?} shows the bytes"
    );

    // §4.4's exporter is read once per epoch; the agent keeps what it
    // read, so asking again in the same epoch is the same answer.
    let again = alice.media_secret(&call).unwrap();
    assert_eq!(again.expose_secret(), hers.expose_secret());

    // The chat's secret is another group's, and so is not the call's.
    let chat_secret = alice.media_secret(&chat).unwrap();
    assert_ne!(chat_secret.expose_secret(), hers.expose_secret());
}

/// An agent that restarts inside an epoch cannot get that epoch's media
/// secret back: §4.4's leaf was punctured and the puncture is in the
/// store, while the secret itself was only ever in memory.
///
/// Oracle: mls-extensions-11 §4.4's deletion MUST, which is the whole
/// point of the forward-secure exporter -- a restart that could re-derive
/// the secret would mean the source key material had not been deleted.
/// So this failure is correct and stays: what bead mimid-1wgh.129 adds
/// is a way OUT of it, which is the next test. The error is its own
/// variant, because it is the one export failure a caller can act on.
#[tokio::test]
async fn an_agent_that_restarts_inside_an_epoch_loses_the_media_secret() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let mut alice = device(&server, ALICE, dir.path(), "alice").await;

    let chat = alice
        .host_room(&HostOptions::named("planning"))
        .await
        .unwrap();
    let call = alice
        .host_room(&HostOptions::child_of(&chat, ""))
        .await
        .unwrap();
    let before = alice.media_secret(&call).unwrap();
    let epoch = before.epoch();
    drop(before);
    drop(alice);

    // The same state directory, as after a crash or an upgrade.
    let mut restarted = device(&server, ALICE, dir.path(), "alice").await;
    let error = restarted.media_secret(&call).unwrap_err();
    assert!(
        matches!(&error, AgentError::SecretConsumed { room, epoch: lost }
            if room == &call && *lost == epoch),
        "the exporter is consumed for this epoch, so this must fail, and \
         say which room and epoch: {error:?}"
    );

    // The epoch has not moved, so there is nothing else to read; another
    // room's group is untouched, which shows the failure is this
    // component's leaf in this group and not a broken reload.
    assert_eq!(restarted.media_secret(&chat).unwrap().epoch(), epoch);
}

/// `Agent::rekey` is the way out: it moves the call to a new epoch, whose
/// Exporter Tree leaf is unread, so the media secret can be derived again
/// (bead mimid-1wgh.129).
///
/// Oracle: §4.4 again. The new secret must be DIFFERENT, because it
/// descends from a different epoch secret -- a rekey that gave the old
/// bytes back would mean the epoch had not really moved. And the epoch
/// number must have advanced, which is what the JMAP surface reports to
/// the client as `EpochMoved`.
#[tokio::test]
async fn a_rekey_gives_the_call_a_media_secret_again() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let mut alice = device(&server, ALICE, dir.path(), "alice").await;

    let chat = alice
        .host_room(&HostOptions::named("planning"))
        .await
        .unwrap();
    let call = alice
        .host_room(&HostOptions::child_of(&chat, ""))
        .await
        .unwrap();
    let before = alice.media_secret(&call).unwrap();
    let (was, bytes) = (before.epoch(), before.expose_secret().to_vec());
    drop(before);
    drop(alice);

    let mut restarted = device(&server, ALICE, dir.path(), "alice").await;
    assert!(
        restarted.media_secret(&call).is_err(),
        "the precondition: the epoch's secret is gone"
    );

    restarted.rekey(&call).await.unwrap();
    let after = restarted
        .media_secret(&call)
        .expect("a new epoch has an unread leaf");
    assert!(
        after.epoch() > was,
        "the epoch moved: {was} -> {}",
        after.epoch()
    );
    assert_ne!(
        after.expose_secret(),
        bytes.as_slice(),
        "a new epoch's secret is a new secret"
    );

    // And the new epoch's secret is itself read once, so the recovery
    // does not quietly make the exporter re-readable.
    let again = restarted.media_secret(&call).unwrap();
    assert_eq!(
        again.expose_secret(),
        after.expose_secret(),
        "the same epoch gives the held secret, not a second export"
    );

    // A rekey of a room the agent does not hold is not a Commit attempt.
    assert!(matches!(
        restarted.rekey("mimi://a.example/r/nothing").await,
        Err(AgentError::NoSuchRoom(_))
    ));
}

/// The hub refuses a parent-dependent room whose parent it does not host,
/// which §5 forbids: "A parent-dependent room is always hosted on the
/// same Hub as the parent room."
#[tokio::test]
async fn a_call_room_needs_a_parent_the_hub_hosts() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let mut alice = device(&server, ALICE, dir.path(), "alice").await;
    let chat = alice
        .host_room(&HostOptions::named("planning"))
        .await
        .unwrap();

    // A parent this agent is not in is refused before anything is sent.
    let refused = alice
        .host_room(&HostOptions::child_of("mimi://a.example/r/nowhere", ""))
        .await;
    assert!(
        matches!(&refused, Err(AgentError::Invalid(why)) if why.contains("not a room of this agent")),
        "{refused:?}"
    );

    // Nothing was hosted for it: the chat is still the only room.
    assert_eq!(alice.rooms().len(), 1);
    assert_eq!(alice.rooms()[0].uri, chat);
}

/// A call room cannot be an open room: an open room has no
/// `base_room_policy` (decision mimid-1wgh.52) and so nowhere to say what
/// its parent is.
#[tokio::test]
async fn a_call_room_cannot_be_open() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let mut alice = device(&server, ALICE, dir.path(), "alice").await;
    let chat = alice
        .host_room(&HostOptions::named("planning"))
        .await
        .unwrap();
    let mut options = HostOptions::child_of(&chat, "");
    options.open = true;
    let refused = alice.host_room(&options).await;
    assert!(
        matches!(&refused, Err(AgentError::Invalid(why)) if why.contains("cannot be open")),
        "{refused:?}"
    );
}

/// §5's own example: a room that is both `fixed_membership` and
/// `parent_dependent`, "for room used for a multi-media call of clients
/// in a Group DM", among the same people as the DM it is under. §5's
/// "only a single fixed-membership room can exist for any unique set of
/// participants" would forbid it, and would let a chat have one call
/// ever; mimid does not count parent-dependent rooms in that rule
/// (decision mimid-1wgh.110, proposed as
/// ietf-wg-mimi/mimi-room-policy#43).
#[tokio::test]
async fn a_fixed_call_room_may_hold_the_same_pair_as_its_direct_room() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = device(&server, ALICE, dir.path(), "alice").await;
    let mut bob = device(&server, BOB, dir.path(), "bob").await;
    bob.publish_key_packages(8).await.unwrap();

    // The DM: fixed_membership with max_users 2, alice and bob.
    let dm = alice.host_room(&HostOptions::direct()).await.unwrap();
    alice.invite(&dm, BOB).await.unwrap();
    let invite = poll_until(&mut bob, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    assert_eq!(bob.join(invite).unwrap(), dm);

    // Two calls in it, each a fixed-membership parent-dependent room with
    // the DM's own participant set.
    let mut options = HostOptions::child_of(&dm, "");
    options.direct = true;
    for _ in 0..2 {
        let call = alice.host_room(&options).await.unwrap();
        alice
            .invite(&call, BOB)
            .await
            .expect("the call room may hold the pair the DM holds");
        assert_eq!(alice.participants(&call).unwrap(), [ALICE, BOB]);
        assert!(alice.is_fixed_membership(&call).unwrap());
        assert_eq!(
            alice.parent_room(&call).unwrap().as_deref(),
            Some(dm.as_str())
        );
    }

    // And a second DM with the same pair is still refused, which is the
    // rule the exception is carved out of.
    let second = alice.host_room(&HostOptions::direct()).await.unwrap();
    let refused = alice.invite(&second, BOB).await;
    assert!(
        refused.is_err(),
        "a second DM with the same pair: {refused:?}"
    );
}
