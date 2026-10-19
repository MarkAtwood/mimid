//! The change bus: one stream of the provider changes that move JMAP state
//! (plan of mimid-1wgh.12 §3).
//!
//! It carries the follower's stored events, forwarded from
//! [`Follower::subscribe`](crate::follower::Follower::subscribe), and its
//! relayed joins and leavings, forwarded from
//! [`Follower::subscribe_membership`](crate::follower::Follower::subscribe_membership)
//! (decision mimid-1wgh.12.34). KeyPackage writes join it in a later bead.
//!
//! # Limitations
//!
//! - Delivery is best effort: a subscriber more than [`CHANGE_BUS_CAPACITY`]
//!   changes behind loses changes and must recompute every state string.
//!   A follower announcement lost before it reached the bus is published
//!   as [`Change::Lagged`].

use tokio::sync::broadcast::{self, error::RecvError};
use tokio::task::JoinHandle;

/// How many changes the bus buffers for a slow subscriber. INVENTED, NOT
/// FROM SPEC; it matches the follower's
/// [`SUBSCRIBE_CAPACITY`](crate::follower::SUBSCRIBE_CAPACITY).
pub const CHANGE_BUS_CAPACITY: usize = 1_024;

/// A change that may move some account's JMAP state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    /// The follower stored event `seq` of room `room_id`.
    RoomEvent {
        /// The room's ID.
        room_id: String,
        /// The event's sequence number in the follower log.
        seq: u64,
    },
    /// A local user joined the room `room_id` by a relayed update, or left
    /// it.
    Membership {
        /// The room's ID.
        room_id: String,
        /// The user's URI.
        user_uri: String,
    },
    /// Changes were lost before reaching the bus; every state may have
    /// moved.
    Lagged,
}

/// The sending side of the change bus. Clones publish to the same bus.
#[derive(Debug, Clone)]
pub struct ChangeBus {
    sender: broadcast::Sender<Change>,
}

impl Default for ChangeBus {
    fn default() -> Self {
        Self::new()
    }
}

impl ChangeBus {
    /// An empty bus.
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(CHANGE_BUS_CAPACITY);
        Self { sender }
    }

    /// Publishes `change` to every current subscriber.
    pub fn publish(&self, change: Change) {
        // An error only means nobody is subscribed.
        let _ = self.sender.send(change);
    }

    /// Receives every change published from now on. A receiver more than
    /// [`CHANGE_BUS_CAPACITY`] changes behind gets
    /// [`RecvError::Lagged`] and should recompute every state.
    pub fn subscribe(&self) -> broadcast::Receiver<Change> {
        self.sender.subscribe()
    }

    /// Spawns a task publishing each follower announcement (as given by
    /// [`Follower::subscribe`](crate::follower::Follower::subscribe)) as a
    /// [`Change::RoomEvent`], and a lag as [`Change::Lagged`]. The task
    /// ends when the follower is dropped.
    pub fn forward(&self, mut announcements: broadcast::Receiver<(String, u64)>) -> JoinHandle<()> {
        let bus = self.clone();
        tokio::spawn(async move {
            loop {
                match announcements.recv().await {
                    Ok((room_id, seq)) => bus.publish(Change::RoomEvent { room_id, seq }),
                    Err(RecvError::Lagged(missed)) => {
                        tracing::warn!(missed, "change bus lagged behind the follower");
                        bus.publish(Change::Lagged);
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        })
    }

    /// Spawns a task publishing each membership announcement (as given by
    /// [`Follower::subscribe_membership`](crate::follower::Follower::subscribe_membership))
    /// as a [`Change::Membership`], and a lag as [`Change::Lagged`]. The
    /// task ends when the follower is dropped.
    pub fn forward_membership(
        &self,
        mut announcements: broadcast::Receiver<(String, String)>,
    ) -> JoinHandle<()> {
        let bus = self.clone();
        tokio::spawn(async move {
            loop {
                match announcements.recv().await {
                    Ok((room_id, user_uri)) => {
                        bus.publish(Change::Membership { room_id, user_uri })
                    }
                    Err(RecvError::Lagged(missed)) => {
                        tracing::warn!(missed, "change bus lagged behind follower memberships");
                        bus.publish(Change::Lagged);
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn forwards_announcements_in_order_and_ends_with_the_sender() {
        let (follower, announcements) = broadcast::channel(4);
        let bus = ChangeBus::new();
        let mut changes = bus.subscribe();
        let task = bus.forward(announcements);
        follower
            .send(("mimi://a.example/r/one".to_owned(), 1))
            .unwrap();
        follower
            .send(("mimi://a.example/r/two".to_owned(), 2))
            .unwrap();
        drop(follower);
        task.await.unwrap();
        assert_eq!(
            changes.recv().await.unwrap(),
            Change::RoomEvent {
                room_id: "mimi://a.example/r/one".to_owned(),
                seq: 1
            }
        );
        assert_eq!(
            changes.recv().await.unwrap(),
            Change::RoomEvent {
                room_id: "mimi://a.example/r/two".to_owned(),
                seq: 2
            }
        );
    }

    /// Three announcements into a channel of capacity one: the receiver
    /// misses the first two, so the bus publishes `Lagged` before the
    /// third.
    #[tokio::test]
    async fn a_lagging_forwarder_publishes_lagged() {
        let (follower, announcements) = broadcast::channel(1);
        for seq in 1..=3 {
            follower
                .send(("mimi://a.example/r/one".to_owned(), seq))
                .unwrap();
        }
        let bus = ChangeBus::new();
        let mut changes = bus.subscribe();
        let task = bus.forward(announcements);
        drop(follower);
        task.await.unwrap();
        assert_eq!(changes.recv().await.unwrap(), Change::Lagged);
        assert_eq!(
            changes.recv().await.unwrap(),
            Change::RoomEvent {
                room_id: "mimi://a.example/r/one".to_owned(),
                seq: 3
            }
        );
    }
}
