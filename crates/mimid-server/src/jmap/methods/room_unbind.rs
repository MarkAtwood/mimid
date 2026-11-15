//! `Room/unbind` (draft-atwood-jmap-chat-mimi-00 §Room/unbind; decision
//! mimid-1wgh.41, client-driven unbind).
//!
//! Arguments: `accountId` and `roomId`. It is `invalidArguments` if no Chat
//! of the account has that `roomId`; otherwise the account leaves the
//! followed room ([`Follower::leave`]), which unbinds its Chat if bound.
//! The Chat keeps its `roomId` and Messages.

use std::sync::Arc;

use jmap_server::{CallContext, HandlerFuture, HandlerOutput, JmapError, JmapHandler};
use serde_json::{Value, json};

use super::Services;
use super::room_common::{room_call, server_fail};
use crate::follower::Follower;
use crate::jmap::api::Methods;
use crate::jmap::auth::Account;
use crate::store::Store;

const METHOD: &str = "Room/unbind";

/// Registers `Room/unbind`.
pub(super) fn register(methods: &mut Methods, services: &Services) {
    methods.add(
        METHOD,
        Arc::new(Handler {
            follower: Arc::clone(&services.follower),
            store: services.store.clone(),
        }),
    );
}

struct Handler {
    follower: Arc<Follower>,
    store: Store,
}

impl JmapHandler<Account> for Handler {
    fn call(&self, cx: CallContext<Account>) -> HandlerFuture {
        let CallContext { args, caller, .. } = cx;
        let (follower, store) = (Arc::clone(&self.follower), self.store.clone());
        Box::pin(async move {
            unbind(&follower, &store, &caller, args)
                .await
                .map(HandlerOutput::new)
        })
    }
}

async fn unbind(
    follower: &Follower,
    store: &Store,
    caller: &Account,
    args: Value,
) -> Result<Value, JmapError> {
    let call = room_call(METHOD, store, caller, args, false).await?;
    follower
        .leave(caller.user(), &call.room_id)
        .await
        .map_err(|e| server_fail(METHOD, &e))?;
    Ok(json!({ "accountId": call.account_id }))
}
