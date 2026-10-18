//! Inbound protocol-06 §5.5 `/notify`: FanoutMessages from a room's hub,
//! deduplicated per FanoutMessage (decision mimid-1wgh.7.3) and appended to
//! the follower log in arrival order (decision mimid-1wgh.7.17). Arrives
//! with mimid-1wgh.7.21.
