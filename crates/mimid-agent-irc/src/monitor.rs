//! `MONITOR`: which of the nicks a client names it can reach
//! (~/PROJECT/IETF/specs/ircv3-monitor.md; docs/design/agent-frontends.md
//! §7.39).
//!
//! What a 730 means here is reachability and not availability: the user
//! has at least one client that is a leaf of the MLS group of a room this
//! user shares with them, which is
//! [`mimid_agent_store::record::Person::clients`] as the last sync
//! counted it. MIMI defines no presence, and a participant with no
//! clients receives nothing, which is the state room-policy-04 §5 leaves
//! a user in who removed their devices and the state `KICK` leaves a
//! participant in. A client will label a 730 "online" and a user will
//! read it as "here"; nothing in the protocol can stop that, so the crate
//! docs, the design note and the numeric's own documentation say what it
//! is (decision mimid-1wgh.146).
//!
//! The list is this connection's, never persisted, and bounded by
//! [`MAX_MONITOR`], which `crate::register::isupport` advertises as the
//! spec's `MONITOR` token.

use std::collections::BTreeMap;

use crate::conn::Session;
use crate::line::{Line, MAX_LINE, Out, pack};
use crate::names::{SERVICE_NICK, fold, is_nick};

/// The most targets one connection's monitor list holds, which 005's
/// `MONITOR` token advertises and 734 `ERR_MONLISTFULL` names.
///
/// INVENTED, NOT FROM SPEC: ircv3-monitor.md:60-65 fixes no number and
/// says a token with no parameter means no limit. 100 is the independent
/// implementation's (~/PROJECT/meshIRCd main.go:2442, `const
/// monitorLimit = 100`), which is also the spec's own example token
/// (:65). It becomes public in 005 and is hard to lower afterwards
/// (decision mimid-1wgh.146).
pub const MAX_MONITOR: usize = 100;

/// One entry of a connection's monitor list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Monitored {
    /// The nick as the client sent it, which is what 732 and 731 echo: a
    /// client that re-reads its list must get back what it asked for, and
    /// not the folded key (meshIRCd main.go:2509-2520 lists the folded
    /// keys).
    pub(crate) nick: String,
    /// Whether the last verdict reported for it was online, so that
    /// [`Session::monitor_refresh`] reports a flip and nothing else.
    pub(crate) online: bool,
}

/// What one command's target parameter holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Targets {
    /// The targets, in the order sent, each a nick this daemon could have
    /// given, with no repeat under [`fold`].
    Nicks(Vec<String>),
    /// Nothing was left after the empty entries were dropped.
    Empty,
    /// This target is not a nick this daemon could have given, so no
    /// target of the command is read.
    NotANick(String),
}

/// The targets `param` names, for a `MONITOR +`.
///
/// Split on `,` (ircv3-monitor.md:70, `target[,target2]*`); an empty
/// entry is dropped, and a parameter left with none is [`Targets::Empty`]
/// for the caller to answer 461. Every entry must satisfy
/// [`is_nick`], the daemon's determination the spec asks for
/// (:67-68): a target that is not a nick refuses the whole command
/// ([`Targets::NotANick`]), which is also what disallows the `nick!user@host`
/// subscription the spec rules out to keep a user from being followed
/// across nick changes (:38-42). The first repeat under [`fold`] is
/// dropped, since `CASEMAPPING=ascii` makes two spellings one nick and
/// the list holds a nick once (:72-73).
pub(crate) fn targets(param: &str) -> Targets {
    let mut nicks: Vec<String> = Vec::new();
    for target in param.split(',') {
        if target.is_empty() {
            continue;
        }
        if !is_nick(target) {
            return Targets::NotANick(target.to_owned());
        }
        if !nicks.iter().any(|n| fold(n) == fold(target)) {
            nicks.push(target.to_owned());
        }
    }
    if nicks.is_empty() {
        return Targets::Empty;
    }
    Targets::Nicks(nicks)
}

/// What a `MONITOR +` does to a list that may be too small for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Added {
    /// The targets to add, in the order sent: those not already in the
    /// list. Empty when every target was already there, which is the one
    /// `MONITOR +` that answers nothing at all.
    Added(Vec<String>),
    /// The list has no room for them, so none is added: the targets to
    /// name in 734, as the client sent them.
    Full(Vec<String>),
}

/// Which of `nicks` a list already holding `held` entries takes.
///
/// A target already in the list is not added again and is not reported
/// again (ircv3-monitor.md:72-73, "Targets already in the list MUST NOT
/// be added again"); `MONITOR S` is how a client re-reads their state.
/// Those left are added only if all of them fit: 734 is for a list that
/// is "full, so the command failed" (:148-149), so the command is
/// all-or-nothing and the list can never pass what 005 advertises
/// (decision mimid-1wgh.146 carries the readings). The bound is checked
/// before anything is inserted.
pub(crate) fn to_add(list: &BTreeMap<String, Monitored>, nicks: &[String]) -> Added {
    let new: Vec<String> = nicks
        .iter()
        .filter(|nick| !list.contains_key(&fold(nick)))
        .cloned()
        .collect();
    if list.len() + new.len() > MAX_MONITOR {
        return Added::Full(new);
    }
    Added::Added(new)
}

impl Session {
    /// `MONITOR`: one modifier, and for `+` and `-` a target list
    /// (ircv3-monitor.md:44-101).
    ///
    /// No credential is read and none could be: this runs from
    /// [`Session::command`], which the connection reaches only once
    /// registration ended, and what ended it was IRC's one authorization
    /// check (`crate::register`; docs/design/frontend-auth.md §4.1). A
    /// `MONITOR` before that is answered 451 there.
    pub(crate) fn monitor(&mut self, line: &Line) {
        let Some(modifier) = line.param(0) else {
            // Modern §"Client Messages": a command sent "with less
            // parameters than the command requires to be processed" is
            // answered ERR_NEEDMOREPARAMS (461) and fails.
            self.numeric("461", &["MONITOR", "Not enough parameters"]);
            return;
        };
        let modifier = modifier.to_ascii_uppercase();
        // Only one modifier per command, and the forms that take a target
        // list take exactly one parameter after it (ircv3-monitor.md:48-54,
        // :70-101). Anything further is a parameter mimid cannot read, so
        // it is refused rather than dropped, as `CHATHISTORY` refuses one
        // (crate::history; ircv3-chathistory.md:141-146).
        let wanted = if modifier == "+" || modifier == "-" {
            2
        } else {
            1
        };
        if line.params.len() > wanted {
            let given = line.params[wanted].clone();
            self.monitor_fail("INVALID_PARAMS", &given, "Too many parameters");
            return;
        }
        match modifier.as_str() {
            "+" => self.monitor_add(line),
            "-" => self.monitor_remove(line),
            "C" => self.monitor.clear(),
            "L" => self.monitor_list(),
            "S" => self.monitor_status(),
            // ircv3-monitor.md names no reply for a modifier it does not
            // define. Standard replies says an implementer "MUST use an
            // existing code if one is already defined"
            // (ircv3-standard-replies.md:46-48), and INVALID_PARAMS is
            // the code this front end already sends for an unknown
            // subcommand (crate::history; ircv3-chathistory.md:141-146).
            // meshIRCd answers nothing at all (main.go:2444-2541), which
            // a client cannot tell from a dropped line; decision
            // mimid-1wgh.146 carries both readings.
            other => self.monitor_fail("INVALID_PARAMS", other, "Unknown modifier"),
        }
    }

    /// `MONITOR + target[,target2]*`.
    fn monitor_add(&mut self, line: &Line) {
        let Some(param) = line.param(1) else {
            self.numeric("461", &["MONITOR", "Not enough parameters"]);
            return;
        };
        let nicks = match targets(param) {
            Targets::Nicks(nicks) => nicks,
            // A parameter that was supplied and holds no target is the
            // case Modern settles for `USER`: "If it is empty, the server
            // SHOULD reject the command with ERR_NEEDMOREPARAMS (even if
            // an empty parameter is provided)".
            Targets::Empty => {
                self.numeric("461", &["MONITOR", "Not enough parameters"]);
                return;
            }
            Targets::NotANick(target) => {
                self.monitor_fail("INVALID_PARAMS", &target, "Target is not a nick here");
                return;
            }
        };
        let new = match to_add(&self.monitor, &nicks) {
            Added::Added(new) => new,
            Added::Full(rejected) => {
                self.monlistfull(&rejected);
                return;
            }
        };
        // Resolved first, then reported: the verdicts are read under the
        // nick and record locks, which `numeric` cannot be called under.
        let verdicts: Vec<(String, Option<String>)> = new
            .into_iter()
            .map(|nick| {
                let mask = self.verdict(&nick);
                (nick, mask)
            })
            .collect();
        let mut online = Vec::new();
        let mut offline = Vec::new();
        for (nick, mask) in verdicts {
            match mask {
                Some(mask) => {
                    online.push(mask);
                    self.monitor
                        .insert(fold(&nick), Monitored { nick, online: true });
                }
                None => {
                    self.monitor.insert(
                        fold(&nick),
                        Monitored {
                            nick: nick.clone(),
                            online: false,
                        },
                    );
                    offline.push(nick);
                }
            }
        }
        self.mononline(&online);
        self.monoffline(&offline);
    }

    /// `MONITOR - target[,target2]*`: "No output will be returned for use
    /// of this command" (ircv3-monitor.md:81-84), so a target that is not
    /// in the list, and one that could never have entered it, are both
    /// removals of nothing and are not refused.
    fn monitor_remove(&mut self, line: &Line) {
        let Some(param) = line.param(1) else {
            self.numeric("461", &["MONITOR", "Not enough parameters"]);
            return;
        };
        for target in param.split(',').filter(|t| !t.is_empty()) {
            self.monitor.remove(&fold(target));
        }
    }

    /// `MONITOR L`: 732 `RPL_MONLIST` lines, then 733
    /// `RPL_ENDOFMONLIST` (ircv3-monitor.md:91-94). An empty list sends
    /// 733 alone, there being no targets for a 732 to carry.
    fn monitor_list(&mut self) {
        let shown: Vec<String> = self.monitor.values().map(|m| m.nick.clone()).collect();
        // 732 RPL_MONLIST, ircdocs-modern-numerics.yml:932-933;
        // ircv3-monitor.md:133 `<nick> :target[,target2]*`.
        self.monitor_lines("732", &shown);
        // 733 RPL_ENDOFMONLIST, numerics.yml:935-936; the description is
        // ircv3-monitor.md:140's own text.
        self.numeric("733", &["End of MONITOR list"]);
    }

    /// `MONITOR S`: every entry reported online or offline, with no
    /// terminator (ircv3-monitor.md:96-101). The verdicts reported become
    /// the ones a later flip is measured against.
    fn monitor_status(&mut self) {
        let entries: Vec<String> = self.monitor.values().map(|m| m.nick.clone()).collect();
        let mut online = Vec::new();
        let mut offline = Vec::new();
        for nick in entries {
            match self.verdict(&nick) {
                Some(mask) => {
                    online.push(mask);
                    self.monitor_seen(&nick, true);
                }
                None => {
                    self.monitor_seen(&nick, false);
                    offline.push(nick);
                }
            }
        }
        self.mononline(&online);
        self.monoffline(&offline);
    }

    /// Reports every monitored nick whose verdict moved since it was last
    /// reported, and stores the new verdicts.
    ///
    /// One hook, called after a batch of changes is applied and after a
    /// connection that fell behind has shown itself again
    /// ([`Session::on_feed`]), so no [`mimid_agent_store::Change`] variant
    /// has to be enumerated here and a connection that lost its place is
    /// brought back in step. It reads the nicks and the records and never
    /// the agent, so it does not wait on a sync.
    pub(crate) fn monitor_refresh(&mut self) {
        if self.monitor.is_empty() {
            return;
        }
        let entries: Vec<(String, bool)> = self
            .monitor
            .values()
            .map(|m| (m.nick.clone(), m.online))
            .collect();
        let mut online = Vec::new();
        let mut offline = Vec::new();
        for (nick, was) in entries {
            let mask = self.verdict(&nick);
            if mask.is_some() == was {
                continue;
            }
            match mask {
                Some(mask) => {
                    online.push(mask);
                    self.monitor_seen(&nick, true);
                }
                None => {
                    self.monitor_seen(&nick, false);
                    offline.push(nick);
                }
            }
        }
        self.mononline(&online);
        self.monoffline(&offline);
    }

    /// Stores `online` as the verdict last reported for `nick`.
    fn monitor_seen(&mut self, nick: &str, online: bool) {
        if let Some(entry) = self.monitor.get_mut(&fold(nick)) {
            entry.online = online;
        }
    }

    /// Whether `nick` is reachable, as `nick!user@host` for 730 to carry;
    /// `None` for offline.
    ///
    /// The service nick is reachable: it is this daemon. This
    /// connection's own nick is reachable: this connection is the proof.
    /// Any other nick is one this run gave a user, and that user is
    /// reachable when the last sync counted at least one of their clients
    /// in a group this user shares
    /// ([`mimid_agent_store::record::Person::clients`]). A nick this run
    /// has not given is offline, as is a user whose count no sync has
    /// taken yet. A banned user needs no case of their own: a ban removes
    /// their clients, so the count is 0.
    ///
    /// The nick lock and the record lock are taken one after the other
    /// and both are released before the caller sends, which is what
    /// `ison` does for the same reason (`crate::command`).
    fn verdict(&self, nick: &str) -> Option<String> {
        let folded = fold(nick);
        if folded == fold(SERVICE_NICK) {
            // The service has no `Identity`: its hostmask is built from
            // the nick and the server name, as USERHOST builds it.
            return Some(format!(
                "{SERVICE_NICK}!{SERVICE_NICK}@{}",
                self.shared.server
            ));
        }
        let me = self.me();
        if folded == fold(&me.nick) {
            return Some(me.mask());
        }
        let who = {
            let mut names = self.shared.names();
            let uri = names.user_of(nick)?.to_owned();
            if uri.is_empty() {
                return None;
            }
            names.identity(&uri)
        };
        let state = self.shared.store.state();
        let count = state
            .person_of_user(&who.uri)
            .and_then(|key| state.people.get(key))
            .and_then(|person| person.clients)?;
        drop(state);
        (count > 0).then(|| who.mask())
    }

    /// 730 `RPL_MONONLINE` for `masks`, nothing for none.
    ///
    /// 730's number is ircdocs-modern-numerics.yml:926-927; its line is
    /// ircv3-monitor.md:107, `<nick> :target[!user@host][,target[!user@host]]*`.
    /// mimid sends the hostmask, which :113 allows ("The server MAY send a
    /// hostmask with the target") and the spec's Errata (:153-156) says
    /// implementations do. `<nick>` is always this client's nick and never
    /// the `*` of :115-117, which is for sending one line to every client
    /// monitoring a target; mimid writes per connection.
    fn mononline(&mut self, masks: &[String]) {
        self.monitor_lines("730", masks);
    }

    /// 731 `RPL_MONOFFLINE` for `targets`, nothing for none.
    ///
    /// 731's number is numerics.yml:929-930; its line is
    /// ircv3-monitor.md:121, `<nick> :target[,target2]*` -- bare nicks and
    /// no hostmask, which is also the only thing there is to send for a
    /// user with nothing in the group.
    fn monoffline(&mut self, targets: &[String]) {
        self.monitor_lines("731", targets);
    }

    /// Numeric `code` carrying `items` as its trailing comma-separated
    /// list, over as many lines as [`MAX_LINE`] needs; nothing for an
    /// empty list.
    fn monitor_lines(&mut self, code: &str, items: &[String]) {
        let probe = Out::new(
            &self.shared.server,
            code,
            vec![self.target(), String::new()],
        );
        let room = probe.room_for_trailing(self.caps.message_tags);
        for list in pack(items, room, ',') {
            self.numeric(code, &[&list]);
        }
    }

    /// 734 `ERR_MONLISTFULL` naming `rejected`.
    ///
    /// 734's number is numerics.yml:938-939; its line is
    /// ircv3-monitor.md:146, `<nick> <limit> <targets> :Monitor list is
    /// full.`, with the description written out as the spec has it, full
    /// stop included (meshIRCd main.go:2468 drops the stop).
    /// `<targets>` is a middle parameter, so the room is what is left of
    /// [`MAX_LINE`] once the rest of the line is written.
    ///
    /// INVENTED, NOT FROM SPEC: the spec shows one 734 with one
    /// `<targets>` list and never says what to do when that list does not
    /// fit a line, which a command naming a hundred nicks does not.
    /// mimid sends one 734 per group the list packs into, each repeating
    /// `<limit>` and the description, so a client reading only the first
    /// still gets a well-formed 734 (decision mimid-1wgh.146).
    fn monlistfull(&mut self, rejected: &[String]) {
        const FULL: &str = "Monitor list is full.";
        let limit = MAX_MONITOR.to_string();
        let probe = Out::new(
            &self.shared.server,
            "734",
            vec![self.target(), limit.clone(), String::new(), FULL.to_owned()],
        );
        let room = MAX_LINE.saturating_sub(probe.to_wire(self.caps.message_tags).len());
        for group in pack(rejected, room, ',') {
            self.numeric("734", &[&limit, &group, FULL]);
        }
    }

    /// `FAIL MONITOR <code> <context> :<description>`
    /// (ircv3-standard-replies.md:26-28, `<type> <command> <code>
    /// [<context>...] <description>`).
    ///
    /// Sent although no `standard-replies` capability is advertised, as
    /// `FAIL METADATA CANNOT_SET` already is (`crate::command`):
    /// ircv3-standard-replies.md:55-57 recommends standard replies to a
    /// client that supports that capability and forbids them to no one,
    /// and `MONITOR` defines no reply of its own for either case. Bead
    /// mimid-1wgh.140.6 owns the capability list.
    fn monitor_fail(&mut self, code: &str, context: &str, description: &str) {
        let server = self.shared.server.clone();
        self.send_cut(Out::new(
            &server,
            "FAIL",
            vec![
                "MONITOR".to_owned(),
                code.to_owned(),
                context.to_owned(),
                description.to_owned(),
            ],
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(nicks: &[&str]) -> BTreeMap<String, Monitored> {
        nicks
            .iter()
            .map(|nick| {
                (
                    fold(nick),
                    Monitored {
                        nick: (*nick).to_owned(),
                        online: false,
                    },
                )
            })
            .collect()
    }

    /// Oracle: ircv3-monitor.md:60-65 (005 announces the maximum) and
    /// :148-149 ("their monitor list is full, so the command failed").
    /// The bound is checked before anything is inserted, so the list can
    /// never hold more than 005 advertises.
    #[test]
    fn the_monitor_list_stops_at_its_bound() {
        let many: Vec<String> = (0..150).map(|n| format!("nick-{n}")).collect();
        let empty = BTreeMap::new();
        let Added::Full(rejected) = to_add(&empty, &many) else {
            panic!("150 targets do not fit a list of {MAX_MONITOR}");
        };
        // All of them, in the order sent: the command failed whole.
        assert_eq!(rejected, many);

        // Exactly the bound fits.
        let fits = &many[..MAX_MONITOR];
        assert_eq!(to_add(&empty, fits), Added::Added(fits.to_vec()));
        let full = list(&fits.iter().map(String::as_str).collect::<Vec<&str>>());
        assert_eq!(full.len(), MAX_MONITOR);
        // One more does not.
        let one = vec![many[MAX_MONITOR].clone()];
        assert_eq!(to_add(&full, &one), Added::Full(one));
        // One already held adds nothing and does not fail: it was never
        // to be added (ircv3-monitor.md:72-73).
        assert_eq!(to_add(&full, &[fits[0].clone()]), Added::Added(Vec::new()));
    }

    /// Oracle: ircv3-monitor.md:67-68 ("'target' MUST be a valid nick as
    /// determined by the IRC daemon") and :38-42 (no subscription to a
    /// hostmask), against `names::is_nick`. A junk entry that can never
    /// come online must not take a slot a real nick could have.
    #[test]
    fn a_target_that_is_no_nick_here_is_not_monitored() {
        for target in [
            "9bob",
            "-bob",
            "bob\u{9}",
            "bob!bob@a.example",
            "bob*",
            "#lobby",
            &"b".repeat(31),
        ] {
            assert_eq!(
                targets(target),
                Targets::NotANick(target.to_owned()),
                "{target:?}"
            );
            // And one bad target in a list refuses that target, not the
            // good one beside it.
            assert_eq!(
                targets(&format!("bob-a,{target}")),
                Targets::NotANick(target.to_owned()),
                "{target:?}"
            );
        }
        // A parameter that was supplied and holds no target at all.
        assert_eq!(targets(""), Targets::Empty);
        assert_eq!(targets(",,"), Targets::Empty);
        // A nick at the limit is one.
        let longest = "b".repeat(crate::names::NICKLEN);
        assert_eq!(targets(&longest), Targets::Nicks(vec![longest]));
    }

    /// Oracle: ircv3-monitor.md:72-73 ("Targets already in the list MUST
    /// NOT be added again") with `CASEMAPPING=ascii`, the 005 token this
    /// front end sends. A duplicate under another spelling would double
    /// every later 730 and 731 and halve the bound.
    #[test]
    fn a_target_already_monitored_is_not_added_again() {
        let held = list(&["bob-a"]);
        assert_eq!(
            to_add(&held, &["BOB-A".to_owned()]),
            Added::Added(Vec::new())
        );
        // Within one command, too.
        assert_eq!(
            targets("bob-a,BOB-A,Bob-A"),
            Targets::Nicks(vec!["bob-a".to_owned()])
        );
        assert_eq!(
            to_add(&BTreeMap::new(), &["bob-a".to_owned(), "BOB-A".to_owned()]),
            Added::Added(vec!["bob-a".to_owned(), "BOB-A".to_owned()]),
            "to_add dedupes against the list, `targets` against the command"
        );
    }
}
