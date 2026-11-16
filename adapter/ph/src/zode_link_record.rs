//! The per-peer Zode link record and its state machine (docs/ZODE_LINKS.md
//! rules 1, 2, 6-8, 10, 11 and 13; zl-zipline#250).
//!
//! A Zode keeps one record per peer it links with: its initial link, and
//! each link in its current topology. The record says who owns the link,
//! where to dial it, which connection currently serves it, and how the link
//! is doing. It is pure: it reads no clock and does no I/O. The driver in
//! [crate::zode_links] feeds it [Event]s and performs the [Action]s it
//! returns.
//!
//! The design's states map onto this record and the per-connection state
//! machine in [crate::link_state] like this:
//!
//! | Design state | Here                                    | Connection (`link_state`) |
//! |--------------|-----------------------------------------|---------------------------|
//! | dialing      | [RecordState::Dialing]                  | `Keying` (dialer)         |
//! | keying       | [RecordState::Dialing]                  | `Keying`                  |
//! | CN check     | [RecordState::Dialing]                  | the `KeyingDone` step     |
//! | up           | [RecordState::Up]                       | `Active`                  |
//! | closing      | (unchanged until the connection closes) | `Closing`                 |
//! | closed       | [Event::Closed], then Down/Failed/redial | peer entry dropped        |
//!
//! Every connection-scoped thing hangs off the connection's peer-table
//! entry, so dropping that entry clears it (rule 9). The record only holds
//! the connection's id, and forgets it on [Event::Closed].

use crate::zode_links::Owner;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use zpr::packet_info::LinkId;

/// How long the owner of a topology link gives it to come up before it
/// reports `failed` and stops (rule 6). 10 s, not the design's first 5 s
/// (gate g123): the non-owner can learn the link about 4 s after the owner
/// (the visa service's VSS start delay plus a NoRoute retry), and the
/// owner's redials must keep going past that.
pub const LINK_UP_WINDOW: Duration = Duration::from_secs(10);

/// How soon the owner redials a topology link after an attempt fails inside
/// the link-up window (rule 6: "about once a second"). This covers the
/// owner's topology arriving before the peer's, so that the peer refuses
/// the first attempt under rule 3.
pub const OWNER_REDIAL_INTERVAL: Duration = Duration::from_secs(1);

/// The first delay before redialing the initial link (rule 11). Each failed
/// attempt doubles it, up to [INITIAL_LINK_BACKOFF_MAX].
pub const INITIAL_LINK_BACKOFF_MIN: Duration = Duration::from_secs(1);

/// The longest delay between initial-link attempts (rule 11).
pub const INITIAL_LINK_BACKOFF_MAX: Duration = Duration::from_secs(30);

// Every per-attempt bound on a Zode link fits inside the link-up window, so
// an owner's attempt ends on its own before the window does.
const _: () = assert!(
    crate::config::ZODE_KEYING_TIMEOUT.as_millis() + crate::config::ZODE_HELLO_TIMEOUT.as_millis()
        < LINK_UP_WINDOW.as_millis()
);

/// The two kinds of Zode link ("Kinds of link").
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// From this Zode's own config. This Zode owns it and retries it with
    /// backoff until it comes back (rule 11). Never failed.
    Initial,
    /// From `setTopology`. One attempt per `setTopology` (rules 6 and 13).
    Topology,
}

/// How a link is doing, as the record tracks it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecordState {
    /// Nothing under way: a non-owner waiting for its peer to dial.
    Idle,
    /// Bringing the link up. For a topology link the owner's link-up window
    /// ends at `window_ends`; the initial link has no window.
    Dialing { window_ends: Option<Instant> },
    /// Up: the connection is Active with the peer's CN verified (rule 7).
    Up,
    /// The owner's link-up window ended without the link coming up (rule 6).
    Failed,
    /// The link was up and was lost (rule 10). The initial link keeps
    /// redialing in this state (rule 11).
    Down,
}

/// The last outcome a link reached: what the link-state report says about
/// it. `None` until there is one ("Reporting summary").
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Up,
    Down,
    Failed,
}

/// Which timer fired. Both carry the record's logical clock from when they
/// were armed, so a timer armed before a state change is ignored.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Timer {
    /// The owner's link-up window ended (rule 6).
    WindowEnd,
    /// Time to redial (rule 6 inside the window, rule 11 for the initial link).
    Redial,
}

/// What happened to a link, fed to [LinkRecord::handle].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Bring the link up: at startup for the initial link, and on every
    /// `setTopology` that contains a topology link (rule 13).
    Start,
    /// The driver started an attempt; `LinkId` is its connection.
    Dialed(LinkId),
    /// The driver could not start an attempt (for example, no route).
    DialFailed,
    /// The connection `LinkId` went Active with the peer's CN verified.
    Up(LinkId),
    /// The connection `LinkId` closed and its peer entry was dropped.
    Closed(LinkId),
    /// A timer fired, armed when the record's logical clock was `clock`.
    Timer { timer: Timer, clock: u64 },
}

/// What the driver must do for a record.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Dial the peer, then feed back [Event::Dialed] or [Event::DialFailed].
    Dial,
    /// Close the connection `LinkId` (an attempt the window gave up on).
    Close(LinkId),
    /// Fire `timer` after `after`, carrying `clock`.
    Arm {
        timer: Timer,
        after: Duration,
        clock: u64,
    },
}

/// One Zode link: everything this Zode tracks about the link to one peer.
#[derive(Clone, Debug)]
pub struct LinkRecord {
    /// Initial or topology link.
    pub kind: Kind,
    /// Who dials it (see [crate::zode_links::link_owner]).
    pub owner: Owner,
    /// The peer's substrate address, which the owner dials. `None` only
    /// when the peer owns the link: the visa service may not know the
    /// address of a Zode that dials in (ZODE_LINKS.md rule 13b).
    pub dial_addr: Option<SocketAddr>,
    /// The connection currently serving the link: an attempt or the up
    /// link. `None` when there is none.
    pub link_id: Option<LinkId>,
    /// How the link is doing.
    pub state: RecordState,
    /// What the link-state report says about the link.
    pub outcome: Option<Outcome>,
    /// The base delay before the next initial-link redial.
    backoff: Duration,
    /// Logical clock: bumped on every state change, so timers armed in an
    /// earlier state are recognised as stale.
    clock: u64,
    /// Jitter source: a uniform number in [0, 1).
    jitter: fn() -> f64,
}

impl LinkRecord {
    /// A new, idle record. `jitter` returns a uniform number in [0, 1) and
    /// spreads initial-link redials; see [jittered].
    pub fn new(
        kind: Kind,
        owner: Owner,
        dial_addr: Option<SocketAddr>,
        jitter: fn() -> f64,
    ) -> Self {
        LinkRecord {
            kind,
            owner,
            dial_addr,
            link_id: None,
            state: RecordState::Idle,
            outcome: None,
            backoff: INITIAL_LINK_BACKOFF_MIN,
            clock: 0,
            jitter,
        }
    }

    /// Feed one event at time `now`, and return what the driver must do.
    pub fn handle(&mut self, event: Event, now: Instant) -> Vec<Action> {
        match event {
            Event::Start => self.start(now),
            Event::Dialed(link_id) => {
                if self.is_retrying() {
                    self.link_id = Some(link_id);
                    Vec::new()
                } else {
                    // The attempt is no longer wanted (the window ended or
                    // the link came up another way): close it.
                    vec![Action::Close(link_id)]
                }
            }
            Event::DialFailed => self.attempt_failed(now),
            Event::Up(link_id) => self.up(link_id),
            Event::Closed(link_id) if self.link_id == Some(link_id) => {
                self.link_id = None;
                if self.state == RecordState::Up {
                    self.lost()
                } else {
                    self.attempt_failed(now)
                }
            }
            // A connection this record no longer tracks.
            Event::Closed(_) => Vec::new(),
            Event::Timer { clock, .. } if clock != self.clock => Vec::new(),
            Event::Timer {
                timer: Timer::WindowEnd,
                ..
            } => self.window_ended(),
            Event::Timer {
                timer: Timer::Redial,
                ..
            } => self.redial(),
        }
    }

    /// Whether this record is trying to bring its link up: it may dial.
    fn is_retrying(&self) -> bool {
        match self.kind {
            Kind::Topology => matches!(self.state, RecordState::Dialing { .. }),
            Kind::Initial => matches!(self.state, RecordState::Dialing { .. } | RecordState::Down),
        }
    }

    /// Start: the owner of an idle, failed or down topology link opens a
    /// window and dials (rules 6 and 13); the initial link dials once at
    /// startup (rule 11). The non-owner never dials (rule 2), and a link
    /// already up or under way is left alone.
    fn start(&mut self, now: Instant) -> Vec<Action> {
        if self.owner != Owner::ThisZode {
            return Vec::new();
        }
        match (self.kind, self.state) {
            (Kind::Topology, RecordState::Idle | RecordState::Failed | RecordState::Down) => {
                // "Reporting contract": `failed` is listed only while the
                // record is Failed. A retry clears it, so the link is not
                // listed until the retry resolves (and a retry that fails is
                // a new failure). A down link stays down meanwhile.
                if self.state == RecordState::Failed {
                    self.outcome = None;
                }
                let window_ends = now + LINK_UP_WINDOW;
                self.enter(RecordState::Dialing {
                    window_ends: Some(window_ends),
                });
                vec![
                    Action::Dial,
                    Action::Arm {
                        timer: Timer::WindowEnd,
                        after: LINK_UP_WINDOW,
                        clock: self.clock,
                    },
                ]
            }
            (Kind::Initial, RecordState::Idle) => {
                self.enter(RecordState::Dialing { window_ends: None });
                vec![Action::Dial]
            }
            _ => Vec::new(),
        }
    }

    /// An attempt failed before the link came up (or could not start).
    /// Inside the window the owner redials after [OWNER_REDIAL_INTERVAL]
    /// (rule 6); the initial link redials with backoff (rule 11).
    fn attempt_failed(&mut self, now: Instant) -> Vec<Action> {
        if !self.is_retrying() {
            return Vec::new();
        }
        match (self.kind, self.state) {
            (
                Kind::Topology,
                RecordState::Dialing {
                    window_ends: Some(ends),
                },
            ) => {
                if now + OWNER_REDIAL_INTERVAL < ends {
                    vec![self.arm(Timer::Redial, OWNER_REDIAL_INTERVAL)]
                } else {
                    // Too late to redial; the window end reports failed.
                    Vec::new()
                }
            }
            (Kind::Initial, _) => {
                let after = jittered(self.backoff, (self.jitter)());
                self.backoff = (self.backoff * 2).min(INITIAL_LINK_BACKOFF_MAX);
                vec![self.arm(Timer::Redial, after)]
            }
            _ => Vec::new(),
        }
    }

    /// The redial timer fired: dial again if still retrying and no attempt
    /// is in flight.
    fn redial(&mut self) -> Vec<Action> {
        if self.is_retrying() && self.link_id.is_none() {
            vec![Action::Dial]
        } else {
            Vec::new()
        }
    }

    /// The owner's window ended without the link up: abort any attempt in
    /// flight, report failed and stop (rule 6). Only a later `setTopology`
    /// tries again (rule 13).
    fn window_ended(&mut self) -> Vec<Action> {
        if !matches!(
            self.state,
            RecordState::Dialing {
                window_ends: Some(_)
            }
        ) {
            return Vec::new();
        }
        self.enter(RecordState::Failed);
        self.outcome = Some(Outcome::Failed);
        self.link_id.take().map(Action::Close).into_iter().collect()
    }

    /// The connection `link_id` went Active with the CN verified (rules 7
    /// and 8). A replacement connection (rule 5) takes over the record.
    fn up(&mut self, link_id: LinkId) -> Vec<Action> {
        let mut actions = Vec::new();
        if let Some(previous) = self.link_id.filter(|id| *id != link_id) {
            // An attempt of ours that the up link made redundant.
            if self.state != RecordState::Up {
                actions.push(Action::Close(previous));
            }
        }
        self.link_id = Some(link_id);
        self.enter(RecordState::Up);
        self.outcome = Some(Outcome::Up);
        if self.kind == Kind::Initial {
            self.backoff = INITIAL_LINK_BACKOFF_MIN;
        }
        actions
    }

    /// The up link was lost (rules 10 and 11). A topology link goes down
    /// and stays down: nobody redials it. The initial link goes down and
    /// redials with backoff.
    fn lost(&mut self) -> Vec<Action> {
        self.enter(RecordState::Down);
        self.outcome = Some(Outcome::Down);
        if self.kind == Kind::Initial {
            let after = jittered(self.backoff, (self.jitter)());
            self.backoff = (self.backoff * 2).min(INITIAL_LINK_BACKOFF_MAX);
            return vec![self.arm(Timer::Redial, after)];
        }
        Vec::new()
    }

    /// Change state, bumping the logical clock so older timers go stale.
    fn enter(&mut self, state: RecordState) {
        self.state = state;
        self.clock = self.clock.wrapping_add(1);
    }

    /// An [Action::Arm] for `timer` after `after`, at the current clock.
    fn arm(&self, timer: Timer, after: Duration) -> Action {
        Action::Arm {
            timer,
            after,
            clock: self.clock,
        }
    }
}

/// `base` with jitter: a delay uniform in [base / 2, base), given `unit`
/// uniform in [0, 1). Spreading redials keeps endpoints that lost their
/// relay together from redialing in lockstep.
pub fn jittered(base: Duration, unit: f64) -> Duration {
    base.mul_f64(0.5 + 0.5 * unit.clamp(0.0, 1.0))
}

/// A uniform number in [0, 1) from the system RNG, the production jitter
/// source for [LinkRecord::new].
pub fn system_jitter() -> f64 {
    let mut bytes = [0u8; 8];
    aws_lc_rs::rand::fill(&mut bytes).expect("OS RNG failed");
    (u64::from_le_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed jitter source: the midpoint, so delays are 3/4 of the base.
    fn mid_jitter() -> f64 {
        0.5
    }

    fn record(kind: Kind, owner: Owner) -> LinkRecord {
        LinkRecord::new(
            kind,
            owner,
            Some("10.0.0.9:5000".parse().unwrap()),
            mid_jitter,
        )
    }

    /// The clock carried by the first `Arm` of `timer` in `actions`.
    fn armed(actions: &[Action], timer: Timer) -> (Duration, u64) {
        actions
            .iter()
            .find_map(|a| match a {
                Action::Arm {
                    timer: t,
                    after,
                    clock,
                } if *t == timer => Some((*after, *clock)),
                _ => None,
            })
            .expect("timer armed")
    }

    // ---- topology link, this Zode owns it (rules 1, 6, 7, 10, 13) ----

    /// Owner: Idle -> Dialing on Start. It dials and arms the window.
    #[test]
    fn owner_idle_to_dialing_on_start() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::ThisZode);
        let actions = r.handle(Event::Start, now);
        assert_eq!(
            r.state,
            RecordState::Dialing {
                window_ends: Some(now + LINK_UP_WINDOW)
            }
        );
        assert_eq!(actions[0], Action::Dial);
        assert_eq!(armed(&actions, Timer::WindowEnd).0, LINK_UP_WINDOW);
        assert_eq!(
            r.outcome, None,
            "nothing to report while the first window is open"
        );
    }

    /// Owner: Dialing records the attempt's connection.
    #[test]
    fn owner_dialing_records_the_attempt() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::ThisZode);
        r.handle(Event::Start, now);
        assert!(r.handle(Event::Dialed(7), now).is_empty());
        assert_eq!(r.link_id, Some(7));
    }

    /// Owner: Dialing -> Up when the connection goes Active.
    #[test]
    fn owner_dialing_to_up() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::ThisZode);
        r.handle(Event::Start, now);
        r.handle(Event::Dialed(7), now);
        assert!(r.handle(Event::Up(7), now).is_empty());
        assert_eq!(r.state, RecordState::Up);
        assert_eq!(r.outcome, Some(Outcome::Up));
    }

    /// Owner: an attempt that fails inside the window is redialed after
    /// about a second.
    #[test]
    fn owner_failed_attempt_redials_inside_window() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::ThisZode);
        r.handle(Event::Start, now);
        r.handle(Event::Dialed(7), now);
        let actions = r.handle(Event::Closed(7), now + Duration::from_millis(300));
        let (after, clock) = armed(&actions, Timer::Redial);
        assert_eq!(after, OWNER_REDIAL_INTERVAL);
        assert_eq!(r.link_id, None);
        assert!(matches!(r.state, RecordState::Dialing { .. }));
        assert_eq!(
            r.handle(
                Event::Timer {
                    timer: Timer::Redial,
                    clock
                },
                now + Duration::from_millis(1300)
            ),
            vec![Action::Dial]
        );
    }

    /// Owner: a start failure counts as a failed attempt.
    #[test]
    fn owner_dial_failure_redials_inside_window() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::ThisZode);
        r.handle(Event::Start, now);
        let actions = r.handle(Event::DialFailed, now);
        assert_eq!(armed(&actions, Timer::Redial).0, OWNER_REDIAL_INTERVAL);
    }

    /// Owner: no redial is armed once it would land past the window.
    #[test]
    fn owner_no_redial_past_the_window() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::ThisZode);
        r.handle(Event::Start, now);
        r.handle(Event::Dialed(7), now);
        assert!(
            r.handle(
                Event::Closed(7),
                now + LINK_UP_WINDOW - OWNER_REDIAL_INTERVAL / 2
            )
            .is_empty()
        );
    }

    /// Gate g123: the non-owner can learn the link well after the owner.
    /// When the owner already has a VSS session as the non-owner
    /// authenticates, the visa service sends the owner the link at once
    /// but reaches the non-owner only after its VSS start delay (3 s) and
    /// a NoRoute retry (1 s); zode-reroute-test.sh saw 4.2 s. An attempt
    /// refused (rule 3) that late must still be followed by a redial
    /// inside the window, or the link ends failed although both ends are
    /// healthy.
    #[test]
    fn owner_redials_after_the_non_owners_topology_lag() {
        const NON_OWNER_TOPOLOGY_LAG: Duration = Duration::from_millis(4500);
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::ThisZode);
        r.handle(Event::Start, now);
        r.handle(Event::Dialed(7), now);
        let actions = r.handle(Event::Closed(7), now + NON_OWNER_TOPOLOGY_LAG);
        assert_eq!(armed(&actions, Timer::Redial).0, OWNER_REDIAL_INTERVAL);
    }

    /// Owner: the window ends -> Failed; the attempt in flight is aborted
    /// and nothing redials.
    #[test]
    fn owner_window_end_to_failed_aborts_attempt() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::ThisZode);
        let start = r.handle(Event::Start, now);
        let (_, window_clock) = armed(&start, Timer::WindowEnd);
        r.handle(Event::Dialed(7), now);
        let actions = r.handle(
            Event::Timer {
                timer: Timer::WindowEnd,
                clock: window_clock,
            },
            now + LINK_UP_WINDOW,
        );
        assert_eq!(actions, vec![Action::Close(7)]);
        assert_eq!(r.state, RecordState::Failed);
        assert_eq!(r.outcome, Some(Outcome::Failed));
        assert_eq!(r.link_id, None);
        // The aborted connection's close changes nothing, and a late
        // redial timer is stale.
        assert!(r.handle(Event::Closed(7), now + LINK_UP_WINDOW).is_empty());
        assert!(
            r.handle(
                Event::Timer {
                    timer: Timer::Redial,
                    clock: window_clock
                },
                now + LINK_UP_WINDOW
            )
            .is_empty()
        );
        assert_eq!(r.state, RecordState::Failed);
    }

    /// Owner: an attempt that only starts after the window ended is closed.
    #[test]
    fn owner_attempt_started_after_window_is_closed() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::ThisZode);
        let start = r.handle(Event::Start, now);
        let (_, clock) = armed(&start, Timer::WindowEnd);
        r.handle(
            Event::Timer {
                timer: Timer::WindowEnd,
                clock,
            },
            now + LINK_UP_WINDOW,
        );
        assert_eq!(
            r.handle(Event::Dialed(8), now + LINK_UP_WINDOW),
            vec![Action::Close(8)]
        );
    }

    /// Owner: a stale window timer after Up is ignored.
    #[test]
    fn owner_stale_timer_after_up_is_ignored() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::ThisZode);
        let start = r.handle(Event::Start, now);
        let (_, clock) = armed(&start, Timer::WindowEnd);
        r.handle(Event::Dialed(7), now);
        r.handle(Event::Up(7), now);
        assert!(
            r.handle(
                Event::Timer {
                    timer: Timer::WindowEnd,
                    clock
                },
                now + LINK_UP_WINDOW
            )
            .is_empty()
        );
        assert_eq!(r.state, RecordState::Up);
    }

    /// Owner: Up -> Down on loss, and it does not redial (rule 10).
    #[test]
    fn owner_up_to_down_on_loss_without_redial() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::ThisZode);
        r.handle(Event::Start, now);
        r.handle(Event::Dialed(7), now);
        r.handle(Event::Up(7), now);
        assert!(r.handle(Event::Closed(7), now).is_empty());
        assert_eq!(r.state, RecordState::Down);
        assert_eq!(r.outcome, Some(Outcome::Down));
        assert_eq!(r.link_id, None);
    }

    /// Owner: Start again (a later setTopology, rule 13) retries a Down
    /// link once; it stays reported down until the attempt resolves.
    #[test]
    fn owner_start_retries_down() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::ThisZode);
        r.state = RecordState::Down;
        r.outcome = Some(Outcome::Down);
        let actions = r.handle(Event::Start, now);
        assert_eq!(actions[0], Action::Dial);
        assert!(matches!(r.state, RecordState::Dialing { .. }));
        assert_eq!(r.outcome, Some(Outcome::Down));
    }

    /// Reporting contract: failed -> retry (not listed) -> failed again.
    /// `failed` is listed only while the record is Failed; a retry clears
    /// it, and a retry that runs out its window is a new failure.
    #[test]
    fn owner_failed_retry_is_unlisted_then_failed_again() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::ThisZode);
        let start = r.handle(Event::Start, now);
        let (_, clock) = armed(&start, Timer::WindowEnd);
        r.handle(
            Event::Timer {
                timer: Timer::WindowEnd,
                clock,
            },
            now + LINK_UP_WINDOW,
        );
        assert_eq!(r.outcome, Some(Outcome::Failed));

        let later = now + LINK_UP_WINDOW * 3;
        let retry = r.handle(Event::Start, later);
        assert_eq!(retry[0], Action::Dial);
        assert_eq!(r.outcome, None, "a retrying link is not listed");

        let (_, clock) = armed(&retry, Timer::WindowEnd);
        r.handle(
            Event::Timer {
                timer: Timer::WindowEnd,
                clock,
            },
            later + LINK_UP_WINDOW,
        );
        assert_eq!(r.state, RecordState::Failed);
        assert_eq!(r.outcome, Some(Outcome::Failed), "listed failed again");
    }

    /// Owner: Start leaves an Up link, or one already dialing, alone.
    #[test]
    fn owner_start_leaves_up_and_dialing_alone() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::ThisZode);
        r.handle(Event::Start, now);
        assert!(r.handle(Event::Start, now).is_empty());
        r.handle(Event::Dialed(7), now);
        r.handle(Event::Up(7), now);
        assert!(r.handle(Event::Start, now).is_empty());
        assert_eq!(r.state, RecordState::Up);
    }

    /// A close of a connection the record does not track changes nothing.
    #[test]
    fn closed_of_untracked_connection_is_ignored() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::ThisZode);
        r.handle(Event::Start, now);
        r.handle(Event::Dialed(7), now);
        r.handle(Event::Up(7), now);
        assert!(r.handle(Event::Closed(99), now).is_empty());
        assert_eq!(r.state, RecordState::Up);
    }

    // ---- topology link, the peer owns it (rules 2, 8, 10) ----

    /// Non-owner: Start never dials.
    #[test]
    fn non_owner_never_dials() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::Peer);
        assert!(r.handle(Event::Start, now).is_empty());
        assert_eq!(r.state, RecordState::Idle);
        assert!(r.handle(Event::DialFailed, now).is_empty());
    }

    /// Non-owner: Idle -> Up when the owner's link is accepted.
    #[test]
    fn non_owner_idle_to_up() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::Peer);
        r.handle(Event::Up(4), now);
        assert_eq!(r.state, RecordState::Up);
        assert_eq!(r.outcome, Some(Outcome::Up));
    }

    /// Non-owner: Up -> Down on loss, and Down -> Up when the owner comes
    /// back. Never Failed.
    #[test]
    fn non_owner_up_down_up_never_failed() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::Peer);
        r.handle(Event::Up(4), now);
        assert!(
            r.handle(Event::Closed(4), now + LINK_UP_WINDOW * 2)
                .is_empty()
        );
        assert_eq!(r.state, RecordState::Down);
        assert!(
            r.handle(Event::Start, now).is_empty(),
            "the non-owner waits"
        );
        r.handle(Event::Up(5), now);
        assert_eq!(r.state, RecordState::Up);
        assert_ne!(r.outcome, Some(Outcome::Failed));
    }

    /// Rule 5: a replacing connection takes over an Up record, and the
    /// replaced connection's later close changes nothing.
    #[test]
    fn replacement_connection_takes_over() {
        let now = Instant::now();
        let mut r = record(Kind::Topology, Owner::Peer);
        r.handle(Event::Up(4), now);
        assert!(r.handle(Event::Up(5), now).is_empty());
        assert_eq!(r.link_id, Some(5));
        assert!(r.handle(Event::Closed(4), now).is_empty());
        assert_eq!(r.state, RecordState::Up);
    }

    // ---- the initial link (rule 11) ----

    /// Initial: Idle -> Dialing on Start, with no window.
    #[test]
    fn initial_idle_to_dialing() {
        let now = Instant::now();
        let mut r = record(Kind::Initial, Owner::ThisZode);
        assert_eq!(r.handle(Event::Start, now), vec![Action::Dial]);
        assert_eq!(r.state, RecordState::Dialing { window_ends: None });
    }

    /// Initial: failed attempts back off 1, 2, 4, ... s, capped at 30 s,
    /// each jittered into [base/2, base).
    #[test]
    fn initial_backoff_doubles_to_the_cap() {
        let now = Instant::now();
        let mut r = record(Kind::Initial, Owner::ThisZode);
        r.handle(Event::Start, now);
        let mut delays = Vec::new();
        for id in 1..=8 {
            r.handle(Event::Dialed(id), now);
            let actions = r.handle(Event::Closed(id), now);
            let (after, clock) = armed(&actions, Timer::Redial);
            delays.push(after);
            assert_eq!(
                r.handle(
                    Event::Timer {
                        timer: Timer::Redial,
                        clock
                    },
                    now
                ),
                vec![Action::Dial]
            );
        }
        let bases = [1, 2, 4, 8, 16, 30, 30, 30].map(Duration::from_secs);
        for (delay, base) in delays.iter().zip(bases) {
            assert_eq!(*delay, base.mul_f64(0.75), "mid jitter is 3/4 of the base");
        }
    }

    /// The jitter stays within [base/2, base].
    #[test]
    fn jitter_bounds() {
        let base = Duration::from_secs(8);
        assert_eq!(jittered(base, 0.0), Duration::from_secs(4));
        assert_eq!(jittered(base, 1.0), base);
        for _ in 0..100 {
            let unit = system_jitter();
            assert!((0.0..1.0).contains(&unit));
            let d = jittered(base, unit);
            assert!(d >= base / 2 && d <= base);
        }
    }

    /// Initial: Up resets the backoff, and is never Failed.
    #[test]
    fn initial_up_resets_backoff() {
        let now = Instant::now();
        let mut r = record(Kind::Initial, Owner::ThisZode);
        r.handle(Event::Start, now);
        for id in 1..=3 {
            r.handle(Event::Dialed(id), now);
            r.handle(Event::Closed(id), now);
        }
        r.handle(Event::Dialed(9), now);
        r.handle(Event::Up(9), now);
        assert_eq!(r.state, RecordState::Up);
        let actions = r.handle(Event::Closed(9), now);
        assert_eq!(
            armed(&actions, Timer::Redial).0,
            INITIAL_LINK_BACKOFF_MIN.mul_f64(0.75)
        );
    }

    /// Initial: loss -> Down, and it redials (rule 11), staying Down while
    /// it retries.
    #[test]
    fn initial_loss_to_down_and_redial() {
        let now = Instant::now();
        let mut r = record(Kind::Initial, Owner::ThisZode);
        r.handle(Event::Start, now);
        r.handle(Event::Dialed(1), now);
        r.handle(Event::Up(1), now);
        let actions = r.handle(Event::Closed(1), now);
        assert_eq!(r.state, RecordState::Down);
        assert_eq!(r.outcome, Some(Outcome::Down));
        let (_, clock) = armed(&actions, Timer::Redial);
        assert_eq!(
            r.handle(
                Event::Timer {
                    timer: Timer::Redial,
                    clock
                },
                now
            ),
            vec![Action::Dial]
        );
        r.handle(Event::Dialed(2), now);
        let actions = r.handle(Event::Closed(2), now);
        assert_eq!(r.state, RecordState::Down);
        armed(&actions, Timer::Redial);
        assert!(
            r.handle(Event::Start, now).is_empty(),
            "the retry runs itself"
        );
    }

    /// Initial: never Failed, whatever the timers do.
    #[test]
    fn initial_never_failed() {
        let now = Instant::now();
        let mut r = record(Kind::Initial, Owner::ThisZode);
        r.handle(Event::Start, now);
        for clock in 0..4 {
            r.handle(
                Event::Timer {
                    timer: Timer::WindowEnd,
                    clock,
                },
                now,
            );
        }
        assert_ne!(r.state, RecordState::Failed);
    }

    /// A redial timer with an attempt still in flight does not dial twice.
    #[test]
    fn redial_with_attempt_in_flight_does_nothing() {
        let now = Instant::now();
        let mut r = record(Kind::Initial, Owner::ThisZode);
        r.handle(Event::Start, now);
        r.handle(Event::Dialed(1), now);
        let actions = r.handle(Event::Closed(1), now);
        let (_, clock) = armed(&actions, Timer::Redial);
        r.handle(
            Event::Timer {
                timer: Timer::Redial,
                clock,
            },
            now,
        );
        r.handle(Event::Dialed(2), now);
        assert!(
            r.handle(
                Event::Timer {
                    timer: Timer::Redial,
                    clock
                },
                now
            )
            .is_empty()
        );
    }
}
