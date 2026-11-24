//! The ZDP link keep-alive budget (ZODE_LINKS rule 9).
//!
//! `ph` runs the link keep-alive itself; the constants live here, in
//! libnode, so that the VS-API session's liveness check in
//! [crate::vsconn] can be sized from the same budget instead of
//! repeating its numbers (zl-zipline#292).

use std::time::Duration;

/// How long an Active link waits after a keep-alive answer before it
/// sends the next echo.
pub const DEFAULT_KEEP_ALIVE_PERIOD: Duration = Duration::from_secs(3);

/// How long a keep-alive echo may go unanswered before it counts as a
/// miss. After a miss the next echo goes out at once.
pub const DEFAULT_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Consecutive keep-alive (echo) misses tolerated on an Active link before
/// the link is declared dead (zipline#113). A single dropped echo on the VS
/// adapter link used to kill the whole run: with a 3 s period and 3 s
/// timeout, 3 misses gives roughly 9-12 s of grace before teardown.
pub const KEEP_ALIVE_MAX_MISSES: u32 = 3;
