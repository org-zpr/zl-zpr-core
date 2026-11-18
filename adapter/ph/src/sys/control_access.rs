//! Platform-neutral pieces of control-channel access control
//! (zipline#154). Compiled on every OS so the Windows DACL string and the
//! warning wording stay unit-testable from Linux builds — the same pattern
//! as `macos_ifconfig` in `sys/mod.rs`.

/// The startup warning for a configured `control_group` that does not
/// exist on this host. One builder for both control arms (posix socket,
/// Windows pipe) so the wording is identical on every platform.
pub(crate) fn missing_group_warning(name: &str) -> String {
    format!(
        "control group '{name}' not found on this host; \
         the control channel keeps its default access"
    )
}

/// The SDDL string for the Windows control pipe's security descriptor
/// (plan D6, zipline#154): a protected DACL (`D:P`, nothing inherited) with
/// full access for `BUILTIN\Administrators` (`BA`), for the owning user's
/// SID, and — when a control group is configured and exists — for that
/// group's SID. Without a group the string is exactly the pre-#154 one.
///
/// `group_sid` must come from `admin_api::local_group_sid`, i.e. from
/// `ConvertSidToStringSidW`; as defence in depth, debug builds assert it is
/// `S-1-` followed only by digits and dashes, so nothing that could close
/// the ACE and open another can be spliced in.
///
/// Pure string construction, unit-testable everywhere; the conversion to a
/// binary security descriptor is in the Windows arm.
pub(crate) fn control_pipe_sddl(owner_sid: &str, group_sid: Option<&str>) -> String {
    match group_sid {
        None => format!("D:P(A;;GA;;;BA)(A;;GA;;;{owner_sid})"),
        Some(group) => {
            debug_assert!(
                is_string_sid(group),
                "control group SID {group:?} is not a string SID"
            );
            format!("D:P(A;;GA;;;BA)(A;;GA;;;{owner_sid})(A;;GA;;;{group})")
        }
    }
}

/// `S-1-` followed only by ASCII digits and dashes.
fn is_string_sid(s: &str) -> bool {
    s.strip_prefix("S-1-").is_some_and(|rest| {
        !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wording is pinned: it is the one string an operator greps for
    /// on every platform.
    #[test]
    fn missing_group_warning_wording() {
        assert_eq!(
            missing_group_warning("zipline"),
            "control group 'zipline' not found on this host; \
             the control channel keeps its default access"
        );
    }

    /// No group: exactly the pre-zipline#154 DACL — Administrators and the
    /// owner, protected from inheritance (plan D6).
    #[test]
    fn sddl_without_group_unchanged() {
        assert_eq!(
            control_pipe_sddl("S-1-5-21-1-2-3-1001", None),
            "D:P(A;;GA;;;BA)(A;;GA;;;S-1-5-21-1-2-3-1001)"
        );
    }

    /// With a group SID: exactly one extra full-access ACE for it, after
    /// the two existing ones (zipline#154 acceptance criterion 1).
    #[test]
    fn sddl_with_group_adds_exactly_one_ace() {
        let sddl = control_pipe_sddl("S-1-5-18", Some("S-1-5-21-111-222-333-1005"));
        assert_eq!(
            sddl,
            "D:P(A;;GA;;;BA)(A;;GA;;;S-1-5-18)(A;;GA;;;S-1-5-21-111-222-333-1005)"
        );
        assert_eq!(sddl.matches("(A;;GA;;;").count(), 3);
    }

    /// Defence in depth: a group "SID" that is not `S-1-` + digits/dashes
    /// never reaches the SDDL string (debug builds assert).
    #[test]
    #[should_panic(expected = "not a string SID")]
    #[cfg(debug_assertions)]
    fn sddl_rejects_non_sid_group() {
        control_pipe_sddl("S-1-5-18", Some("S-1-5-32-545)(A;;GA;;;WD"));
    }
}
