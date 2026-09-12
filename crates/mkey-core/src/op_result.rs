//! What the lock says happened.
//!
//! The lock reports the outcome of an operation as a single byte. Its two low
//! bits carry the outcome *class*, which is why a code nobody has a name for
//! can still be classified — and why the session can tell "the lock has
//! decided" from "the lock is still working".

/// Outcome class, taken from the two low bits of an operation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpResultGroup {
    #[default]
    Unknown = 0,
    Failure = 1,
    Accepted = 2,
    Rejected = 3,
}

impl OpResultGroup {
    /// Classify an operation result byte.
    pub const fn of(op_result: u8) -> Self {
        match op_result & 3 {
            1 => Self::Failure,
            2 => Self::Accepted,
            3 => Self::Rejected,
            _ => Self::Unknown,
        }
    }

    /// The spelling the TypeScript port uses.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Failure => "failure",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }

    /// Whether the lock let the holder through.
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }

    /// Whether the lock has reached a verdict — the session may end.
    pub const fn is_final(self) -> bool {
        matches!(self, Self::Accepted | Self::Rejected)
    }
}

impl std::fmt::Display for OpResultGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Human readable name of an operation result reported by the lock.
pub const fn decode_op_result(op_result: u8) -> &'static str {
    match op_result {
        0 => "UNKNOWN_RESULT",
        2 => "ACCESS_GRANTED",
        3 => "ACCESS_REJECTED",
        6 => "DOOR_IN_OFFICE",
        7 => "PIN_REQUIRED",
        10 => "END_OFFICE",
        11 => "CANCELLED_KEY",
        14 => "OPENING_ROLLER",
        18 => "CLOSING_ROLLER",
        22 => "STOP_ROLLER",
        26 => "WAIT_SECOND_CARD",
        27 => "FINGER_REQUIRED",
        30 => "KEY_PROCESSED",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_group_is_the_two_low_bits() {
        assert_eq!(OpResultGroup::of(30), OpResultGroup::Accepted);
        assert_eq!(OpResultGroup::of(3), OpResultGroup::Rejected);
        assert_eq!(OpResultGroup::of(11), OpResultGroup::Rejected);
        assert_eq!(OpResultGroup::of(0), OpResultGroup::Unknown);
        assert_eq!(OpResultGroup::of(1), OpResultGroup::Failure);
    }

    #[test]
    fn only_accepted_and_rejected_end_a_session() {
        assert!(OpResultGroup::Accepted.is_final());
        assert!(OpResultGroup::Rejected.is_final());
        assert!(!OpResultGroup::Unknown.is_final());
        assert!(!OpResultGroup::Failure.is_final());
    }

    #[test]
    fn an_unnamed_result_still_has_a_group() {
        assert_eq!(decode_op_result(200), "UNKNOWN");
        assert_eq!(OpResultGroup::of(200), OpResultGroup::Unknown);
    }
}
