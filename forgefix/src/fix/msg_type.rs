use crate::fix::generated::{is_session_message, MsgType};

/// Longest `MsgType(35)` value accepted, in bytes. Covers FIXT/FIX 5.0 two-character types
/// ("AE") and venue-proprietary ones such as "UMS".
pub(crate) const MSG_TYPE_MAX: usize = 4;

/// A `MsgType(35)` value stored inline, so carrying it costs no allocation.
///
/// FIX defines MsgType as a String: most types are one character, but FIXT/FIX 5.0 and some
/// venues use longer ones. Only the seven session-level types are interpreted by the engine;
/// every other value is an application message, delivered to the application when validation
/// accepts it (see [`is_accepted`](MsgTypeBuf::is_accepted)).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MsgTypeBuf {
    buf: [u8; MSG_TYPE_MAX],
    len: u8,
}

impl MsgTypeBuf {
    /// Wraps a MsgType used to build an outbound message.
    ///
    /// # Panics
    ///
    /// If `msg_type` is longer than [`MSG_TYPE_MAX`] bytes.
    pub(crate) fn new(msg_type: &str) -> Self {
        let bytes = msg_type.as_bytes();
        assert!(
            bytes.len() <= MSG_TYPE_MAX,
            "MsgType length {} exceeds {}",
            bytes.len(),
            MSG_TYPE_MAX
        );
        let mut buf = [0u8; MSG_TYPE_MAX];
        buf[..bytes.len()].copy_from_slice(bytes);
        Self {
            buf,
            len: bytes.len() as u8,
        }
    }

    /// Wraps a MsgType read off the wire. `None` only when the value is empty or longer
    /// than [`MSG_TYPE_MAX`] bytes — the two cases the fixed buffer cannot represent.
    /// Content is not judged here: an odd-looking type must flow on as an application
    /// message (advancing the inbound seq), never be dropped as garbled.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > MSG_TYPE_MAX {
            return None;
        }
        let mut buf = [0u8; MSG_TYPE_MAX];
        buf[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            buf,
            len: bytes.len() as u8,
        })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    pub(crate) fn len(&self) -> usize {
        self.len as usize
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The session-level type (`0 1 2 3 4 5 A`) this value names, or `None` for an
    /// application message.
    pub(crate) fn session_type(&self) -> Option<MsgType> {
        match self.as_bytes() {
            [c] if is_session_message(*c as char) => MsgType::try_from(*c as char).ok(),
            _ => None,
        }
    }

    pub(crate) fn is_session(&self) -> bool {
        self.session_type().is_some()
    }

    /// Whether this type is accepted on an inbound message: any single-character FIX 4.2
    /// type the generated [`MsgType`] enum knows, or one of the session's `extra` types
    /// (see `SessionSettingsBuilder::with_accepted_msg_types`). Judged at validation, where
    /// a rejection sends a Reject and advances the inbound seq, never at framing, where a
    /// failure would silently drop the message and stall the session.
    pub(crate) fn is_accepted(&self, extra: &[MsgTypeBuf]) -> bool {
        let fix42 = match self.as_bytes() {
            [c] => MsgType::try_from(*c as char).is_ok(),
            _ => false,
        };
        fix42 || extra.contains(self)
    }
}

#[cfg(test)]
mod tests {
    use super::MsgTypeBuf;
    use crate::fix::generated::MsgType;

    #[test]
    fn single_character_session_types_resolve() {
        for (wire, expected) in [
            (&b"0"[..], MsgType::HEARTBEAT),
            (b"1", MsgType::TEST_REQUEST),
            (b"2", MsgType::RESEND_REQUEST),
            (b"3", MsgType::REJECT),
            (b"4", MsgType::SEQUENCE_RESET),
            (b"5", MsgType::LOGOUT),
            (b"A", MsgType::LOGON),
        ] {
            let msg_type = MsgTypeBuf::from_bytes(wire).expect("valid");
            assert_eq!(msg_type.session_type(), Some(expected));
        }
    }

    #[test]
    fn application_types_of_any_length_are_not_session() {
        for wire in [&b"8"[..], b"D", b"AE", b"UMS", b"ABCD"] {
            let msg_type = MsgTypeBuf::from_bytes(wire).expect("valid");
            assert_eq!(msg_type.as_bytes(), wire);
            assert!(!msg_type.is_session());
        }
    }

    #[test]
    fn rejects_only_empty_and_too_long() {
        assert_eq!(MsgTypeBuf::from_bytes(b""), None);
        assert_eq!(MsgTypeBuf::from_bytes(b"ABCDE"), None);
        // Content is not judged at framing: unusual bytes still parse, so the message
        // reaches validation, whose rejection advances the inbound seq (no stall).
        let odd = MsgTypeBuf::from_bytes(b"#").expect("parseable");
        assert!(!odd.is_session());
    }

    fn accepted(wire: &[u8], extra: &[MsgTypeBuf]) -> bool {
        MsgTypeBuf::from_bytes(wire)
            .expect("valid")
            .is_accepted(extra)
    }

    #[test]
    fn accepts_the_fix42_list_by_default() {
        for wire in [&b"0"[..], b"A", b"8", b"D"] {
            assert!(accepted(wire, &[]));
        }
        for wire in [&b"z"[..], b"#", b"AE", b"UMS", b"ABCD"] {
            assert!(!accepted(wire, &[]));
        }
    }

    #[test]
    fn configured_types_extend_the_fix42_list() {
        let extra = [MsgTypeBuf::new("UMS"), MsgTypeBuf::new("z")];
        for wire in [&b"8"[..], b"UMS", b"z"] {
            assert!(accepted(wire, &extra));
        }
        for wire in [&b"UMX"[..], b"AE", b"#"] {
            assert!(!accepted(wire, &extra));
        }
    }
}
