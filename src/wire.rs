//! Wire contract — shared by server and client, byte-compatible with the TS
//! `@bsv` authsocket stack.
//!
//! Two layers:
//!  1. **Transport frame:** every BRC-103 `AuthMessage` travels over a single
//!     Socket.IO event named [`AUTH_MESSAGE_EVENT`] (`"authMessage"`). The event
//!     argument *is* the `AuthMessage` JSON (camelCase; `payload`/`signature`
//!     serialize as JSON number arrays — this is the bsv-sdk default, do not
//!     base64 them).
//!  2. **Application envelope:** an app event is `{"eventName","data"}` JSON,
//!     encoded to UTF-8 bytes and carried as the `payload` of a signed BRC-103
//!     *general* message. The event name (e.g. `sendMessage-{room}`, `joinRoom`)
//!     is the `eventName` string — there is NO distinct Socket.IO event per app
//!     event or room.

use serde_json::Value;

/// The one Socket.IO event name carrying all BRC-103 frames, both directions.
pub const AUTH_MESSAGE_EVENT: &str = "authMessage";

/// Encode an application event as the UTF-8 JSON bytes that become a BRC-103
/// general-message payload. Mirrors TS `encodeEventPayload`.
pub fn encode_event(event_name: &str, data: &Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "eventName": event_name,
        "data": data,
    }))
    .unwrap_or_default()
}

/// Decode a BRC-103 general-message payload back into `(eventName, data)`.
/// Returns `None` on invalid UTF-8/JSON or a missing `eventName` (TS yields a
/// `_unknown` sentinel; `None` is the equivalent "no callback will fire").
pub fn decode_event(payload: &[u8]) -> Option<(String, Value)> {
    let v: Value = serde_json::from_slice(payload).ok()?;
    let event_name = v.get("eventName")?.as_str()?.to_string();
    let data = v.get("data").cloned().unwrap_or(Value::Null);
    Some((event_name, data))
}

/// Room id convention: `{identityKey}-{messageBox}`. A live listener joins under
/// its OWN identity key; a sender targets the RECIPIENT's identity key — that
/// asymmetry is what makes delivery rendezvous.
pub fn room_id(identity_key: &str, message_box: &str) -> String {
    format!("{identity_key}-{message_box}")
}

/// 66-hex-char compressed pubkey length, used to split `{key}-{box}` room ids.
pub const IDENTITY_KEY_HEX_LEN: usize = 66;

/// Split a room id back into `(identity_key, message_box)`. Splits after the
/// 66-char hex key (the message box may itself contain hyphens); falls back to
/// the first hyphen if the prefix isn't a 66-char key.
pub fn split_room_id(room_id: &str) -> Option<(String, String)> {
    if room_id.len() > IDENTITY_KEY_HEX_LEN
        && room_id.as_bytes()[IDENTITY_KEY_HEX_LEN] == b'-'
        && room_id[..IDENTITY_KEY_HEX_LEN]
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Some((
            room_id[..IDENTITY_KEY_HEX_LEN].to_string(),
            room_id[IDENTITY_KEY_HEX_LEN + 1..].to_string(),
        ));
    }
    let (k, b) = room_id.split_once('-')?;
    Some((k.to_string(), b.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_round_trips() {
        let data = serde_json::json!({ "roomId": "abc", "n": 7 });
        let bytes = encode_event("sendMessage", &data);
        // Wire form is exactly {"eventName":...,"data":...} UTF-8 JSON.
        let s = String::from_utf8(bytes.clone()).unwrap();
        assert!(s.contains(r#""eventName":"sendMessage""#));
        let (ev, got) = decode_event(&bytes).unwrap();
        assert_eq!(ev, "sendMessage");
        assert_eq!(got, data);
    }

    #[test]
    fn decode_bad_payload_is_none() {
        assert!(decode_event(b"not json").is_none());
        assert!(decode_event(br#"{"data":1}"#).is_none()); // missing eventName
    }

    #[test]
    fn room_id_and_split() {
        let key = "02".to_string() + &"a".repeat(64); // 66 hex chars
        let r = room_id(&key, "payment_inbox");
        assert_eq!(r, format!("{key}-payment_inbox"));
        assert_eq!(
            split_room_id(&r),
            Some((key.clone(), "payment_inbox".to_string()))
        );
        // message box containing a hyphen still splits correctly after the key.
        let r2 = room_id(&key, "inbox-2");
        assert_eq!(split_room_id(&r2), Some((key, "inbox-2".to_string())));
    }
}
