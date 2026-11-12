//! A box's id on this host: how it is minted, and how a log line spells it.
//!
//! The host mints the id when a box is registered, from its own random
//! source and from nothing the guest could observe or arrange. The id names
//! the box in the host's table, in the guest daemon's record, in the
//! delivery header the credential proxy reads, and in the proxy's audit
//! log.

use std::fmt;

/// A box's identity in a delivered connection: 16 opaque bytes.
pub use bep::listener::BoxId;

/// Mints a box's id: one UUIDv7, a millisecond timestamp and 74 random
/// bits from the host's random source. It is never a counter and never a
/// digest of the box's facts, so a box recreated under the same name and
/// addresses is a new box with a new id, and a revocation of the old id
/// never names it. The version and variant bits keep a minted id off the
/// all-zero value, which names no box.
pub fn mint_box_id() -> BoxId {
    mint_record_box_id().to_bytes()
}

/// [`mint_box_id`] as the type a box record is keyed by.
#[must_use]
pub fn mint_record_box_id() -> minimald_rpc::BoxId {
    minimald_rpc::BoxId::mint()
}

/// A box id rendered for a log line only: the hyphenated UUID form, the
/// same spelling `minimald` logs and a reply's id prints
/// ([`minimald_rpc::BoxId`]'s `Display`), so a tail can compare a line
/// from each daemon for the same box. An audit record does not use it: it
/// spells the id as 32 lowercase hex digits, the form
/// `bep::listener::box_id_text` gives every BEP audit `subject`.
pub(crate) struct BoxIdText<'a>(pub(crate) &'a BoxId);

impl fmt::Display for BoxIdText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&minimald_rpc::BoxId::from_bytes(*self.0), f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The minted id is the type a box record is keyed by. Its raw bytes
    /// and its log spelling name the same id.
    #[test]
    fn minted_box_id_is_the_record_key_type() {
        let minted: minimald_rpc::BoxId = mint_record_box_id();
        // The record's key and its handed id are this type: a compile-time
        // check that no conversion stands between the mint and the record.
        let mut record_key: boxes::BoxId = minted;
        let key_of: fn(&boxes::Record) -> boxes::SessionId = |record| record.id;
        let _ = key_of;
        assert!(!record_key.is_nil(), "a mint never names the nil id");
        let uuid: &uuid::Uuid = record_key.as_ref();
        assert_eq!(uuid.get_version_num(), 7, "a minted id is a UUIDv7");

        // The raw mint is the same type's bytes, and reads back as the same id.
        let raw = mint_box_id();
        record_key = minimald_rpc::BoxId::from_bytes(raw);
        assert_eq!(record_key.to_bytes(), raw);
        assert!(
            minted < record_key,
            "a later mint sorts after an earlier one"
        );

        // The log spelling is the record key's own printed spelling.
        assert_eq!(BoxIdText(&raw).to_string(), record_key.to_string());
        assert_eq!(
            minimald_rpc::BoxId::parse_str(&BoxIdText(&raw).to_string()).unwrap(),
            record_key
        );
    }

    /// A minted id has the shape of a UUIDv7, which keeps it off the
    /// all-zero value, and two mints give two ids.
    #[test]
    fn box_id_is_unique_per_creation() {
        let id = mint_box_id();
        assert_eq!(id[6] & 0xf0, 0x70, "a minted id is a version-7 UUID");
        assert_eq!(
            id[8] & 0xc0,
            0x80,
            "a minted id carries the RFC 4122 variant"
        );
        assert_ne!(id, [0u8; 16]);
        assert_ne!(mint_box_id(), mint_box_id(), "two creations name two boxes");
    }
}
