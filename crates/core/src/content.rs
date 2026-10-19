//! Message content carried inside sealed envelopes (PROTOCOL §7).
//!
//! Encoded with protobuf (`prost`). Decoding is **canonical-only**: the input must
//! re-encode to exactly the same bytes, which rejects unknown fields, duplicate
//! fields and non-minimal encodings. Every field is then range-checked by
//! [`Content::validate`] before the message is handed to the app.

use prost::Message as _;

use crate::error::{CoreError, Result};

/// Maximum encoded `Content` size (before block padding).
pub const MAX_CONTENT_LEN: usize = 65_536 - 1024;
/// Maximum text body length in bytes. Chosen so that the largest valid `Text` or `Edit`
/// still seals into the 64 KiB bucket while the session is in its `PreKey` phase, which
/// carries ~1.6 KiB of ML-KEM ciphertext (review round 2, N7: 63 488 did not fit).
pub const MAX_BODY_LEN: usize = 61 * 1024;
const ID_LEN: usize = 16;
const MAX_IDS: usize = 256;
const MAX_SDP_LEN: usize = 16 * 1024;
const MAX_CANDIDATES: usize = 64;
const MAX_CANDIDATE_LEN: usize = 512;
const MAX_NAME_CHARS: usize = 64;
const MAX_MIME_LEN: usize = 127;
const MAX_FILE_NAME_CHARS: usize = 255;
const MAX_THUMBNAIL: usize = 8 * 1024;
const MAX_WAVEFORM: usize = 256;
const MAX_EMOJI_BYTES: usize = 32;
const MAX_EMOJI_CHARS: usize = 8;
const MAX_REKEY_LINK: usize = 512;
const MAX_REKEY_SEALED: usize = 8 * 1024;
const MAX_RELAY_URL: usize = 200;
const MAX_TIMER_SECS: u32 = 4 * 7 * 24 * 3600;

/// Top-level message.
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct Content {
    /// Random 16-byte message id (idempotency key).
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
    /// Sender's clock, milliseconds. Display only; never trusted for security.
    #[prost(uint64, tag = "2")]
    pub sent_at_ms: u64,
    #[prost(oneof = "Body", tags = "10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21")]
    pub body: Option<Body>,
}

/// Content variants.
#[derive(Clone, PartialEq, prost::Oneof)]
#[prost(skip_debug)]
pub enum Body {
    #[prost(message, tag = "10")]
    Text(Text),
    #[prost(message, tag = "11")]
    Reaction(Reaction),
    #[prost(message, tag = "12")]
    Edit(Edit),
    #[prost(message, tag = "13")]
    Delete(Delete),
    #[prost(message, tag = "14")]
    Attachment(Attachment),
    #[prost(message, tag = "15")]
    Receipt(Receipt),
    #[prost(message, tag = "16")]
    Typing(Typing),
    #[prost(message, tag = "17")]
    TimerUpdate(TimerUpdate),
    #[prost(message, tag = "18")]
    Call(Call),
    #[prost(message, tag = "19")]
    ContactIntro(ContactIntro),
    #[prost(message, tag = "20")]
    MailboxUpdate(MailboxUpdate),
    #[prost(message, tag = "21")]
    SessionReset(SessionReset),
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct Text {
    #[prost(string, tag = "1")]
    pub body: String,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub reply_to: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "3")]
    pub expire_timer_secs: Option<u32>,
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct Reaction {
    #[prost(bytes = "vec", tag = "1")]
    pub target_id: Vec<u8>,
    #[prost(string, tag = "2")]
    pub emoji: String,
    #[prost(bool, tag = "3")]
    pub remove: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct Edit {
    #[prost(bytes = "vec", tag = "1")]
    pub target_id: Vec<u8>,
    #[prost(string, tag = "2")]
    pub body: String,
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct Delete {
    #[prost(bytes = "vec", tag = "1")]
    pub target_id: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct Attachment {
    #[prost(bytes = "vec", tag = "1")]
    pub blob_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub key: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub nonce_prefix: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub ciphertext_sha256: Vec<u8>,
    #[prost(uint64, tag = "5")]
    pub size: u64,
    #[prost(uint64, tag = "6")]
    pub padded_size: u64,
    #[prost(string, tag = "7")]
    pub mime: String,
    #[prost(string, optional, tag = "8")]
    pub file_name: Option<String>,
    #[prost(bytes = "vec", optional, tag = "9")]
    pub thumbnail: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "10")]
    pub voice_duration_ms: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "11")]
    pub waveform: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "12")]
    pub expire_timer_secs: Option<u32>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, prost::Enumeration)]
#[repr(i32)]
pub enum ReceiptKind {
    Unspecified = 0,
    Delivered = 1,
    Read = 2,
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct Receipt {
    #[prost(enumeration = "ReceiptKind", tag = "1")]
    pub kind: i32,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub ids: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct Typing {
    #[prost(bool, tag = "1")]
    pub started: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct TimerUpdate {
    #[prost(uint32, tag = "1")]
    pub seconds: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct Call {
    #[prost(bytes = "vec", tag = "1")]
    pub call_id: Vec<u8>,
    #[prost(oneof = "CallKind", tags = "10, 11, 12, 13, 14")]
    pub kind: Option<CallKind>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
#[prost(skip_debug)]
pub enum CallKind {
    #[prost(string, tag = "10")]
    Offer(String),
    #[prost(string, tag = "11")]
    Answer(String),
    #[prost(message, tag = "12")]
    Ice(IceCandidates),
    #[prost(string, tag = "13")]
    Hangup(String),
    #[prost(bool, tag = "14")]
    Busy(bool),
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct IceCandidates {
    #[prost(string, repeated, tag = "1")]
    pub candidates: Vec<String>,
}

/// First message of a new contact (PROTOCOL §4.3), and the reply.
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct ContactIntro {
    #[prost(bytes = "vec", tag = "1")]
    pub mailbox_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub delivery_token: Vec<u8>,
    #[prost(string, optional, tag = "3")]
    pub display_name: Option<String>,
    /// Present when this intro redeems an invite.
    #[prost(bytes = "vec", optional, tag = "4")]
    pub invite_id: Option<Vec<u8>>,
    /// HMAC proving knowledge of the invite secret, bound to the sender's identity key.
    #[prost(bytes = "vec", optional, tag = "5")]
    pub invite_proof: Option<Vec<u8>>,
    /// A standing invite the recipient keeps for re-keying after a restore (PROTOCOL §3).
    #[prost(message, optional, tag = "6")]
    pub rekey: Option<RekeyInvite>,
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct RekeyInvite {
    #[prost(string, tag = "1")]
    pub link: String,
    #[prost(bytes = "vec", tag = "2")]
    pub sealed_package: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct MailboxUpdate {
    #[prost(bytes = "vec", tag = "1")]
    pub new_mailbox_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub new_delivery_token: Vec<u8>,
    #[prost(string, optional, tag = "3")]
    pub relay_url: Option<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct SessionReset {}

impl Content {
    /// Encodes to protobuf bytes.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Strict decode: size limit first, canonical form only, then field validation.
    pub fn decode_strict(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CONTENT_LEN {
            return Err(CoreError::TooLarge);
        }
        let msg = <Self as prost::Message>::decode(bytes).map_err(|_| CoreError::Malformed)?;
        if msg.encode_to_vec() != bytes {
            return Err(CoreError::Malformed);
        }
        msg.validate()?;
        Ok(msg)
    }

    /// Range-checks every field (INV-MSG-5). Called on decode and before encode by the session layer.
    pub fn validate(&self) -> Result<()> {
        ensure(self.id.len() == ID_LEN)?;
        match self.body.as_ref().ok_or(CoreError::Malformed)? {
            Body::Text(t) => {
                ensure(t.body.len() <= MAX_BODY_LEN)?;
                opt(t.reply_to.as_ref(), |r| r.len() == ID_LEN)?;
                opt(t.expire_timer_secs.as_ref(), |s| *s <= MAX_TIMER_SECS)
            }
            Body::Reaction(r) => {
                ensure(r.target_id.len() == ID_LEN)?;
                ensure(!r.emoji.is_empty() && r.emoji.len() <= MAX_EMOJI_BYTES)?;
                ensure(r.emoji.chars().count() <= MAX_EMOJI_CHARS && !has_control(&r.emoji))
            }
            Body::Edit(e) => {
                ensure(e.target_id.len() == ID_LEN)?;
                ensure(e.body.len() <= MAX_BODY_LEN)
            }
            Body::Delete(d) => ensure(d.target_id.len() == ID_LEN),
            Body::Attachment(a) => {
                ensure(a.blob_id.len() == 32 && a.key.len() == 32 && a.nonce_prefix.len() == 19)?;
                ensure(a.ciphertext_sha256.len() == 32)?;
                ensure(a.size <= a.padded_size && a.padded_size <= crate::attachment::MAX_ATTACHMENT_PADDED)?;
                ensure(!a.mime.is_empty() && a.mime.len() <= MAX_MIME_LEN && a.mime.is_ascii())?;
                ensure(!has_control(&a.mime))?;
                opt(a.file_name.as_ref(), |n| {
                    !n.is_empty() && n.chars().count() <= MAX_FILE_NAME_CHARS && !has_control(n)
                })?;
                opt(a.thumbnail.as_ref(), |t| t.len() <= MAX_THUMBNAIL)?;
                opt(a.waveform.as_ref(), |w| w.len() <= MAX_WAVEFORM)?;
                opt(a.expire_timer_secs.as_ref(), |s| *s <= MAX_TIMER_SECS)
            }
            Body::Receipt(r) => {
                ensure(matches!(
                    ReceiptKind::try_from(r.kind),
                    Ok(ReceiptKind::Delivered | ReceiptKind::Read)
                ))?;
                ensure(!r.ids.is_empty() && r.ids.len() <= MAX_IDS)?;
                ensure(r.ids.iter().all(|i| i.len() == ID_LEN))
            }
            Body::Typing(_) | Body::SessionReset(_) => Ok(()),
            Body::TimerUpdate(t) => ensure(t.seconds <= MAX_TIMER_SECS),
            Body::Call(c) => {
                ensure(c.call_id.len() == ID_LEN)?;
                match c.kind.as_ref().ok_or(CoreError::Malformed)? {
                    CallKind::Offer(s) | CallKind::Answer(s) => {
                        ensure(!s.is_empty() && s.len() <= MAX_SDP_LEN)
                    }
                    CallKind::Ice(i) => {
                        ensure(!i.candidates.is_empty() && i.candidates.len() <= MAX_CANDIDATES)?;
                        ensure(
                            i.candidates
                                .iter()
                                .all(|c| c.len() <= MAX_CANDIDATE_LEN && !has_control(c)),
                        )
                    }
                    CallKind::Hangup(r) => ensure(r.len() <= 64 && !has_control(r)),
                    CallKind::Busy(_) => Ok(()),
                }
            }
            Body::ContactIntro(i) => {
                ensure(i.mailbox_id.len() == 32 && i.delivery_token.len() == 32)?;
                opt(i.display_name.as_ref(), |n| {
                    !n.is_empty() && n.chars().count() <= MAX_NAME_CHARS && !has_control(n)
                })?;
                ensure(i.invite_id.is_some() == i.invite_proof.is_some())?;
                opt(i.invite_id.as_ref(), |v| v.len() == 16)?;
                opt(i.invite_proof.as_ref(), |v| v.len() == 32)?;
                opt(i.rekey.as_ref(), |r| {
                    r.link.len() <= MAX_REKEY_LINK && r.sealed_package.len() <= MAX_REKEY_SEALED
                })
            }
            Body::MailboxUpdate(m) => {
                ensure(m.new_mailbox_id.len() == 32 && m.new_delivery_token.len() == 32)?;
                opt(m.relay_url.as_ref(), |u| {
                    u.len() <= MAX_RELAY_URL && u.starts_with("wss://") && u.is_ascii() && !has_control(u)
                })
            }
        }
    }
}

fn ensure(cond: bool) -> Result<()> {
    if cond { Ok(()) } else { Err(CoreError::Malformed) }
}

fn opt<T>(v: Option<&T>, f: impl FnOnce(&T) -> bool) -> Result<()> {
    ensure(v.is_none_or(f))
}

/// Control characters (incl. bidi overrides) are rejected in short UI strings to
/// prevent spoofing; message bodies may contain newlines and are rendered as plain text.
fn has_control(s: &str) -> bool {
    s.chars().any(|c| {
        c.is_control()
            || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}')
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use proptest::prelude::*;

    pub(crate) fn text(body: &str) -> Content {
        Content {
            id: vec![7; 16],
            sent_at_ms: 1,
            body: Some(Body::Text(Text {
                body: body.into(),
                ..Default::default()
            })),
        }
    }

    #[test]
    fn roundtrip_text() {
        let c = text("hello");
        assert_eq!(Content::decode_strict(&c.encode()).ok(), Some(c));
    }

    #[test]
    fn rejects_unknown_fields_and_noncanonical() {
        let mut bytes = text("hello").encode();
        // Append an unknown field (tag 99, varint 1): decodes in prost but is not canonical.
        bytes.extend_from_slice(&[0x98, 0x06, 0x01]);
        assert_eq!(Content::decode_strict(&bytes), Err(CoreError::Malformed));
        // Duplicate scalar field (sent_at twice): last-wins in protobuf, rejected here.
        let mut dup = text("x").encode();
        dup.extend_from_slice(&[0x10, 0x05]);
        assert_eq!(Content::decode_strict(&dup), Err(CoreError::Malformed));
    }

    #[test]
    fn validation_rules() {
        let mut c = text("x");
        c.id = vec![1; 15];
        assert_eq!(c.validate(), Err(CoreError::Malformed));
        let c = Content {
            id: vec![1; 16],
            sent_at_ms: 0,
            body: None,
        };
        assert_eq!(c.validate(), Err(CoreError::Malformed));
        let c = Content {
            id: vec![1; 16],
            sent_at_ms: 0,
            body: Some(Body::Reaction(Reaction {
                target_id: vec![2; 16],
                emoji: "\u{202E}x".into(),
                remove: false,
            })),
        };
        assert_eq!(c.validate(), Err(CoreError::Malformed), "bidi override rejected");
        let c = Content {
            id: vec![1; 16],
            sent_at_ms: 0,
            body: Some(Body::ContactIntro(ContactIntro {
                mailbox_id: vec![0; 32],
                delivery_token: vec![0; 32],
                display_name: None,
                invite_id: Some(vec![0; 16]),
                invite_proof: None,
                rekey: None,
            })),
        };
        assert_eq!(c.validate(), Err(CoreError::Malformed), "invite id without proof");
    }

    #[test]
    fn size_limit_checked_before_parsing() {
        assert_eq!(
            Content::decode_strict(&vec![0u8; MAX_CONTENT_LEN + 1]),
            Err(CoreError::TooLarge)
        );
    }

    proptest! {
        #[test]
        fn text_roundtrip(body in ".{0,500}", sent in any::<u64>(), id in proptest::collection::vec(any::<u8>(), 16)) {
            let c = Content { id, sent_at_ms: sent, body: Some(Body::Text(Text { body, ..Default::default() })) };
            prop_assert_eq!(Content::decode_strict(&c.encode()).ok(), Some(c));
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = Content::decode_strict(&bytes);
        }
    }
}

// Review round 2, N5: secrets that arrive in decoded content (attachment keys, mailbox
// capabilities, invite proofs, re-key links that embed an invite secret) are wiped when the
// value is dropped. (`Drop` means these types cannot be built with `..Default::default()`.)
impl Drop for Attachment {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
        zeroize::Zeroize::zeroize(&mut self.nonce_prefix);
    }
}

impl Drop for ContactIntro {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.mailbox_id);
        zeroize::Zeroize::zeroize(&mut self.delivery_token);
        zeroize::Zeroize::zeroize(&mut self.invite_id);
        zeroize::Zeroize::zeroize(&mut self.invite_proof);
    }
}

impl Drop for RekeyInvite {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.link);
        zeroize::Zeroize::zeroize(&mut self.sealed_package);
    }
}

impl Drop for MailboxUpdate {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.new_mailbox_id);
        zeroize::Zeroize::zeroize(&mut self.new_delivery_token);
    }
}

crate::redacted_debug!(
    Content,
    Body,
    Text,
    Reaction,
    Edit,
    Delete,
    Attachment,
    Receipt,
    Typing,
    TimerUpdate,
    Call,
    CallKind,
    IceCandidates,
    ContactIntro,
    RekeyInvite,
    MailboxUpdate,
    SessionReset
);
