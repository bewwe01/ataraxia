//! Client ↔ relay wire protocol (PROTOCOL §2, §4.2, §6.3, §8, §9, §15).
//!
//! One WebSocket binary message carries exactly one [`ClientFrame`] or [`ServerFrame`],
//! encoded as protobuf. Decoding is **strict**, as in `veil-core`:
//! * the frame size is checked *before* parsing ([`MAX_FRAME`]);
//! * the input must re-encode to exactly the same bytes (rejects unknown fields,
//!   duplicates and non-minimal encodings);
//! * the version must be [`VERSION`];
//! * every field is range-checked ([`ClientFrame::validate`], [`ServerFrame::validate`]).
//!
//! No crypto happens here. Nothing in these types identifies a user: mailbox ids and
//! delivery tokens are random, envelopes are sealed (see `veil-core`).
#![forbid(unsafe_code)]

use prost::Message as _;

/// Current wire version. Frames with any other `v` are refused (PROTOCOL §13).
pub const VERSION: u32 = 1;
/// Largest envelope bucket (PROTOCOL §6.3).
pub const MAX_ENVELOPE: usize = 65_536;
/// Envelope sizes that may appear on the wire.
pub const ENVELOPE_BUCKETS: [usize; 4] = [1024, 4096, 16_384, 65_536];
/// Sealed invite package size (PROTOCOL §4.2).
pub const SEALED_INVITE_LEN: usize = 4136;
/// Blob chunk ciphertext size: 64 KiB of plaintext plus a 16-byte tag (PROTOCOL §9).
pub const MAX_BLOB_CHUNK: usize = 65_536 + 16;
/// Largest blob, in chunks (≈ 100 MiB of padded plaintext).
pub const MAX_BLOB_CHUNKS: u32 = 1600;
/// Maximum envelopes per fetch response.
pub const MAX_FETCH: u32 = 32;
const MAX_FETCH_USIZE: usize = 32;
/// Maximum tokens added or removed per request.
pub const MAX_TOKEN_CHANGES: usize = 64;
/// Maximum *client* frame, checked before decoding: one envelope or blob chunk plus framing.
/// The relay also configures its WebSocket layer with this limit.
pub const MAX_CLIENT_FRAME: usize = MAX_BLOB_CHUNK + 1024;
/// Maximum *relay* frame, checked by clients before decoding: a full fetch response.
pub const MAX_FRAME: usize = MAX_FETCH_USIZE * (MAX_ENVELOPE + 64) + 1024;
const ID32: usize = 32;
const INVITE_ID: usize = 16;
const SIG: usize = 64;
const MAX_URLS: usize = 4;
const MAX_URL: usize = 200;

/// Errors from decoding or validating a frame. Messages carry no input data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("frame too large")]
    TooLarge,
    #[error("malformed frame")]
    Malformed,
    #[error("unsupported wire version")]
    UnsupportedVersion,
}

pub type Result<T> = core::result::Result<T, WireError>;

fn ensure(ok: bool) -> Result<()> {
    if ok { Ok(()) } else { Err(WireError::Malformed) }
}

fn decode_strict<M: prost::Message + Default>(bytes: &[u8], max: usize) -> Result<M> {
    if bytes.len() > max {
        return Err(WireError::TooLarge);
    }
    let msg = M::decode(bytes).map_err(|_| WireError::Malformed)?;
    if msg.encode_to_vec() != bytes {
        return Err(WireError::Malformed);
    }
    Ok(msg)
}

// ---------------------------------------------------------------------------------------
// Client → relay
// ---------------------------------------------------------------------------------------

/// A request from a client. `id` is echoed in the response (0 is reserved for pushes).
#[derive(Clone, PartialEq, prost::Message)]
pub struct ClientFrame {
    #[prost(uint32, tag = "1")]
    pub v: u32,
    #[prost(uint64, tag = "2")]
    pub id: u64,
    #[prost(
        oneof = "Request",
        tags = "10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24"
    )]
    pub req: Option<Request>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Request {
    /// Register a new mailbox with its Ed25519 auth key (§2).
    #[prost(message, tag = "10")]
    CreateMailbox(CreateMailbox),
    /// Ask for a single-use auth challenge for one mailbox.
    #[prost(message, tag = "11")]
    Challenge(MailboxRef),
    /// Answer the challenge; on success the connection may act for that mailbox.
    #[prost(message, tag = "12")]
    Authenticate(Authenticate),
    /// Add/remove delivery-token hashes (auth).
    #[prost(message, tag = "13")]
    UpdateTokens(UpdateTokens),
    /// Deposit an envelope with a delivery token (no auth: the token is the capability).
    #[prost(message, tag = "14")]
    Deposit(Deposit),
    /// Fetch stored envelopes after a sequence number (auth).
    #[prost(message, tag = "15")]
    Fetch(Fetch),
    /// Delete envelopes up to and including a sequence number (auth).
    #[prost(message, tag = "16")]
    Ack(Ack),
    /// Delete a mailbox and everything in it (auth).
    #[prost(message, tag = "17")]
    DeleteMailbox(MailboxRef),
    /// Store a sealed invite package (auth on any mailbox, for rate limiting only).
    #[prost(message, tag = "18")]
    PutInvite(PutInvite),
    /// Fetch an invite package; the relay deletes it on first successful take (INV-PAIR-2).
    #[prost(message, tag = "19")]
    TakeInvite(TakeInvite),
    /// Get a one-time upload capability for one blob (auth).
    #[prost(message, tag = "20")]
    BlobUploadToken(MailboxRef),
    /// Upload one chunk of a blob.
    #[prost(message, tag = "21")]
    BlobPut(BlobPut),
    /// Download one chunk of a complete blob.
    #[prost(message, tag = "22")]
    BlobGet(BlobGet),
    /// Get short-lived TURN credentials (auth, §8).
    #[prost(message, tag = "23")]
    TurnCredentials(MailboxRef),
    /// Liveness check.
    #[prost(message, tag = "24")]
    Ping(Empty),
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Empty {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MailboxRef {
    #[prost(bytes = "vec", tag = "1")]
    pub mailbox_id: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CreateMailbox {
    #[prost(bytes = "vec", tag = "1")]
    pub mailbox_id: Vec<u8>,
    /// Ed25519 public key (32 bytes), separate from the identity key.
    #[prost(bytes = "vec", tag = "2")]
    pub auth_pub: Vec<u8>,
}

/// Signature over `"veil/v1/mbox-auth" || relay_spki_sha256 || mailbox_id || nonce || unix_secs (u64 BE)`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Authenticate {
    #[prost(bytes = "vec", tag = "1")]
    pub mailbox_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub unix_secs: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub signature: Vec<u8>,
}

/// The exact bytes a mailbox owner signs to authenticate (PROTOCOL §2).
pub fn auth_message(
    relay_spki_sha256: &[u8; 32],
    mailbox_id: &[u8],
    nonce: &[u8],
    unix_secs: u64,
) -> Vec<u8> {
    const LABEL: &[u8] = b"veil/v1/mbox-auth";
    let mut m = Vec::with_capacity(LABEL.len().saturating_add(32 + ID32 + ID32 + 8));
    m.extend_from_slice(LABEL);
    m.extend_from_slice(relay_spki_sha256);
    m.extend_from_slice(mailbox_id);
    m.extend_from_slice(nonce);
    m.extend_from_slice(&unix_secs.to_be_bytes());
    m
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct UpdateTokens {
    #[prost(bytes = "vec", tag = "1")]
    pub mailbox_id: Vec<u8>,
    /// `SHA-256("veil/v1/tok" || token)` values to add.
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub add: Vec<Vec<u8>>,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub remove: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Deposit {
    #[prost(bytes = "vec", tag = "1")]
    pub mailbox_id: Vec<u8>,
    /// The raw delivery token; the relay hashes it and checks membership.
    #[prost(bytes = "vec", tag = "2")]
    pub token: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub envelope: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Fetch {
    #[prost(bytes = "vec", tag = "1")]
    pub mailbox_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub after_seq: u64,
    #[prost(uint32, tag = "3")]
    pub limit: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Ack {
    #[prost(bytes = "vec", tag = "1")]
    pub mailbox_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub up_to_seq: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PutInvite {
    /// An authenticated mailbox on this connection (rate limiting only; not stored).
    #[prost(bytes = "vec", tag = "1")]
    pub mailbox_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub invite_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub sealed: Vec<u8>,
    /// Unix seconds; the relay caps it at its own maximum TTL.
    #[prost(uint64, tag = "4")]
    pub expires_at: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct TakeInvite {
    #[prost(bytes = "vec", tag = "1")]
    pub invite_id: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct BlobPut {
    #[prost(bytes = "vec", tag = "1")]
    pub upload_token: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub blob_id: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub chunk_index: u32,
    #[prost(uint32, tag = "4")]
    pub total_chunks: u32,
    #[prost(bytes = "vec", tag = "5")]
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct BlobGet {
    #[prost(bytes = "vec", tag = "1")]
    pub blob_id: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub chunk_index: u32,
}

impl ClientFrame {
    /// Strictly decodes and validates a client frame.
    pub fn decode_strict(bytes: &[u8]) -> Result<Self> {
        let f: Self = decode_strict(bytes, MAX_CLIENT_FRAME)?;
        f.validate()?;
        Ok(f)
    }

    pub fn encode(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Version and field ranges. Called on decode, and by senders before encoding.
    pub fn validate(&self) -> Result<()> {
        if self.v != VERSION {
            return Err(WireError::UnsupportedVersion);
        }
        ensure(self.id != 0)?;
        let id32 = |b: &[u8]| ensure(b.len() == ID32);
        match self.req.as_ref().ok_or(WireError::Malformed)? {
            Request::CreateMailbox(c) => {
                id32(&c.mailbox_id)?;
                id32(&c.auth_pub)
            }
            Request::Challenge(m)
            | Request::DeleteMailbox(m)
            | Request::BlobUploadToken(m)
            | Request::TurnCredentials(m) => id32(&m.mailbox_id),
            Request::Authenticate(a) => {
                id32(&a.mailbox_id)?;
                ensure(a.signature.len() == SIG)
            }
            Request::UpdateTokens(u) => {
                id32(&u.mailbox_id)?;
                ensure(u.add.len().saturating_add(u.remove.len()) <= MAX_TOKEN_CHANGES)?;
                ensure(u.add.iter().chain(&u.remove).all(|t| t.len() == ID32))
            }
            Request::Deposit(d) => {
                id32(&d.mailbox_id)?;
                id32(&d.token)?;
                ensure(ENVELOPE_BUCKETS.contains(&d.envelope.len()))
            }
            Request::Fetch(f) => {
                id32(&f.mailbox_id)?;
                ensure((1..=MAX_FETCH).contains(&f.limit))
            }
            Request::Ack(a) => id32(&a.mailbox_id),
            Request::PutInvite(p) => {
                id32(&p.mailbox_id)?;
                ensure(p.invite_id.len() == INVITE_ID)?;
                ensure(p.sealed.len() == SEALED_INVITE_LEN)
            }
            Request::TakeInvite(t) => ensure(t.invite_id.len() == INVITE_ID),
            Request::BlobPut(b) => {
                id32(&b.upload_token)?;
                id32(&b.blob_id)?;
                ensure((1..=MAX_BLOB_CHUNKS).contains(&b.total_chunks))?;
                ensure(b.chunk_index < b.total_chunks)?;
                ensure(!b.data.is_empty() && b.data.len() <= MAX_BLOB_CHUNK)
            }
            Request::BlobGet(b) => {
                id32(&b.blob_id)?;
                ensure(b.chunk_index < MAX_BLOB_CHUNKS)
            }
            Request::Ping(_) => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Relay → client
// ---------------------------------------------------------------------------------------

/// A response (`id` = the request's id) or a push (`id` = 0).
#[derive(Clone, PartialEq, prost::Message)]
pub struct ServerFrame {
    #[prost(uint32, tag = "1")]
    pub v: u32,
    #[prost(uint64, tag = "2")]
    pub id: u64,
    #[prost(oneof = "Response", tags = "10, 11, 12, 13, 14, 15, 16, 17, 18")]
    pub resp: Option<Response>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Response {
    /// Generic success.
    #[prost(message, tag = "10")]
    Ok(Empty),
    #[prost(message, tag = "11")]
    Error(ErrorResponse),
    #[prost(message, tag = "12")]
    Challenge(ChallengeResponse),
    #[prost(message, tag = "13")]
    Envelopes(Envelopes),
    #[prost(message, tag = "14")]
    Invite(InviteResponse),
    #[prost(message, tag = "15")]
    UploadToken(UploadTokenResponse),
    #[prost(message, tag = "16")]
    BlobChunk(BlobChunk),
    #[prost(message, tag = "17")]
    Turn(TurnResponse),
    /// Push (`id` = 0): new envelopes are waiting in an authenticated mailbox.
    #[prost(message, tag = "18")]
    NewEnvelopes(NewEnvelopes),
}

/// Error codes. Deliberately coarse: they never echo input or say *why* auth failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum ErrorCode {
    Unspecified = 0,
    Malformed = 1,
    Unauthorized = 2,
    NotFound = 3,
    RateLimited = 4,
    QuotaExceeded = 5,
    Conflict = 6,
    Unsupported = 7,
    Internal = 8,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ErrorResponse {
    #[prost(enumeration = "ErrorCode", tag = "1")]
    pub code: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ChallengeResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub nonce: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct StoredEnvelope {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    /// Receipt time rounded down to the minute (unix seconds).
    #[prost(uint64, tag = "2")]
    pub received_minute: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub envelope: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Envelopes {
    #[prost(message, repeated, tag = "1")]
    pub items: Vec<StoredEnvelope>,
    /// Highest sequence number ever assigned in this mailbox (lets the owner detect gaps, §11).
    #[prost(uint64, tag = "2")]
    pub last_seq: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct InviteResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub sealed: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct UploadTokenResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub upload_token: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct BlobChunk {
    #[prost(uint32, tag = "1")]
    pub total_chunks: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub data: Vec<u8>,
}

/// coturn `use-auth-secret` credentials (PROTOCOL §8).
#[derive(Clone, PartialEq, prost::Message)]
pub struct TurnResponse {
    #[prost(string, tag = "1")]
    pub username: String,
    #[prost(string, tag = "2")]
    pub credential: String,
    #[prost(uint32, tag = "3")]
    pub ttl_secs: u32,
    #[prost(string, repeated, tag = "4")]
    pub urls: Vec<String>,
    /// The IP literals the TURN server relays media on (coturn's `external-ip`), at most 4.
    /// Clients reached through another address (a Funnel name) need them to accept relay
    /// candidates there (ADR-0018). Empty when the operator did not set them.
    #[prost(string, repeated, tag = "5")]
    pub relay_ips: Vec<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct NewEnvelopes {
    #[prost(bytes = "vec", tag = "1")]
    pub mailbox_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub last_seq: u64,
}

impl ServerFrame {
    /// Strictly decodes and validates a relay frame. Clients MUST use this: the relay is
    /// hostile (CLAUDE.md non-negotiable 3).
    pub fn decode_strict(bytes: &[u8]) -> Result<Self> {
        let f: Self = decode_strict(bytes, MAX_FRAME)?;
        f.validate()?;
        Ok(f)
    }

    pub fn encode(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    pub fn validate(&self) -> Result<()> {
        if self.v != VERSION {
            return Err(WireError::UnsupportedVersion);
        }
        match self.resp.as_ref().ok_or(WireError::Malformed)? {
            Response::Ok(_) => Ok(()),
            Response::Error(e) => ensure(ErrorCode::try_from(e.code).is_ok()),
            Response::Challenge(c) => ensure(c.nonce.len() == ID32),
            Response::Envelopes(e) => {
                ensure(e.items.len() <= MAX_FETCH_USIZE)?;
                ensure(
                    e.items
                        .iter()
                        .all(|i| ENVELOPE_BUCKETS.contains(&i.envelope.len()) && i.seq <= e.last_seq),
                )
            }
            Response::Invite(i) => ensure(i.sealed.len() == SEALED_INVITE_LEN),
            Response::UploadToken(u) => ensure(u.upload_token.len() == ID32),
            Response::BlobChunk(b) => {
                ensure((1..=MAX_BLOB_CHUNKS).contains(&b.total_chunks))?;
                ensure(!b.data.is_empty() && b.data.len() <= MAX_BLOB_CHUNK)
            }
            Response::Turn(t) => {
                ensure(t.username.len() <= 64 && t.credential.len() <= 64)?;
                ensure(!t.urls.is_empty() && t.urls.len() <= MAX_URLS)?;
                ensure(t.urls.iter().all(|u| {
                    u.len() <= MAX_URL && (u.starts_with("turn:") || u.starts_with("turns:")) && u.is_ascii()
                }))?;
                ensure(t.relay_ips.len() <= MAX_URLS)?;
                ensure(
                    t.relay_ips
                        .iter()
                        .all(|ip| ip.len() <= 45 && ip.parse::<core::net::IpAddr>().is_ok()),
                )
            }
            Response::NewEnvelopes(n) => {
                ensure(self.id == 0)?;
                ensure(n.mailbox_id.len() == ID32)
            }
        }
    }

    pub fn ok(id: u64) -> Self {
        Self {
            v: VERSION,
            id,
            resp: Some(Response::Ok(Empty {})),
        }
    }

    pub fn error(id: u64, code: ErrorCode) -> Self {
        Self {
            v: VERSION,
            id,
            resp: Some(Response::Error(ErrorResponse { code: code.into() })),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn frame(req: Request) -> ClientFrame {
        ClientFrame {
            v: VERSION,
            id: 7,
            req: Some(req),
        }
    }

    #[test]
    fn roundtrip_and_validation() {
        let good = [
            frame(Request::CreateMailbox(CreateMailbox {
                mailbox_id: vec![1; 32],
                auth_pub: vec![2; 32],
            })),
            frame(Request::Deposit(Deposit {
                mailbox_id: vec![1; 32],
                token: vec![3; 32],
                envelope: vec![0; 4096],
            })),
            frame(Request::Fetch(Fetch {
                mailbox_id: vec![1; 32],
                after_seq: 0,
                limit: MAX_FETCH,
            })),
            frame(Request::PutInvite(PutInvite {
                mailbox_id: vec![1; 32],
                invite_id: vec![4; 16],
                sealed: vec![5; SEALED_INVITE_LEN],
                expires_at: 1,
            })),
            frame(Request::BlobPut(BlobPut {
                upload_token: vec![6; 32],
                blob_id: vec![7; 32],
                chunk_index: 0,
                total_chunks: 1,
                data: vec![8; MAX_BLOB_CHUNK],
            })),
            frame(Request::Ping(Empty {})),
        ];
        for f in good {
            let bytes = f.encode();
            assert_eq!(ClientFrame::decode_strict(&bytes).unwrap(), f);
        }
        let bad = [
            frame(Request::Deposit(Deposit {
                mailbox_id: vec![1; 32],
                token: vec![3; 32],
                envelope: vec![0; 4095],
            })),
            frame(Request::Deposit(Deposit {
                mailbox_id: vec![1; 31],
                token: vec![3; 32],
                envelope: vec![0; 1024],
            })),
            frame(Request::Fetch(Fetch {
                mailbox_id: vec![1; 32],
                after_seq: 0,
                limit: 0,
            })),
            frame(Request::Fetch(Fetch {
                mailbox_id: vec![1; 32],
                after_seq: 0,
                limit: MAX_FETCH + 1,
            })),
            frame(Request::Authenticate(Authenticate {
                mailbox_id: vec![1; 32],
                unix_secs: 1,
                signature: vec![0; 63],
            })),
            frame(Request::UpdateTokens(UpdateTokens {
                mailbox_id: vec![1; 32],
                add: vec![vec![0; 32]; MAX_TOKEN_CHANGES + 1],
                remove: vec![],
            })),
            frame(Request::BlobPut(BlobPut {
                upload_token: vec![6; 32],
                blob_id: vec![7; 32],
                chunk_index: 1,
                total_chunks: 1,
                data: vec![8; 10],
            })),
            ClientFrame {
                v: VERSION,
                id: 7,
                req: None,
            },
            ClientFrame {
                v: VERSION,
                id: 0,
                req: Some(Request::Ping(Empty {})),
            },
        ];
        for f in bad {
            assert!(ClientFrame::decode_strict(&f.encode()).is_err());
        }
        let v2 = ClientFrame {
            v: 2,
            id: 1,
            req: Some(Request::Ping(Empty {})),
        };
        assert_eq!(
            ClientFrame::decode_strict(&v2.encode()),
            Err(WireError::UnsupportedVersion)
        );
    }

    #[test]
    fn strict_decoding_rejects_unknown_and_trailing_fields() {
        let mut bytes = frame(Request::Ping(Empty {})).encode();
        bytes.extend_from_slice(&[0xF8, 0x01, 0x01]); // unknown field 31, varint 1
        assert_eq!(ClientFrame::decode_strict(&bytes), Err(WireError::Malformed));
        assert_eq!(
            ClientFrame::decode_strict(&vec![0; MAX_CLIENT_FRAME + 1]),
            Err(WireError::TooLarge)
        );
        assert_eq!(
            ServerFrame::decode_strict(&vec![0; MAX_FRAME + 1]),
            Err(WireError::TooLarge)
        );
    }

    #[test]
    fn server_frames_are_validated_too() {
        let push = ServerFrame {
            v: VERSION,
            id: 0,
            resp: Some(Response::NewEnvelopes(NewEnvelopes {
                mailbox_id: vec![1; 32],
                last_seq: 3,
            })),
        };
        assert!(ServerFrame::decode_strict(&push.encode()).is_ok());
        let bad_push = ServerFrame { id: 9, ..push };
        assert!(ServerFrame::decode_strict(&bad_push.encode()).is_err());
        let bad_env = ServerFrame {
            v: VERSION,
            id: 1,
            resp: Some(Response::Envelopes(Envelopes {
                items: vec![StoredEnvelope {
                    seq: 5,
                    received_minute: 0,
                    envelope: vec![0; 1024],
                }],
                last_seq: 4,
            })),
        };
        assert!(
            ServerFrame::decode_strict(&bad_env.encode()).is_err(),
            "seq beyond last_seq"
        );
        let bad_turn = ServerFrame {
            v: VERSION,
            id: 1,
            resp: Some(Response::Turn(TurnResponse {
                username: "1:ab".into(),
                credential: "x".into(),
                ttl_secs: 3600,
                urls: vec!["http://evil".into()],
                relay_ips: vec![],
            })),
        };
        assert!(ServerFrame::decode_strict(&bad_turn.encode()).is_err());
        let turn = |relay_ips: &[&str]| ServerFrame {
            v: VERSION,
            id: 1,
            resp: Some(Response::Turn(TurnResponse {
                username: "1:ab".into(),
                credential: "x".into(),
                ttl_secs: 3600,
                urls: vec!["turn:relay.example.org:3478".into()],
                relay_ips: relay_ips.iter().map(|s| (*s).to_owned()).collect(),
            })),
        };
        assert!(ServerFrame::decode_strict(&turn(&[]).encode()).is_ok());
        assert!(ServerFrame::decode_strict(&turn(&["100.101.102.103", "fd00::1"]).encode()).is_ok());
        for bad in [
            &["pi.example.ts.net"][..],
            &["100.1"],
            &["1.1.1.1"; 5],
            &["1.1.1.1/10.0.0.1"],
        ] {
            assert!(
                ServerFrame::decode_strict(&turn(bad).encode()).is_err(),
                "{bad:?}"
            );
        }
        assert!(ServerFrame::decode_strict(&ServerFrame::error(1, ErrorCode::NotFound).encode()).is_ok());
        let unknown_code = ServerFrame {
            v: VERSION,
            id: 1,
            resp: Some(Response::Error(ErrorResponse { code: 99 })),
        };
        assert!(ServerFrame::decode_strict(&unknown_code.encode()).is_err());
    }

    #[test]
    fn auth_message_layout() {
        let m = auth_message(&[0xAA; 32], &[0xBB; 32], &[0xCC; 32], 0x0102_0304_0506_0708);
        assert_eq!(&m[..17], b"veil/v1/mbox-auth");
        assert_eq!(m.len(), 17 + 32 + 32 + 32 + 8);
        assert_eq!(&m[m.len() - 8..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = ClientFrame::decode_strict(&data);
            let _ = ServerFrame::decode_strict(&data);
        }
    }
}
