//! The session API (PROTOCOL §4–§7): create and redeem invites, seal and open envelopes.
//!
//! Every operation that touches protocol state runs in a store transaction that is
//! committed only on complete success. Rejected, forged, replayed or malformed input
//! therefore never changes state.

use core::cell::RefCell;
use std::time::{Duration, SystemTime};

use libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, ContentHint, DeviceId, GenericSignedPreKey as _, IdentityKey,
    IdentityKeyPair, IdentityKeyStore as _, KeyPair, KyberPreKeyRecord, KyberPreKeyStore as _, PreKeyBundle,
    PreKeyRecord, PreKeySignalMessage, PreKeyStore as _, ProtocolAddress, PublicKey, SenderCertificate,
    ServerCertificate, SignalMessage, SignedPreKeyRecord, SignedPreKeyStore as _, Timestamp,
    UnidentifiedSenderMessageContent, kem, message_decrypt, message_encrypt, process_prekey_bundle,
    sealed_sender_decrypt_to_usmc, sealed_sender_encrypt_from_usmc,
};
use prost::Message as _;
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

use crate::content::{Body, ContactIntro, Content, RekeyInvite};
use crate::envelope;
use crate::error::{CoreError, Result};
use crate::identity::{Address, Identity};
use crate::invite::{Invite, InviteMode, MAX_TTL_SECS, PackagePb, verify_proof};
use crate::padding::{pad_block, unpad_block};
use crate::safety::SafetyNumber;
use crate::store::{KvBackend, StoreHandle, VeilStore, keys};

/// libsignal message version that includes PQXDH/Kyber; anything lower is a downgrade (INV-CRY-3).
pub const MIN_MESSAGE_VERSION: u8 = 4;
/// Sender certificates outlive relay storage (14 days) with margin for clock skew.
const CERT_LIFETIME_SECS: u64 = 30 * 24 * 3600;
const SERVER_CERT_KEY_ID: u32 = 1;
/// First byte of every sealed-sender v1 message (version 1 in both nibbles).
const SEALED_SENDER_V1: u8 = 0x11;
const DEVICE: u8 = 1;

/// Fields we send in our `ContactIntro` when redeeming an invite.
#[derive(Clone)]
pub struct IntroFields {
    pub mailbox_id: [u8; 32],
    pub delivery_token: [u8; 32],
    pub display_name: Option<String>,
    pub rekey: Option<RekeyInvite>,
}

/// Result of [`Account::create_invite`].
pub struct CreatedInvite {
    /// Show as QR / share as link (contains the secret).
    pub invite: Invite,
    /// Upload to the relay under `invite.id`. Opaque to the relay.
    pub sealed_package: Vec<u8>,
}

/// Result of [`Account::redeem_invite`].
pub struct Redeemed {
    pub contact: Address,
    pub contact_identity: IdentityKey,
    pub contact_mailbox_id: [u8; 32],
    pub contact_delivery_token: [u8; 32],
    /// First envelope (a `ContactIntro`), to deposit in the contact's mailbox.
    pub envelope: Vec<u8>,
}

/// A successfully opened envelope.
#[derive(Debug)]
pub enum Opened {
    /// A message from an existing contact.
    Message { from: Address, content: Content },
    /// Someone redeemed one of our invites. The caller creates the contact
    /// (initially unverified unless a mutual in-person scan confirms the key).
    NewContact {
        from: Address,
        identity: IdentityKey,
        intro: ContactIntro,
        invite_mode: InviteMode,
    },
}

/// Stored metadata for an invite we issued.
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
struct InviteRecordPb {
    #[prost(uint64, tag = "1")]
    expires_at: u64,
    #[prost(uint32, tag = "2")]
    prekey_id: u32,
    #[prost(uint32, tag = "3")]
    signed_prekey_id: u32,
    #[prost(uint32, tag = "4")]
    kyber_prekey_id: u32,
    #[prost(bytes = "vec", tag = "5")]
    proof_key: Vec<u8>,
    #[prost(uint32, tag = "6")]
    mode: u32,
}

impl Drop for InviteRecordPb {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.proof_key);
    }
}

/// One user's protocol state.
pub struct Account<B: KvBackend> {
    identity: Identity,
    store: RefCell<VeilStore<B>>,
}

impl<B: KvBackend> core::fmt::Debug for Account<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Account")
            .field("address", &self.identity.address())
            .finish_non_exhaustive()
    }
}

fn device() -> Result<DeviceId> {
    DeviceId::new(DEVICE).map_err(|_| CoreError::Protocol)
}

fn system_time(now: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(now))
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

fn timestamp(now: u64) -> Timestamp {
    Timestamp::from_epoch_millis(now.saturating_mul(1000))
}

fn arr32(v: &[u8]) -> Result<[u8; 32]> {
    v.try_into().map_err(|_| CoreError::Malformed)
}

impl<B: KvBackend> Account<B> {
    /// Creates a new account with a fresh identity and stores it in `backend`.
    pub fn create<R: Rng + CryptoRng>(mut backend: B, rng: &mut R) -> Result<Self> {
        if backend.get(keys::IDENTITY)?.is_some() {
            return Err(CoreError::Storage);
        }
        let identity = Identity::generate(rng);
        // libsignal registration ids are 14-bit and non-zero.
        let reg_id = rng.random_range(1..0x3FFF_u32);
        backend.apply(&[
            (
                keys::IDENTITY.to_vec(),
                Some(Zeroizing::new(identity.to_secret_bytes().to_vec())),
            ),
            (
                keys::REG_ID.to_vec(),
                Some(Zeroizing::new(reg_id.to_be_bytes().to_vec())),
            ),
        ])?;
        Ok(Self::assemble(backend, identity, reg_id))
    }

    /// Loads an existing account from its backend.
    pub fn load(backend: B) -> Result<Self> {
        let id_bytes = backend.get(keys::IDENTITY)?.ok_or(CoreError::Storage)?;
        let identity = Identity::from_secret_bytes(&id_bytes)?;
        let reg = backend.get(keys::REG_ID)?.ok_or(CoreError::Storage)?;
        let reg_id = u32::from_be_bytes(reg.as_slice().try_into().map_err(|_| CoreError::Storage)?);
        Ok(Self::assemble(backend, identity, reg_id))
    }

    fn assemble(backend: B, identity: Identity, reg_id: u32) -> Self {
        let pair: IdentityKeyPair = *identity.key_pair();
        Self {
            identity,
            store: RefCell::new(VeilStore::new(backend, pair, reg_id)),
        }
    }

    /// Our identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Consumes the account and returns its storage backend.
    pub fn into_backend(self) -> B {
        self.store.into_inner().into_backend()
    }

    fn handle(&self) -> StoreHandle<'_, B> {
        StoreHandle(&self.store)
    }

    fn local_address(&self) -> Result<ProtocolAddress> {
        Ok(ProtocolAddress::new(
            self.identity.address().as_str().to_owned(),
            device()?,
        ))
    }

    fn with_store<T>(&self, f: impl FnOnce(&mut VeilStore<B>) -> Result<T>) -> Result<T> {
        let mut s = self.store.try_borrow_mut().map_err(|_| CoreError::Storage)?;
        f(&mut s)
    }

    fn commit(&self) -> Result<()> {
        self.with_store(VeilStore::commit)
    }

    fn rollback(&self) {
        if let Ok(mut s) = self.store.try_borrow_mut() {
            s.rollback();
        }
    }

    /// Runs `op` as a transaction: commit on `Ok`, roll back on `Err`.
    async fn transact<T>(&self, op: impl core::future::Future<Output = Result<T>>) -> Result<T> {
        if self.with_store(|s| Ok(s.has_pending()))? {
            return Err(CoreError::Storage);
        }
        match op.await {
            Ok(v) => match self.commit() {
                Ok(()) => Ok(v),
                Err(e) => {
                    self.rollback();
                    Err(e)
                }
            },
            Err(e) => {
                self.rollback();
                Err(e)
            }
        }
    }

    /// The identity key we have recorded for a contact, if any.
    pub fn contact_identity(&self, addr: &Address) -> Result<Option<IdentityKey>> {
        self.with_store(|s| s.peer_identity(addr.as_str()))
    }

    /// Safety number with a contact (PROTOCOL §5).
    pub fn safety_number(&self, contact: &Address) -> Result<SafetyNumber> {
        let remote = self.contact_identity(contact)?.ok_or(CoreError::NoSession)?;
        SafetyNumber::new(&self.identity.address(), self.identity.public(), contact, &remote)
    }

    /// Creates a single-use invite with its own one-time prekeys (PROTOCOL §4.2).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_invite<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        mode: InviteMode,
        relay_url: &str,
        relay_spki_sha256: [u8; 32],
        mailbox_id: [u8; 32],
        delivery_token: [u8; 32],
        now: u64,
        ttl_secs: u64,
    ) -> Result<CreatedInvite> {
        if ttl_secs == 0 || ttl_secs > MAX_TTL_SECS {
            return Err(CoreError::Malformed);
        }
        let expires_at = now.checked_add(ttl_secs).ok_or(CoreError::Malformed)?;
        let invite = Invite::generate(
            rng,
            mode,
            *self.identity.public(),
            expires_at,
            relay_url,
            relay_spki_sha256,
        )?;
        let private = *self.identity.key_pair().private_key();

        let prekey_id: u32 = rng.random();
        let signed_id: u32 = rng.random();
        let kyber_id: u32 = rng.random();
        let ec_otk = KeyPair::generate(rng);
        let signed = KeyPair::generate(rng);
        let signed_sig = private
            .calculate_signature(&signed.public_key.serialize(), rng)
            .map_err(|_| CoreError::Protocol)?;
        let kyber = KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, kyber_id.into(), &private)?;
        let kyber_pub = kyber.public_key()?;
        let kyber_sig = kyber.signature()?;

        let pkg = PackagePb {
            registration_id: self.handle().get_local_registration_id().await?,
            prekey_id,
            prekey_pub: ec_otk.public_key.serialize().into_vec(),
            signed_prekey_id: signed_id,
            signed_prekey_pub: signed.public_key.serialize().into_vec(),
            signed_prekey_sig: signed_sig.to_vec(),
            kyber_prekey_id: kyber_id,
            kyber_prekey_pub: kyber_pub.serialize().into_vec(),
            kyber_prekey_sig: kyber_sig,
            identity_key: self.identity.public().serialize().into_vec(),
            mailbox_id: mailbox_id.to_vec(),
            delivery_token: delivery_token.to_vec(),
        };
        let sealed_package = invite.seal_package(rng, &pkg)?;
        let record = InviteRecordPb {
            expires_at,
            prekey_id,
            signed_prekey_id: signed_id,
            kyber_prekey_id: kyber_id,
            proof_key: invite.proof_key_bytes()?.to_vec(),
            mode: mode.to_u32(),
        };

        self.transact(async {
            let mut h = self.handle();
            // Refuse id collisions with existing keys rather than overwrite them.
            if h.get_pre_key(prekey_id.into()).await.is_ok()
                || h.get_signed_pre_key(signed_id.into()).await.is_ok()
                || h.get_kyber_pre_key(kyber_id.into()).await.is_ok()
            {
                return Err(CoreError::Protocol);
            }
            h.save_pre_key(prekey_id.into(), &PreKeyRecord::new(prekey_id.into(), &ec_otk))
                .await?;
            h.save_signed_pre_key(
                signed_id.into(),
                &SignedPreKeyRecord::new(signed_id.into(), timestamp(now), &signed, &signed_sig),
            )
            .await?;
            h.save_kyber_pre_key(kyber_id.into(), &kyber).await?;
            let rec = Zeroizing::new(record.encode_to_vec());
            self.with_store(|s| {
                s.put(keys::with(keys::INVITE, &invite.id), &rec);
                Ok(())
            })
        })
        .await?;
        Ok(CreatedInvite {
            invite,
            sealed_package,
        })
    }

    /// Redeems someone else's invite (PROTOCOL §4.3).
    pub async fn redeem_invite<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        invite: &Invite,
        sealed_package: &[u8],
        intro: IntroFields,
        now: u64,
    ) -> Result<Redeemed> {
        let (pkg, ik, bundle) = self.open_invite(invite, sealed_package, now)?;
        let contact_mailbox_id = arr32(&pkg.mailbox_id)?;
        let contact_delivery_token = arr32(&pkg.delivery_token)?;
        let contact = Address::of(&ik);
        let content = Content {
            id: random_id(rng),
            sent_at_ms: now.saturating_mul(1000),
            body: Some(Body::ContactIntro(ContactIntro {
                mailbox_id: intro.mailbox_id.to_vec(),
                delivery_token: intro.delivery_token.to_vec(),
                display_name: intro.display_name,
                invite_id: Some(invite.id.to_vec()),
                invite_proof: Some(invite.proof(self.identity.public())?.to_vec()),
                rekey: intro.rekey,
            })),
        };
        content.validate()?;
        let plaintext = Zeroizing::new(pad_block(&content.encode()));
        let envelope = self
            .establish_and_seal(rng, &bundle, &ik, &plaintext, now)
            .await?;
        Ok(Redeemed {
            contact,
            contact_identity: ik,
            contact_mailbox_id,
            contact_delivery_token,
            envelope,
        })
    }

    /// Seals `content` for an existing contact (PROTOCOL §6.1).
    pub async fn seal<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        to: &Address,
        content: &Content,
        now: u64,
    ) -> Result<Vec<u8>> {
        content.validate()?;
        if self.contact_identity(to)?.is_none() {
            return Err(CoreError::NoSession);
        }
        let remote = ProtocolAddress::new(to.as_str().to_owned(), device()?);
        self.transact(self.seal_in_tx(rng, &remote, content, now)).await
    }

    /// Starts a session from an invite bundle and seals the first message, as one transaction.
    async fn establish_and_seal<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        bundle: &PreKeyBundle,
        ik: &IdentityKey,
        plaintext: &[u8],
        now: u64,
    ) -> Result<Vec<u8>> {
        let contact = Address::of(ik);
        let remote = ProtocolAddress::new(contact.as_str().to_owned(), device()?);
        self.transact(async {
            self.with_store(|s| {
                s.set_peer_identity(contact.as_str(), ik);
                Ok(())
            })?;
            let mut session = self.handle();
            let mut ids = self.handle();
            process_prekey_bundle(
                &remote,
                &self.local_address()?,
                &mut session,
                &mut ids,
                bundle,
                system_time(now),
                rng,
            )
            .await?;
            self.seal_bytes_in_tx(rng, &remote, plaintext, now).await
        })
        .await
    }

    async fn seal_in_tx<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        remote: &ProtocolAddress,
        content: &Content,
        now: u64,
    ) -> Result<Vec<u8>> {
        let plaintext = Zeroizing::new(pad_block(&content.encode()));
        self.seal_bytes_in_tx(rng, remote, &plaintext, now).await
    }

    /// Seals already padded plaintext. Callers validate content first; tests use this
    /// directly to produce well-encrypted envelopes around hostile content.
    async fn seal_bytes_in_tx<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        remote: &ProtocolAddress,
        plaintext: &[u8],
        now: u64,
    ) -> Result<Vec<u8>> {
        let cert = self.sender_certificate(rng, now)?;
        let local = ProtocolAddress::new(cert.sender_uuid()?.to_owned(), cert.sender_device_id()?);
        let mut session = self.handle();
        let mut ids = self.handle();
        let message = message_encrypt(
            plaintext,
            remote,
            &local,
            &mut session,
            &mut ids,
            system_time(now),
            rng,
        )
        .await?;
        let sealed = self.seal_to_bucket(rng, remote, &message, &cert).await?;
        envelope::frame(&sealed)
    }

    /// Wraps an encrypted message in sealed sender so that the result fills an envelope bucket
    /// *exactly* (review round 1, H1). This is the same composition as libsignal's
    /// `sealed_sender_encrypt`, except that the USMC's `groupId` field (unused by Veil and
    /// inside the sealed-sender encryption) carries zero filler bytes. A filler length is
    /// searched for; protobuf varint boundaries can skip one size, which toggling the
    /// equally encrypted `contentHint` field (+2 bytes) covers. The relay sees only the bucket.
    async fn seal_to_bucket<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        remote: &ProtocolAddress,
        message: &CiphertextMessage,
        cert: &SenderCertificate,
    ) -> Result<Vec<u8>> {
        let base = self
            .seal_usmc(rng, remote, message, cert, ContentHint::Default, None)
            .await?
            .len();
        for bucket in crate::padding::ENVELOPE_BUCKETS {
            let target = envelope::sealed_len_for(bucket);
            if target < base.saturating_add(2) {
                continue;
            }
            for hint in [ContentHint::Default, ContentHint::Implicit] {
                let mut filler = target.saturating_sub(base).saturating_sub(2);
                for _ in 0..8 {
                    let sealed = self
                        .seal_usmc(rng, remote, message, cert, hint, Some(filler))
                        .await?;
                    if sealed.len() == target {
                        return Ok(sealed);
                    }
                    let next = if sealed.len() > target {
                        filler.checked_sub(sealed.len().saturating_sub(target))
                    } else {
                        filler.checked_add(target.saturating_sub(sealed.len()))
                    };
                    match next {
                        Some(n) if n != filler => filler = n,
                        _ => break,
                    }
                }
            }
        }
        Err(CoreError::TooLarge)
    }

    async fn seal_usmc<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        remote: &ProtocolAddress,
        message: &CiphertextMessage,
        cert: &SenderCertificate,
        hint: ContentHint,
        filler: Option<usize>,
    ) -> Result<Vec<u8>> {
        let usmc = UnidentifiedSenderMessageContent::new(
            message.message_type(),
            cert.clone(),
            message.serialize().to_vec(),
            hint,
            filler.map(|n| vec![0u8; n]),
        )?;
        Ok(sealed_sender_encrypt_from_usmc(remote, &usmc, &self.handle(), rng).await?)
    }

    /// Opens and checks an invite package, returning it with the inviter's key and bundle.
    fn open_invite(
        &self,
        invite: &Invite,
        sealed_package: &[u8],
        now: u64,
    ) -> Result<(PackagePb, IdentityKey, PreKeyBundle)> {
        if invite.is_expired(now) || &invite.identity == self.identity.public() {
            return Err(CoreError::InviteInvalid);
        }
        let pkg = invite.open_package(sealed_package)?;
        let ik = IdentityKey::decode(&pkg.identity_key).map_err(|_| CoreError::Malformed)?;
        // INV-PAIR-1: the bundle must belong to the identity in the QR code / link.
        if ik != invite.identity {
            return Err(CoreError::AuthFailed);
        }
        let bundle = PreKeyBundle::new(
            pkg.registration_id,
            device()?,
            Some((
                pkg.prekey_id.into(),
                PublicKey::deserialize(&pkg.prekey_pub).map_err(|_| CoreError::Malformed)?,
            )),
            pkg.signed_prekey_id.into(),
            PublicKey::deserialize(&pkg.signed_prekey_pub).map_err(|_| CoreError::Malformed)?,
            pkg.signed_prekey_sig.clone(),
            pkg.kyber_prekey_id.into(),
            kem::PublicKey::deserialize(&pkg.kyber_prekey_pub).map_err(|_| CoreError::Malformed)?,
            pkg.kyber_prekey_sig.clone(),
            ik,
        )?;
        Ok((pkg, ik, bundle))
    }

    /// Self-issued sender certificate (ADR-0006): our identity key is the trust root.
    fn sender_certificate<R: Rng + CryptoRng>(&self, rng: &mut R, now: u64) -> Result<SenderCertificate> {
        let pair = self.identity.key_pair();
        let signer = KeyPair::generate(rng);
        let server = ServerCertificate::new(SERVER_CERT_KEY_ID, signer.public_key, pair.private_key(), rng)?;
        Ok(SenderCertificate::new(
            self.identity.address().as_str().to_owned(),
            None,
            *pair.public_key(),
            device()?,
            timestamp(now.saturating_add(CERT_LIFETIME_SECS)),
            server,
            &signer.private_key,
            rng,
        )?)
    }

    /// Opens an envelope (PROTOCOL §6.2). Never changes state unless it returns `Ok`.
    pub async fn open<R: Rng + CryptoRng>(&self, rng: &mut R, env: &[u8], now: u64) -> Result<Opened> {
        let sealed = envelope::unframe(env)?;
        // Sealed sender v1 only (ADR-0006, review L5), with the exact version byte libsignal
        // writes: libsignal reads just the high nibble, so the low one would be malleable.
        if sealed.first() != Some(&SEALED_SENDER_V1) {
            return Err(CoreError::UnsupportedVersion);
        }
        let usmc = sealed_sender_decrypt_to_usmc(sealed, &self.handle()).await?;
        let cert = usmc.sender()?;
        let sender_key = cert.key()?;
        let sender_ik = IdentityKey::new(sender_key);
        let from = Address::of(&sender_ik);
        // The certificate must name exactly the address derived from the authenticated key,
        // and must be signed under that same key (self-issued, ADR-0006).
        if cert.sender_uuid()? != from.as_str() || cert.sender_device_id()? != device()? {
            return Err(CoreError::AuthFailed);
        }
        if !cert.validate(&sender_key, timestamp(now))? {
            return Err(CoreError::AuthFailed);
        }
        if &sender_ik == self.identity.public() {
            return Err(CoreError::AuthFailed);
        }
        let ciphertext = match usmc.msg_type()? {
            CiphertextMessageType::Whisper => {
                let m = SignalMessage::try_from(usmc.contents()?)?;
                if m.message_version() < MIN_MESSAGE_VERSION {
                    return Err(CoreError::UnsupportedVersion);
                }
                CiphertextMessage::SignalMessage(m)
            }
            CiphertextMessageType::PreKey => {
                let m = PreKeySignalMessage::try_from(usmc.contents()?)?;
                if m.message_version() < MIN_MESSAGE_VERSION || m.kyber_pre_key_id().is_none() {
                    return Err(CoreError::UnsupportedVersion);
                }
                CiphertextMessage::PreKeySignalMessage(m)
            }
            _ => return Err(CoreError::Malformed),
        };
        let remote = ProtocolAddress::new(from.as_str().to_owned(), device()?);

        match self.contact_identity(&from)? {
            Some(known) if known == sender_ik => {
                self.transact(async {
                    let content = self.decrypt_in_tx(rng, &remote, &ciphertext).await?;
                    // A known contact redeeming one of our re-key invites consumes it.
                    if let Some(Body::ContactIntro(intro)) = &content.body {
                        self.consume_invite_if_proven(intro, &sender_ik, now)?;
                    }
                    Ok(Opened::Message {
                        from: from.clone(),
                        content,
                    })
                })
                .await
            }
            // Unreachable by construction (address = hash(key)); kept as a hard stop.
            Some(_) => Err(CoreError::IdentityChanged),
            None => {
                let CiphertextMessage::PreKeySignalMessage(pre) = &ciphertext else {
                    return Err(CoreError::UnknownSender);
                };
                let (invite_id, record) = self.find_invite_for(pre, now)?.ok_or(CoreError::UnknownSender)?;
                self.transact(async {
                    // Tentatively record the sender; rolled back unless everything below succeeds.
                    self.with_store(|s| {
                        s.set_peer_identity(from.as_str(), &sender_ik);
                        Ok(())
                    })?;
                    let content = self.decrypt_in_tx(rng, &remote, &ciphertext).await?;
                    let Some(Body::ContactIntro(intro)) = &content.body else {
                        return Err(CoreError::InviteInvalid);
                    };
                    if intro.invite_id.as_deref() != Some(&invite_id[..]) {
                        return Err(CoreError::InviteInvalid);
                    }
                    let proof = intro.invite_proof.as_deref().ok_or(CoreError::InviteInvalid)?;
                    verify_proof(&record.proof_key, &invite_id, &sender_ik, proof)?;
                    self.delete_invite(&invite_id, &record)?;
                    let invite_mode = if record.mode == InviteMode::InPerson.to_u32() {
                        InviteMode::InPerson
                    } else {
                        InviteMode::Remote
                    };
                    Ok(Opened::NewContact {
                        from: from.clone(),
                        identity: sender_ik,
                        intro: intro.clone(),
                        invite_mode,
                    })
                })
                .await
            }
        }
    }

    async fn decrypt_in_tx<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        remote: &ProtocolAddress,
        ciphertext: &CiphertextMessage,
    ) -> Result<Content> {
        let mut session = self.handle();
        let mut ids = self.handle();
        let mut pre = self.handle();
        let signed = self.handle();
        let mut kyber = self.handle();
        let local = self.local_address()?;
        let padded = Zeroizing::new(
            message_decrypt(
                ciphertext,
                remote,
                &local,
                &mut session,
                &mut ids,
                &mut pre,
                &signed,
                &mut kyber,
                rng,
            )
            .await?,
        );
        Content::decode_strict(unpad_block(&padded)?)
    }

    /// Finds the live invite whose one-time prekeys this `PreKey` message uses.
    fn find_invite_for(
        &self,
        msg: &PreKeySignalMessage,
        now: u64,
    ) -> Result<Option<(Vec<u8>, InviteRecordPb)>> {
        let signed_id = u32::from(msg.signed_pre_key_id());
        let kyber_id = msg.kyber_pre_key_id().map(u32::from);
        let pre_id = msg.pre_key_id().map(u32::from);
        self.with_store(|s| {
            for key in s.keys_with_prefix(keys::INVITE)? {
                let Some(raw) = s.get(&key)? else { continue };
                let rec = InviteRecordPb::decode(raw.as_slice()).map_err(|_| CoreError::Storage)?;
                if rec.signed_prekey_id == signed_id
                    && Some(rec.kyber_prekey_id) == kyber_id
                    && Some(rec.prekey_id) == pre_id
                {
                    if now >= rec.expires_at {
                        return Err(CoreError::InviteInvalid);
                    }
                    let id = key.get(keys::INVITE.len()..).ok_or(CoreError::Storage)?.to_vec();
                    return Ok(Some((id, rec)));
                }
            }
            Ok(None)
        })
    }

    fn consume_invite_if_proven(&self, intro: &ContactIntro, sender: &IdentityKey, now: u64) -> Result<()> {
        let (Some(id), Some(proof)) = (intro.invite_id.as_deref(), intro.invite_proof.as_deref()) else {
            return Ok(());
        };
        let rec = self.with_store(|s| s.get(&keys::with(keys::INVITE, id)))?;
        let Some(raw) = rec else { return Ok(()) };
        let rec = InviteRecordPb::decode(raw.as_slice()).map_err(|_| CoreError::Storage)?;
        if now >= rec.expires_at {
            return Err(CoreError::InviteInvalid);
        }
        verify_proof(&rec.proof_key, id, sender, proof)?;
        self.delete_invite(id, &rec)
    }

    /// Fails (and so aborts the transaction) if the store is unavailable, never skips (review L6).
    fn delete_invite(&self, id: &[u8], rec: &InviteRecordPb) -> Result<()> {
        self.with_store(|s| {
            s.delete(keys::with(keys::INVITE, id));
            s.delete(keys::with(keys::PREKEY, &rec.prekey_id.to_be_bytes()));
            s.delete(keys::with(
                keys::SIGNED_PREKEY,
                &rec.signed_prekey_id.to_be_bytes(),
            ));
            s.delete(keys::with(keys::KYBER_PREKEY, &rec.kyber_prekey_id.to_be_bytes()));
            Ok(())
        })
    }

    /// Revokes an unused invite: its prekeys are deleted, so it can never be redeemed.
    pub async fn revoke_invite(&self, id: &[u8; 16]) -> Result<()> {
        self.transact(async {
            let raw = self
                .with_store(|s| s.get(&keys::with(keys::INVITE, id)))?
                .ok_or(CoreError::InviteInvalid)?;
            let rec = InviteRecordPb::decode(raw.as_slice()).map_err(|_| CoreError::Storage)?;
            self.delete_invite(id, &rec)?;
            Ok(())
        })
        .await
    }

    /// Deletes all expired invites and their prekeys. Returns how many were removed.
    pub async fn sweep_expired_invites(&self, now: u64) -> Result<usize> {
        self.transact(async {
            let mut removed = 0usize;
            let keys_list = self.with_store(|s| s.keys_with_prefix(keys::INVITE))?;
            for key in keys_list {
                let Some(raw) = self.with_store(|s| s.get(&key))? else {
                    continue;
                };
                let rec = InviteRecordPb::decode(raw.as_slice()).map_err(|_| CoreError::Storage)?;
                if now >= rec.expires_at {
                    let id = key.get(keys::INVITE.len()..).ok_or(CoreError::Storage)?.to_vec();
                    self.delete_invite(&id, &rec)?;
                    removed = removed.saturating_add(1);
                }
            }
            Ok(removed)
        })
        .await
    }
}

/// Random 16-byte message id.
pub fn random_id<R: Rng + CryptoRng>(rng: &mut R) -> Vec<u8> {
    let mut id = vec![0u8; 16];
    rng.fill(&mut id[..]);
    id
}

#[cfg(test)]
mod pq_tests {
    //! White-box checks that PQXDH and SPQR are active inside Veil's own envelopes.
    use super::*;
    use crate::content::Text;
    use crate::store::MemoryBackend;
    use futures_executor::block_on;
    use rand::TryRngCore as _;
    use rand::rngs::OsRng;

    const NOW: u64 = 1_800_000_000;

    async fn inner(acc: &Account<MemoryBackend>, env: &[u8]) -> CiphertextMessage {
        let sealed = envelope::unframe(env).unwrap();
        let usmc = sealed_sender_decrypt_to_usmc(sealed, &acc.handle())
            .await
            .unwrap();
        match usmc.msg_type().unwrap() {
            CiphertextMessageType::PreKey => CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(usmc.contents().unwrap()).unwrap(),
            ),
            CiphertextMessageType::Whisper => {
                CiphertextMessage::SignalMessage(SignalMessage::try_from(usmc.contents().unwrap()).unwrap())
            }
            _ => panic!("unexpected type"),
        }
    }

    #[test]
    fn pqxdh_and_spqr_are_active() {
        block_on(async {
            let mut rng = OsRng.unwrap_err();
            let alice = Account::create(MemoryBackend::new(), &mut rng).unwrap();
            let bob = Account::create(MemoryBackend::new(), &mut rng).unwrap();
            let c = bob
                .create_invite(
                    &mut rng,
                    InviteMode::Remote,
                    "wss://r.example",
                    [0; 32],
                    [1; 32],
                    [2; 32],
                    NOW,
                    600,
                )
                .await
                .unwrap();
            let intro = IntroFields {
                mailbox_id: [5; 32],
                delivery_token: [6; 32],
                display_name: None,
                rekey: None,
            };
            let red = alice
                .redeem_invite(&mut rng, &c.invite, &c.sealed_package, intro, NOW)
                .await
                .unwrap();
            // INV-CRY-1: first message is v4 with an ML-KEM (Kyber1024) ciphertext.
            match inner(&bob, &red.envelope).await {
                CiphertextMessage::PreKeySignalMessage(m) => {
                    assert!(m.message_version() >= MIN_MESSAGE_VERSION);
                    assert_eq!(m.kyber_ciphertext().map(|k| k.len()), Some(1569));
                }
                _ => panic!("first message must be PreKey"),
            }
            assert!(matches!(
                bob.open(&mut rng, &red.envelope, NOW).await,
                Ok(Opened::NewContact { .. })
            ));
            // INV-CRY-2: every subsequent message carries SPQR (post-quantum ratchet) data.
            let mut with_spqr = 0;
            for i in 0..20 {
                let (from, to) = if i % 2 == 0 {
                    (&bob, &alice)
                } else {
                    (&alice, &bob)
                };
                let content = Content {
                    id: random_id(&mut rng),
                    sent_at_ms: 0,
                    body: Some(Body::Text(Text {
                        body: format!("{i}"),
                        ..Default::default()
                    })),
                };
                let env = from
                    .seal(&mut rng, &to.identity().address(), &content, NOW)
                    .await
                    .unwrap();
                match inner(to, &env).await {
                    CiphertextMessage::SignalMessage(m) => {
                        assert!(m.message_version() >= MIN_MESSAGE_VERSION);
                        if !m.pq_ratchet().is_empty() {
                            with_spqr += 1;
                        }
                    }
                    // Alice's first reply-direction message may still be PreKey until Bob answers.
                    CiphertextMessage::PreKeySignalMessage(m) => {
                        assert!(m.message_version() >= MIN_MESSAGE_VERSION);
                    }
                    _ => panic!("unexpected"),
                }
                assert!(to.open(&mut rng, &env, NOW).await.is_ok());
            }
            assert!(with_spqr >= 19, "SPQR data in {with_spqr}/20 messages");
        });
    }
}

crate::redacted_debug!(InviteRecordPb);

#[cfg(test)]
mod rollback_tests {
    //! Review round 1, M4 (INV-STATE-1): input that *decrypts successfully* and is refused
    //! afterwards (wrong invite id, bad proof, wrong body, undecodable content) must leave
    //! the recipient byte-identical, and the genuine message must still work afterwards.
    //! A plain bit flip is rejected before any state is touched, so it cannot show this.
    use super::*;
    use crate::content::Text;
    use crate::store::MemoryBackend;
    use futures_executor::block_on;
    use rand::TryRngCore as _;
    use rand::rngs::OsRng;

    const NOW: u64 = 1_800_000_000;
    type Acc = Account<MemoryBackend>;

    fn rng() -> rand::rand_core::UnwrapErr<OsRng> {
        OsRng.unwrap_err()
    }

    fn intro(invite: &Invite, from: &Acc, invite_id: Vec<u8>, proof: Option<Vec<u8>>) -> Content {
        Content {
            id: random_id(&mut rng()),
            sent_at_ms: 1,
            body: Some(Body::ContactIntro(ContactIntro {
                mailbox_id: vec![1; 32],
                delivery_token: vec![2; 32],
                display_name: None,
                invite_id: Some(invite_id),
                invite_proof: Some(
                    proof.unwrap_or_else(|| invite.proof(from.identity.public()).unwrap().to_vec()),
                ),
                rekey: None,
            })),
        }
    }

    fn text(s: &str) -> Content {
        Content {
            id: random_id(&mut rng()),
            sent_at_ms: 1,
            body: Some(Body::Text(Text {
                body: s.into(),
                ..Default::default()
            })),
        }
    }

    /// Redeems `invite` as `from` but seals arbitrary padded plaintext as the first message.
    fn redeem_raw(from: &Acc, invite: &Invite, pkg: &[u8], plaintext: &[u8]) -> Vec<u8> {
        block_on(async {
            let (_, ik, bundle) = from.open_invite(invite, pkg, NOW).unwrap();
            from.establish_and_seal(&mut rng(), &bundle, &ik, plaintext, NOW)
                .await
                .unwrap()
        })
    }

    /// Opens `env` at `at`, asserts it is refused and that `at` is byte-identical after.
    fn refused(at: Acc, env: &[u8]) -> (Acc, CoreError) {
        let before = at.into_backend();
        let at = Account::load(before.clone()).unwrap();
        let err = block_on(at.open(&mut rng(), env, NOW)).unwrap_err();
        let after = at.into_backend();
        assert!(
            after == before,
            "state changed after a decrypted-then-refused envelope ({err:?})"
        );
        (Account::load(after).unwrap(), err)
    }

    #[test]
    fn refused_intros_change_nothing_and_invite_stays_usable() {
        let bob = Account::create(MemoryBackend::new(), &mut rng()).unwrap();
        let created = block_on(bob.create_invite(
            &mut rng(),
            InviteMode::Remote,
            "wss://r",
            [3; 32],
            [1; 32],
            [2; 32],
            NOW,
            3600,
        ))
        .unwrap();
        let (inv, pkg) = (&created.invite, &created.sealed_package);
        let mut bob = bob;
        let cases: [(&str, Vec<u8>, CoreError); 4] = {
            let m = || Account::create(MemoryBackend::new(), &mut rng()).unwrap();
            let pad = |c: &Content| pad_block(&c.encode());
            let (m1, m2, m3, m4) = (m(), m(), m(), m());
            [
                (
                    "wrong invite id",
                    redeem_raw(&m1, inv, pkg, &pad(&intro(inv, &m1, vec![9; 16], None))),
                    CoreError::InviteInvalid,
                ),
                (
                    "bad proof",
                    redeem_raw(
                        &m2,
                        inv,
                        pkg,
                        &pad(&intro(inv, &m2, inv.id.to_vec(), Some(vec![7; 32]))),
                    ),
                    CoreError::AuthFailed,
                ),
                (
                    "not an intro",
                    redeem_raw(&m3, inv, pkg, &pad(&text("hi"))),
                    CoreError::InviteInvalid,
                ),
                (
                    "undecodable content",
                    redeem_raw(&m4, inv, pkg, &pad_block(&[0xFF; 40])),
                    CoreError::Malformed,
                ),
            ]
        };
        for (what, env, want) in cases {
            let (b, err) = refused(bob, &env);
            assert_eq!(err, want, "{what}");
            bob = b;
        }
        // The invite was not consumed: a genuine redemption still succeeds.
        let alice = Account::create(MemoryBackend::new(), &mut rng()).unwrap();
        let fields = IntroFields {
            mailbox_id: [4; 32],
            delivery_token: [5; 32],
            display_name: None,
            rekey: None,
        };
        let red = block_on(alice.redeem_invite(&mut rng(), inv, pkg, fields, NOW)).unwrap();
        assert!(matches!(
            block_on(bob.open(&mut rng(), &red.envelope, NOW)).unwrap(),
            Opened::NewContact { .. }
        ));
    }

    #[test]
    fn known_contact_with_undecodable_content_changes_nothing() {
        let (alice, bob) = {
            let bob = Account::create(MemoryBackend::new(), &mut rng()).unwrap();
            let alice = Account::create(MemoryBackend::new(), &mut rng()).unwrap();
            let created = block_on(bob.create_invite(
                &mut rng(),
                InviteMode::Remote,
                "wss://r",
                [3; 32],
                [1; 32],
                [2; 32],
                NOW,
                3600,
            ))
            .unwrap();
            let fields = IntroFields {
                mailbox_id: [4; 32],
                delivery_token: [5; 32],
                display_name: None,
                rekey: None,
            };
            let red = block_on(alice.redeem_invite(
                &mut rng(),
                &created.invite,
                &created.sealed_package,
                fields,
                NOW,
            ))
            .unwrap();
            block_on(bob.open(&mut rng(), &red.envelope, NOW)).unwrap();
            (alice, bob)
        };
        let to = ProtocolAddress::new(bob.identity.address().as_str().to_owned(), device().unwrap());
        let mut bob = bob;
        // Undecodable bytes, an all-zero block (bad padding), and an empty `Content` (fails validation).
        for plaintext in [
            pad_block(&[0xFF; 40]),
            vec![0; 256],
            pad_block(&Content::default().encode()),
        ] {
            let env =
                block_on(alice.transact(alice.seal_bytes_in_tx(&mut rng(), &to, &plaintext, NOW))).unwrap();
            let (b, err) = refused(bob, &env);
            assert!(matches!(err, CoreError::Malformed), "{err:?}");
            bob = b;
        }
        let env =
            block_on(alice.seal(&mut rng(), &bob.identity.address(), &text("still fine"), NOW)).unwrap();
        assert!(matches!(
            block_on(bob.open(&mut rng(), &env, NOW)).unwrap(),
            Opened::Message { .. }
        ));
    }
}
