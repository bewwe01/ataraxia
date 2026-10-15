//! Protocol state storage.
//!
//! [`KvBackend`] is the persistence boundary: the client implements it over SQLCipher,
//! and tests use [`MemoryBackend`]. [`VeilStore`] implements libsignal's store traits
//! on top, with two Veil-specific properties:
//!
//! * **Transactions.** All writes go to an overlay that is committed only when the
//!   whole operation succeeded. A rejected or forged message therefore never changes
//!   state (INV-MSG-2: "session state unaffected").
//! * **Strict identity policy.** `is_trusted_identity` is true only for an exact match
//!   with the stored key. Unknown and changed keys are untrusted, so libsignal itself
//!   refuses them; Veil decides explicitly when to record a new contact (INV-ID-2).

use std::collections::BTreeMap;

use async_trait::async_trait;
use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, KyberPreKeyId,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, PublicKey,
    SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Minimal persistent key-value interface. Values may contain secrets (session
/// records, private prekeys); implementations must store them encrypted.
pub trait KvBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()>;
    fn delete(&mut self, key: &[u8]) -> Result<()>;
    /// All keys starting with `prefix` (used for invite expiry sweeps).
    fn keys_with_prefix(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>>;
}

/// In-memory backend for tests and ephemeral use. Values are zeroized on drop.
/// `Clone`/`PartialEq` exist so tests can snapshot state and prove it did not change.
#[derive(Default, Clone, PartialEq)]
pub struct MemoryBackend {
    map: BTreeMap<Vec<u8>, Zeroizing<Vec<u8>>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KvBackend for MemoryBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.map.get(key).cloned())
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.map.insert(key.to_vec(), Zeroizing::new(value.to_vec()));
        Ok(())
    }
    fn delete(&mut self, key: &[u8]) -> Result<()> {
        self.map.remove(key);
        Ok(())
    }
    fn keys_with_prefix(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>> {
        Ok(self.map.keys().filter(|k| k.starts_with(prefix)).cloned().collect())
    }
}

pub(crate) mod keys {
    pub const IDENTITY: &[u8] = b"self/identity";
    pub const REG_ID: &[u8] = b"self/regid";
    pub const PEER: &[u8] = b"peer/";
    pub const SESSION: &[u8] = b"sess/";
    pub const PREKEY: &[u8] = b"pk/";
    pub const SIGNED_PREKEY: &[u8] = b"spk/";
    pub const KYBER_PREKEY: &[u8] = b"kpk/";
    pub const INVITE: &[u8] = b"inv/";

    pub fn with(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
        let mut k = Vec::with_capacity(prefix.len().saturating_add(suffix.len()));
        k.extend_from_slice(prefix);
        k.extend_from_slice(suffix);
        k
    }
}

/// libsignal store implementation with a transactional overlay.
pub struct VeilStore<B: KvBackend> {
    backend: B,
    overlay: BTreeMap<Vec<u8>, Option<Zeroizing<Vec<u8>>>>,
    identity: IdentityKeyPair,
    registration_id: u32,
}

impl<B: KvBackend> VeilStore<B> {
    pub(crate) fn new(backend: B, identity: IdentityKeyPair, registration_id: u32) -> Self {
        Self { backend, overlay: BTreeMap::new(), identity, registration_id }
    }

    pub(crate) fn backend(&self) -> &B {
        &self.backend
    }

    /// Consumes the store, returning the backend (used to persist/reopen in tests and the client).
    pub fn into_backend(self) -> B {
        self.backend
    }

    pub(crate) fn get(&self, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match self.overlay.get(key) {
            Some(v) => Ok(v.clone()),
            None => self.backend.get(key),
        }
    }

    pub(crate) fn put(&mut self, key: Vec<u8>, value: &[u8]) {
        self.overlay.insert(key, Some(Zeroizing::new(value.to_vec())));
    }

    pub(crate) fn delete(&mut self, key: Vec<u8>) {
        self.overlay.insert(key, None);
    }

    /// Keys with `prefix`, including uncommitted puts and excluding uncommitted deletes.
    pub(crate) fn keys_with_prefix(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut ks: std::collections::BTreeSet<Vec<u8>> =
            self.backend.keys_with_prefix(prefix)?.into_iter().collect();
        for (k, v) in self.overlay.range(prefix.to_vec()..) {
            if !k.starts_with(prefix) {
                break;
            }
            if v.is_some() {
                ks.insert(k.clone());
            } else {
                ks.remove(k);
            }
        }
        Ok(ks.into_iter().collect())
    }

    /// Applies all pending writes to the backend.
    pub(crate) fn commit(&mut self) -> Result<()> {
        let pending = core::mem::take(&mut self.overlay);
        for (k, v) in pending {
            match v {
                Some(v) => self.backend.put(&k, &v)?,
                None => self.backend.delete(&k)?,
            }
        }
        Ok(())
    }

    /// Discards all pending writes.
    pub(crate) fn rollback(&mut self) {
        self.overlay.clear();
    }

    pub(crate) fn has_pending(&self) -> bool {
        !self.overlay.is_empty()
    }

    pub(crate) fn peer_identity(&self, addr: &str) -> Result<Option<IdentityKey>> {
        self.get(&keys::with(keys::PEER, addr.as_bytes()))?
            .map(|v| IdentityKey::decode(&v).map_err(|_| CoreError::Storage))
            .transpose()
    }

    pub(crate) fn set_peer_identity(&mut self, addr: &str, key: &IdentityKey) {
        self.put(keys::with(keys::PEER, addr.as_bytes()), &key.serialize());
    }
}

/// A handle through which libsignal accesses a shared [`VeilStore`]. libsignal takes the
/// session and identity stores as two separate `&mut` arguments, so the store lives in a
/// `RefCell` and each handle borrows it briefly per call (never across an `.await`).
pub(crate) struct StoreHandle<'a, B: KvBackend>(pub(crate) &'a core::cell::RefCell<VeilStore<B>>);

impl<B: KvBackend> StoreHandle<'_, B> {
    fn read(&self) -> libsignal_protocol::error::Result<core::cell::Ref<'_, VeilStore<B>>> {
        self.0.try_borrow().map_err(|_| SignalProtocolError::InvalidState("store-borrow", String::new()))
    }
    fn write(&self) -> libsignal_protocol::error::Result<core::cell::RefMut<'_, VeilStore<B>>> {
        self.0.try_borrow_mut().map_err(|_| SignalProtocolError::InvalidState("store-borrow", String::new()))
    }
}

fn storage_err(_: CoreError) -> SignalProtocolError {
    SignalProtocolError::InvalidState("storage", String::new())
}

fn decode_err<E>(_: E) -> SignalProtocolError {
    SignalProtocolError::InvalidState("storage-decode", String::new())
}

fn id_key(prefix: &[u8], id: u32) -> Vec<u8> {
    keys::with(prefix, &id.to_be_bytes())
}

#[async_trait(?Send)]
impl<B: KvBackend> IdentityKeyStore for StoreHandle<'_, B> {
    async fn get_identity_key_pair(&self) -> libsignal_protocol::error::Result<IdentityKeyPair> {
        Ok(self.read()?.identity)
    }

    async fn get_local_registration_id(&self) -> libsignal_protocol::error::Result<u32> {
        Ok(self.read()?.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> libsignal_protocol::error::Result<IdentityChange> {
        let existing = self.read()?.peer_identity(address.name()).map_err(storage_err)?;
        match existing {
            Some(k) if &k == identity => Ok(IdentityChange::NewOrUnchanged),
            // libsignal only calls this after `is_trusted_identity` passed, which requires an
            // exact match; refuse to overwrite here as defence in depth (INV-ID-2).
            Some(_) => Err(SignalProtocolError::UntrustedIdentity(address.clone())),
            None => Err(SignalProtocolError::UntrustedIdentity(address.clone())),
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> libsignal_protocol::error::Result<bool> {
        Ok(self.read()?.peer_identity(address.name()).map_err(storage_err)?.as_ref() == Some(identity))
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> libsignal_protocol::error::Result<Option<IdentityKey>> {
        self.read()?.peer_identity(address.name()).map_err(storage_err)
    }
}

#[async_trait(?Send)]
impl<B: KvBackend> SessionStore for StoreHandle<'_, B> {
    async fn load_session(&self, address: &ProtocolAddress) -> libsignal_protocol::error::Result<Option<SessionRecord>> {
        self.read()?.get(&keys::with(keys::SESSION, address.name().as_bytes()))
            .map_err(storage_err)?
            .map(|v| SessionRecord::deserialize(&v).map_err(decode_err))
            .transpose()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> libsignal_protocol::error::Result<()> {
        let bytes = Zeroizing::new(record.serialize()?);
        self.write()?.put(keys::with(keys::SESSION, address.name().as_bytes()), &bytes);
        Ok(())
    }
}

#[async_trait(?Send)]
impl<B: KvBackend> PreKeyStore for StoreHandle<'_, B> {
    async fn get_pre_key(&self, id: PreKeyId) -> libsignal_protocol::error::Result<PreKeyRecord> {
        let v = self
            .read()?
            .get(&id_key(keys::PREKEY, u32::from(id)))
            .map_err(storage_err)?
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;
        PreKeyRecord::deserialize(&v).map_err(decode_err)
    }

    async fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> libsignal_protocol::error::Result<()> {
        let bytes = Zeroizing::new(record.serialize()?);
        self.write()?.put(id_key(keys::PREKEY, u32::from(id)), &bytes);
        Ok(())
    }

    async fn remove_pre_key(&mut self, id: PreKeyId) -> libsignal_protocol::error::Result<()> {
        self.write()?.delete(id_key(keys::PREKEY, u32::from(id)));
        Ok(())
    }
}

#[async_trait(?Send)]
impl<B: KvBackend> SignedPreKeyStore for StoreHandle<'_, B> {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> libsignal_protocol::error::Result<SignedPreKeyRecord> {
        let v = self
            .read()?
            .get(&id_key(keys::SIGNED_PREKEY, u32::from(id)))
            .map_err(storage_err)?
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
        SignedPreKeyRecord::deserialize(&v).map_err(decode_err)
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> libsignal_protocol::error::Result<()> {
        let bytes = Zeroizing::new(record.serialize()?);
        self.write()?.put(id_key(keys::SIGNED_PREKEY, u32::from(id)), &bytes);
        Ok(())
    }
}

#[async_trait(?Send)]
impl<B: KvBackend> KyberPreKeyStore for StoreHandle<'_, B> {
    async fn get_kyber_pre_key(&self, id: KyberPreKeyId) -> libsignal_protocol::error::Result<KyberPreKeyRecord> {
        let v = self
            .read()?
            .get(&id_key(keys::KYBER_PREKEY, u32::from(id)))
            .map_err(storage_err)?
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;
        KyberPreKeyRecord::deserialize(&v).map_err(decode_err)
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> libsignal_protocol::error::Result<()> {
        let bytes = Zeroizing::new(record.serialize()?);
        self.write()?.put(id_key(keys::KYBER_PREKEY, u32::from(id)), &bytes);
        Ok(())
    }

    /// Veil uses only one-time Kyber prekeys (one per invite), so "used" means deleted.
    async fn mark_kyber_pre_key_used(
        &mut self,
        id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> libsignal_protocol::error::Result<()> {
        self.write()?.delete(id_key(keys::KYBER_PREKEY, u32::from(id)));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::TryRngCore as _;
    use rand::rngs::OsRng;

    fn store() -> VeilStore<MemoryBackend> {
        VeilStore::new(MemoryBackend::new(), IdentityKeyPair::generate(&mut OsRng.unwrap_err()), 7)
    }

    #[test]
    fn rollback_discards_and_commit_persists() {
        let mut s = store();
        s.put(b"a".to_vec(), b"1");
        assert!(s.has_pending());
        assert_eq!(s.get(b"a").ok().flatten().map(|v| v.to_vec()), Some(b"1".to_vec()));
        s.rollback();
        assert_eq!(s.get(b"a").ok().flatten(), None);
        s.put(b"a".to_vec(), b"2");
        assert!(s.commit().is_ok());
        assert!(!s.has_pending());
        assert_eq!(s.backend().get(b"a").ok().flatten().map(|v| v.to_vec()), Some(b"2".to_vec()));
        s.delete(b"a".to_vec());
        assert_eq!(s.get(b"a").ok().flatten(), None, "uncommitted delete hides value");
        s.rollback();
        assert!(s.get(b"a").ok().flatten().is_some(), "rollback restores");
    }

    #[test]
    fn prefix_listing_sees_overlay() {
        let mut s = store();
        s.put(b"inv/1".to_vec(), b"x");
        assert!(s.commit().is_ok());
        s.put(b"inv/2".to_vec(), b"y");
        s.delete(b"inv/1".to_vec());
        assert_eq!(s.keys_with_prefix(b"inv/").ok(), Some(vec![b"inv/2".to_vec()]));
    }

    #[test]
    fn identity_policy_is_exact_match_only() {
        futures_executor::block_on(async {
            let cell = core::cell::RefCell::new(store());
            let mut s = StoreHandle(&cell);
            let addr = ProtocolAddress::new("v1:x".into(), libsignal_protocol::DeviceId::new(1).unwrap());
            let k1 = *IdentityKeyPair::generate(&mut OsRng.unwrap_err()).identity_key();
            let k2 = *IdentityKeyPair::generate(&mut OsRng.unwrap_err()).identity_key();
            // Unknown peer: untrusted, and save_identity refuses (no TOFU inside libsignal).
            assert_eq!(s.is_trusted_identity(&addr, &k1, Direction::Receiving).await.ok(), Some(false));
            assert!(s.save_identity(&addr, &k1).await.is_err());
            // Explicitly recorded: trusted, and a different key is not.
            cell.borrow_mut().set_peer_identity(addr.name(), &k1);
            assert_eq!(s.is_trusted_identity(&addr, &k1, Direction::Sending).await.ok(), Some(true));
            assert_eq!(s.is_trusted_identity(&addr, &k2, Direction::Sending).await.ok(), Some(false));
            assert!(s.save_identity(&addr, &k2).await.is_err(), "never overwrite silently");
        });
    }
}
