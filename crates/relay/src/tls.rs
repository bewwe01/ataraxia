//! TLS for the relay: TLS 1.3 only, rustls with the `ring` provider (ADR-0010).
//!
//! Clients pin the SHA-256 of the relay's `SubjectPublicKeyInfo` (PROTOCOL §13, INV-NET-2), so a
//! self-signed certificate is the normal setup: `veil-relay gen-cert` creates one and prints
//! the pin to put in invites.

use std::path::Path;
use std::sync::Arc;

use rcgen::PublicKeyData as _;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest as _, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("cannot read or write the certificate/key files")]
    Io,
    #[error("invalid certificate or key")]
    Invalid,
    #[error("the certificate does not match the private key")]
    Mismatch,
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        },
    )
}

/// Creates a self-signed ECDSA P-256 certificate for `names` and writes `cert.pem` and
/// `key.pem` (mode 0600) into `dir`. Returns the SPKI SHA-256 pin.
pub fn generate(dir: &Path, names: Vec<String>) -> Result<[u8; 32], TlsError> {
    let key = rcgen::KeyPair::generate().map_err(|_| TlsError::Invalid)?;
    let params = rcgen::CertificateParams::new(names).map_err(|_| TlsError::Invalid)?;
    let cert = params.self_signed(&key).map_err(|_| TlsError::Invalid)?;
    std::fs::create_dir_all(dir).map_err(|_| TlsError::Io)?;
    write_private(&dir.join("key.pem"), key.serialize_pem().as_bytes())?;
    std::fs::write(dir.join("cert.pem"), cert.pem()).map_err(|_| TlsError::Io)?;
    Ok(Sha256::digest(key.subject_public_key_info()).into())
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> Result<(), TlsError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| TlsError::Io)?;
    f.write_all(data).map_err(|_| TlsError::Io)
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> Result<(), TlsError> {
    std::fs::write(path, data).map_err(|_| TlsError::Io)
}

/// Loads `cert.pem`/`key.pem` and builds a TLS 1.3-only server config. Returns it with the
/// SPKI pin, after checking that the certificate really carries the key's public key.
pub fn load(cert: &Path, key: &Path) -> Result<(Arc<ServerConfig>, [u8; 32]), TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|_| TlsError::Io)?
        .collect::<Result<_, _>>()
        .map_err(|_| TlsError::Invalid)?;
    let leaf = certs.first().ok_or(TlsError::Invalid)?;
    let key_pem = std::fs::read_to_string(key).map_err(|_| TlsError::Io)?;
    let spki = rcgen::KeyPair::from_pem(&key_pem)
        .map_err(|_| TlsError::Invalid)?
        .subject_public_key_info();
    // The SubjectPublicKeyInfo is embedded verbatim in the certificate's TBSCertificate.
    if !leaf.as_ref().windows(spki.len()).any(|w| w == spki.as_slice()) {
        return Err(TlsError::Mismatch);
    }
    let pin: [u8; 32] = Sha256::digest(&spki).into();
    let private = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|_| TlsError::Invalid)?;
    let config = server_config(certs, private)?;
    Ok((config, pin))
}

/// TLS 1.3 only, no client auth, `ring` provider.
pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| TlsError::Invalid)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| TlsError::Invalid)?;
    Ok(Arc::new(config))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_load_and_pin() {
        let dir = std::env::temp_dir().join(format!("veil-tls-{}", rand::random::<u64>()));
        let pin = generate(&dir, vec!["relay.test".into()]).unwrap();
        let (_, loaded) = load(&dir.join("cert.pem"), &dir.join("key.pem")).unwrap();
        assert_eq!(pin, loaded);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.join("key.pem"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // A certificate paired with another key is refused.
        let other = dir.join("other");
        generate(&other, vec!["relay.test".into()]).unwrap();
        assert!(matches!(
            load(&dir.join("cert.pem"), &other.join("key.pem")),
            Err(TlsError::Mismatch)
        ));
        // Refuses to overwrite an existing key.
        assert!(generate(&dir, vec!["relay.test".into()]).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
