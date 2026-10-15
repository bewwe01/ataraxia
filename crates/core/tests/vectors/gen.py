"""Independent oracle for veil-core known-answer vectors.

Uses only Python stdlib + argon2-cffi + pyca/cryptography. Implements HChaCha20 and the
STREAM (BE32) nonce layout directly from their specifications, so these vectors do not
depend on any Rust code under test. Run:  python3 gen.py > ../../src/test_vectors.rs
"""
import hashlib, struct
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def rotl(v, c): return ((v << c) & 0xffffffff) | (v >> (32 - c))
def qr(s, a, b, c, d):
    s[a]=(s[a]+s[b])&0xffffffff; s[d]=rotl(s[d]^s[a],16)
    s[c]=(s[c]+s[d])&0xffffffff; s[b]=rotl(s[b]^s[c],12)
    s[a]=(s[a]+s[b])&0xffffffff; s[d]=rotl(s[d]^s[a],8)
    s[c]=(s[c]+s[d])&0xffffffff; s[b]=rotl(s[b]^s[c],7)
def hchacha20(key, nonce16):
    s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]+list(struct.unpack('<8I',key))+list(struct.unpack('<4I',nonce16))
    for _ in range(10):
        qr(s,0,4,8,12);qr(s,1,5,9,13);qr(s,2,6,10,14);qr(s,3,7,11,15)
        qr(s,0,5,10,15);qr(s,1,6,11,12);qr(s,2,7,8,13);qr(s,3,4,9,14)
    return struct.pack('<8I', *(s[0:4]+s[12:16]))
def xchacha_encrypt(key, nonce24, pt, aad):
    sub = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(sub).encrypt(b'\0\0\0\0'+nonce24[16:], pt, aad)

def rs_bytes(name, b):
    return f"pub const {name}: [u8; {len(b)}] = {list(b)};"

out = ["//! Known-answer vectors, computed independently by `tests/vectors/gen.py` (Python stdlib +",
       "//! argon2-cffi + pyca/cryptography, with HChaCha20/STREAM implemented from the specs), NOT by",
       "//! this crate, so tests compare against an outside oracle. Regenerate: `python3 gen.py`.",
       "#![cfg(test)]", ""]

# Address / fingerprint
raw = bytes([5]) + bytes([1]) * 32
out.append('/// `Address::of(0x05 || 0x01 * 32)`')
out.append(f'pub const ADDR_OF_05_01X32: &str = "v1:{hashlib.sha256(b"veil/v1/addr"+raw).hexdigest()[:40]}";')
fp = hashlib.sha256(b"veil/v1/fp"+raw).hexdigest()[:32].upper()
out.append('/// `display_fingerprint(0x05 || 0x01 * 32)`')
out.append(f'pub const FP_OF_05_01X32: &str = "{" ".join(fp[i:i+4] for i in range(0,32,4))}";')

# Vault: header layout per vault.rs / PROTOCOL §12, low Argon2 cost so the test is fast.
passphrase = b"lantern orbit maple quietly"
dev = bytes(range(32))
vault_id = bytes([0x11]*16); salt = bytes([0x22]*16); nonce = bytes([0x33]*24)
m, t, p = 64, 1, 1
db_key = bytes([0x44]*32)
pw = hash_secret_raw(passphrase, salt, time_cost=t, memory_cost=m, parallelism=p, hash_len=32, type=Type.ID, version=19)
kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=vault_id, info=b"veil/v1/kek").derive(pw + dev)
aad = b"VEILVLT" + bytes([1]) + vault_id + struct.pack('>III', m, t, p) + salt
wrapped = xchacha_encrypt(kek, nonce, db_key, aad)
header = aad + nonce + wrapped
out.append('/// Passphrase for `VAULT_HEADER`.')
out.append(f'pub const VAULT_PASSPHRASE: &[u8] = b"{passphrase.decode()}";')
out.append('/// Device secret for `VAULT_HEADER`.')
out.append(rs_bytes("VAULT_DEVICE_SECRET", dev))
out.append('/// DB key wrapped in `VAULT_HEADER`.')
out.append(rs_bytes("VAULT_DB_KEY", db_key))
out.append('/// A complete vault header (m=64 KiB, t=1, p=1).')
out.append(rs_bytes("VAULT_HEADER", header))

# Attachment: one STREAM-BE32 chunk (counter 0, last=1) of a padded plaintext.
att_key = bytes([0x55]*32); prefix = bytes([0x66]*19)
plain = b"hello attachment" + b"\x80"
padded_len = 17  # padme(17) == 17
plain = plain.ljust(padded_len, b"\0")
stream_nonce = prefix + struct.pack('>I', 0) + b"\x01"
ct = xchacha_encrypt(att_key, stream_nonce, plain, b"veil/v1/attachment")
out.append(rs_bytes("ATT_KEY", att_key))
out.append(rs_bytes("ATT_PREFIX", prefix))
out.append(f"pub const ATT_PLAIN_PADDED: &[u8] = &{list(plain)};")
out.append(rs_bytes("ATT_CT", ct))

# Sanity check of the HChaCha20 implementation against draft-irtf-cfrg-xchacha §2.2.1.
k = bytes(range(32)); n = bytes.fromhex("000000090000004a0000000031415927")
assert hchacha20(k, n).hex() == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc", "HChaCha20 self-test"

print("\n".join(out))
