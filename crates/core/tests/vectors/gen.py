"""Independent oracle for veil-core known-answer vectors.

Uses only Python stdlib + argon2-cffi + pyca/cryptography. Implements HChaCha20 and the
STREAM (BE32) nonce layout directly from their specifications, so these vectors do not
depend on any Rust code under test. Run:  python3 gen.py > vectors.rs
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
       "//! this crate, so tests compare against an outside oracle.",
       "//! Regenerate: `cd crates/core/tests/vectors && python3 gen.py > vectors.rs`.", ""]

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

# Attachment, multi-chunk (review L7): 150 000 bytes -> Padme -> 3 STREAM-BE32 chunks.
def padme(L):
    if L < 2: return L
    E = L.bit_length() - 1
    S = E.bit_length()
    mask = (1 << (E - S)) - 1
    return (L + mask) & ~mask
CHUNK = 64 * 1024
size = 150_000
data = bytes((i * 7 + 3) % 256 for i in range(size))
padded = padme(size + 1)
plain = (data + b"\x80").ljust(padded, b"\0")
chunks = [plain[i:i + CHUNK] for i in range(0, len(plain), CHUNK)]
ct = b"".join(
    xchacha_encrypt(att_key, prefix + struct.pack('>I', i) + (b"\x01" if i == len(chunks) - 1 else b"\x00"), c, b"veil/v1/attachment")
    for i, c in enumerate(chunks))
out.append("/// Multi-chunk attachment: plaintext byte i = (7i + 3) mod 256, same key and prefix as above.")
out.append(f"pub const ATT2_SIZE: u64 = {size:_};")
out.append(f"pub const ATT2_PADDED: u64 = {padded:_};")
out.append(f"pub const ATT2_CHUNKS: u32 = {len(chunks)};")
out.append(f"pub const ATT2_CT_LEN: u64 = {len(ct):_};")
out.append(rs_bytes("ATT2_CT_SHA256", hashlib.sha256(ct).digest()))

# Safety numbers (review L7): libsignal numeric fingerprint v2, written from the algorithm:
# per side h = SHA-512(0x0000 || key || id || key), then 5199 x h = SHA-512(h || key);
# first 30 bytes -> six 5-byte big-endian numbers mod 100000; smaller string first.
def fp_half(key, ident, iterations=5200):
    h = hashlib.sha512(b"\0\0" + key + ident + key).digest()
    for _ in range(iterations - 1):
        h = hashlib.sha512(h + key).digest()
    return h
def fp_digits(h):
    return "".join(f"{int.from_bytes(h[i:i + 5], 'big') % 100000:05d}" for i in range(0, 30, 5))
def safety_number(k1, id1, k2, id2):
    a, b = fp_digits(fp_half(k1, id1)), fp_digits(fp_half(k2, id2))
    return a + b if a < b else b + a
# Self-test against the vector published in libsignal's own test-suite (phone-number ids).
ka = bytes.fromhex("0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868")
kb = bytes.fromhex("05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b")
assert safety_number(ka, b"+14152222222", kb, b"+14153333333") == "300354477692869396892869876765458257569162576843440918079131", "fingerprint self-test"
addr = lambda k: ("v1:" + hashlib.sha256(b"veil/v1/addr" + k).hexdigest()[:40]).encode()
out.append("/// Two valid identity keys (from libsignal's test-suite) and their Veil safety number.")
out.append(rs_bytes("SAFETY_KEY_A", ka))
out.append(rs_bytes("SAFETY_KEY_B", kb))
out.append(f'pub const SAFETY_DIGITS: &str = "{safety_number(ka, addr(ka), kb, addr(kb))}";')

# Sanity check of the HChaCha20 implementation against draft-irtf-cfrg-xchacha §2.2.1.
k = bytes(range(32)); n = bytes.fromhex("000000090000004a0000000031415927")
assert hchacha20(k, n).hex() == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc", "HChaCha20 self-test"

print("\n".join(out))
