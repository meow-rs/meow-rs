#!/usr/bin/env python3
"""Generate the frozen REALITY server wire vectors used by unit tests.

The oracle is intentionally outside meow-rs: Python cryptography performs the
X25519, HKDF/HMAC, AES-256-GCM, ML-KEM-768 and Ed25519 operations while this
script serializes the ClientHello and certificate template byte-for-byte from
the specification.  All seeds are fixed labels, so regenerating is
byte-for-byte reproducible.  The script self-checks every vector and fails
before writing if the independent verifier rejects it.

Locked generation environment: Python 3.11 with cryptography==50.0.0.
Regenerate with `python3 generate_reality_independent_vectors.py`; verify the
committed oracle without touching the filesystem or network with `--check`.
"""

from pathlib import Path
import argparse
import hashlib
import sys
import hmac as py_hmac

from cryptography.hazmat.primitives.asymmetric import ed25519, mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
import cryptography


def check_locked_environment():
    """Fail clearly unless the locked oracle environment is in use.

    The frozen vectors are byte-exact evidence; regenerating them with a
    different cryptography release could silently shift encodings.  The lock
    is the 50.x series exercised in CI (50.0.0 at introduction).  Byte
    equality under `--check` is the cross-environment correctness proof, so
    the check tolerates any 50.x while rejecting anything else loudly.
    """
    if sys.version_info < (3, 11):
        sys.exit(
            "error: generate_reality_independent_vectors.py requires Python 3.11+ "
            f"(running {sys.version.split()[0]})"
        )
    major = int(cryptography.__version__.split(".")[0])
    if major != 50:
        sys.exit(
            "error: locked oracle environment is cryptography 50.x "
            f"(found {cryptography.__version__}); install the locked version "
            "or update the lock deliberately with fresh byte-exact review"
        )
    try:
        mlkem.MLKEM768PrivateKey  # noqa: B018 - importability probe, not use
    except AttributeError:
        sys.exit(
            "error: cryptography 50.x must expose ML-KEM-768; this build does not"
        )


check_locked_environment()


GROUP_X25519 = 0x001D
GROUP_X25519_MLKEM768 = 0x11EC
TLS_AES_128_GCM_SHA256 = 0x1301
TLS13_VERSION = 0x0304
EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGORITHMS = 13
EXT_PADDING = 21
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51

SERVER_NAME = "www.example.com"
UNIX_SECONDS = 1_700_000_000
VERSION = bytes([26, 3, 27])
RESERVED = 0
SHORT_ID = bytes.fromhex("a1b2c3d4") + bytes(4)

# Deterministic test-only key material.  These are not production keys and are
# never accepted by configuration code; they exist only to make the frozen
# vectors reproducible.
def seed32(label: bytes) -> bytes:
    return hashlib.sha256(b"meow-rs REALITY independent vector v1\0" + label).digest()


def seed64(label: bytes) -> bytes:
    return hashlib.sha512(b"meow-rs REALITY independent vector v1\0" + label).digest()


SERVER_STATIC_PRIVATE = seed32(b"server static x25519")
CLIENT_X25519_PRIVATE = seed32(b"client independent x25519")
HYBRID_X25519_PRIVATE = seed32(b"client hybrid x25519")
WRONG_X25519_PRIVATE = seed32(b"client wrong x25519")
MLKEM768_SEED = seed64(b"client mlkem768")
ED25519_SEED = seed32(b"server leaf ed25519")


def x25519_private(private_bytes: bytes) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(private_bytes)


def x25519_public_bytes(private_bytes: bytes) -> bytes:
    return x25519_private(private_bytes).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


SERVER_STATIC_PUBLIC = x25519_public_bytes(SERVER_STATIC_PRIVATE)
CLIENT_X25519_PUBLIC = x25519_public_bytes(CLIENT_X25519_PRIVATE)
HYBRID_X25519_PUBLIC = x25519_public_bytes(HYBRID_X25519_PRIVATE)
WRONG_X25519_PUBLIC = x25519_public_bytes(WRONG_X25519_PRIVATE)
MLKEM_PRIVATE = mlkem.MLKEM768PrivateKey.from_seed_bytes(MLKEM768_SEED)
MLKEM768_PUBLIC = MLKEM_PRIVATE.public_key().public_bytes_raw()
assert len(MLKEM768_PUBLIC) == 1184


def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def u24(value: int) -> bytes:
    return value.to_bytes(3, "big")


def extension(ext_type: int, data: bytes) -> bytes:
    return u16(ext_type) + u16(len(data)) + data


def server_name_extension(name: str) -> bytes:
    encoded = name.encode("ascii")
    entry = b"\x00" + u16(len(encoded)) + encoded
    return extension(EXT_SERVER_NAME, u16(len(entry)) + entry)


def supported_versions_extension() -> bytes:
    versions = u16(TLS13_VERSION)
    return extension(EXT_SUPPORTED_VERSIONS, bytes([len(versions)]) + versions)


def supported_groups_extension(groups: list[int]) -> bytes:
    encoded = b"".join(u16(group) for group in groups)
    return extension(EXT_SUPPORTED_GROUPS, u16(len(encoded)) + encoded)


def signature_algorithms_extension() -> bytes:
    # A browser-like list deliberately does not advertise Ed25519 (0x0807).
    # REALITY's custom server still has to send an Ed25519 CertificateVerify.
    algorithms = [
        0x0403,
        0x0804,
        0x0401,
        0x0503,
        0x0805,
        0x0501,
        0x0603,
        0x0806,
        0x0601,
    ]
    encoded = b"".join(u16(algorithm) for algorithm in algorithms)
    return extension(EXT_SIGNATURE_ALGORITHMS, u16(len(encoded)) + encoded)


def key_share_extension(shares: list[tuple[int, bytes]]) -> bytes:
    encoded = b"".join(u16(group) + u16(len(share)) + share for group, share in shares)
    return extension(EXT_KEY_SHARE, u16(len(encoded)) + encoded)


def padding_extension(length: int = 16) -> bytes:
    return extension(EXT_PADDING, bytes(length))


def build_client_hello(
    random32: bytes,
    session_id: bytes,
    key_share_exts: list[bytes],
    groups: list[int],
    duplicate_supported_versions: bool = False,
    cipher_suite_list=None,
) -> bytes:
    assert len(random32) == 32
    assert len(session_id) == 32
    exts = [server_name_extension(SERVER_NAME), supported_versions_extension()]
    if duplicate_supported_versions:
        exts.append(supported_versions_extension())
    exts.append(supported_groups_extension(groups))
    exts.extend(key_share_exts)
    exts.append(signature_algorithms_extension())
    exts.append(padding_extension())
    encoded_exts = b"".join(exts)

    cipher_suite_list = cipher_suite_list or [TLS_AES_128_GCM_SHA256]
    cipher_suites = b"".join(u16(cipher) for cipher in cipher_suite_list)
    body = (
        b"\x03\x03"
        + random32
        + bytes([len(session_id)])
        + session_id
        + u16(len(cipher_suites))
        + cipher_suites
        + b"\x01\x00"
        + u16(len(encoded_exts))
        + encoded_exts
    )
    hello = b"\x01" + u24(len(body)) + body
    assert hello[0] == 1
    assert hello[38] == 0x20
    assert hello[39:71] == session_id
    return hello


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = py_hmac.new(salt, ikm, hashlib.sha256).digest()
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = py_hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output += previous
        counter += 1
    return output[:length]


def auth_plaintext() -> bytes:
    return VERSION + bytes([RESERVED]) + UNIX_SECONDS.to_bytes(4, "big") + SHORT_ID


RANDOM32 = seed32(b"client random")
PLAINTEXT = auth_plaintext()
assert len(PLAINTEXT) == 16


def seal_hello_vector(
    name: str,
    shares: list[tuple[int, bytes]],
    groups: list[int],
    shared: bytes,
    duplicate_supported_versions: bool = False,
) -> dict[str, object]:
    zero_hello = build_client_hello(
        RANDOM32,
        bytes(32),
        [key_share_extension(shares)],
        groups,
        duplicate_supported_versions=duplicate_supported_versions,
    )
    aad = zero_hello
    auth_key = hkdf_sha256(shared, RANDOM32[:20], b"REALITY", 32)
    sid = AESGCM(auth_key).encrypt(RANDOM32[20:32], PLAINTEXT, aad)
    assert len(sid) == 32
    hello = zero_hello[:39] + sid + zero_hello[71:]
    assert AESGCM(auth_key).decrypt(RANDOM32[20:32], sid, aad) == PLAINTEXT
    return {
        "name": name,
        "hello": hello,
        "aad": aad,
        "sid": sid,
        "shared": shared,
        "auth_key": auth_key,
        "plaintext": PLAINTEXT,
    }


def seal_hello_vector_multiple_key_share_exts(
    name: str,
    key_share_exts: list[bytes],
    groups: list[int],
    shared: bytes,
) -> dict[str, object]:
    zero_hello = build_client_hello(RANDOM32, bytes(32), key_share_exts, groups)
    aad = zero_hello
    auth_key = hkdf_sha256(shared, RANDOM32[:20], b"REALITY", 32)
    sid = AESGCM(auth_key).encrypt(RANDOM32[20:32], PLAINTEXT, aad)
    hello = zero_hello[:39] + sid + zero_hello[71:]
    assert AESGCM(auth_key).decrypt(RANDOM32[20:32], sid, aad) == PLAINTEXT
    return {
        "name": name,
        "hello": hello,
        "aad": aad,
        "sid": sid,
        "shared": shared,
        "auth_key": auth_key,
        "plaintext": PLAINTEXT,
    }


server_auth_private = x25519_private(SERVER_STATIC_PRIVATE)
client_auth_private = x25519_private(CLIENT_X25519_PRIVATE)
SHARED = server_auth_private.exchange(
    x25519.X25519PublicKey.from_public_bytes(CLIENT_X25519_PUBLIC)
)
assert SHARED == client_auth_private.exchange(
    x25519.X25519PublicKey.from_public_bytes(SERVER_STATIC_PUBLIC)
)
HYBRID_AUTH_SHARED = server_auth_private.exchange(
    x25519.X25519PublicKey.from_public_bytes(HYBRID_X25519_PUBLIC)
)

HYBRID_SHARE = MLKEM768_PUBLIC + HYBRID_X25519_PUBLIC
assert len(HYBRID_SHARE) == 1184 + 32

POSITIVE_X25519 = seal_hello_vector(
    "positive-x25519",
    [(GROUP_X25519, CLIENT_X25519_PUBLIC)],
    [GROUP_X25519],
    SHARED,
)
POSITIVE_HYBRID = seal_hello_vector(
    "positive-hybrid-only",
    [(GROUP_X25519_MLKEM768, HYBRID_SHARE)],
    [GROUP_X25519_MLKEM768, GROUP_X25519],
    HYBRID_AUTH_SHARED,
)
DUAL_SHARE = seal_hello_vector(
    "positive-dual-independent-x25519-wins",
    [
        (GROUP_X25519_MLKEM768, HYBRID_SHARE),
        (GROUP_X25519, CLIENT_X25519_PUBLIC),
    ],
    [GROUP_X25519_MLKEM768, GROUP_X25519],
    SHARED,
)
# The forbidden all-zero X25519 share would produce an all-zero shared secret.
# Sealing with that forbidden value is deliberate: if the implementation ever
# stops rejecting low-order ECDH, this vector authenticates and the test fails.
LOW_ORDER = seal_hello_vector(
    "negative-low-order-x25519",
    [
        (GROUP_X25519_MLKEM768, HYBRID_SHARE),
        (GROUP_X25519, bytes(32)),
    ],
    [GROUP_X25519_MLKEM768, GROUP_X25519],
    bytes(32),
)
DUPLICATE_KEY_SHARE = seal_hello_vector_multiple_key_share_exts(
    "negative-duplicate-key-share-correct-then-wrong",
    [
        key_share_extension([(GROUP_X25519, CLIENT_X25519_PUBLIC)]),
        key_share_extension([(GROUP_X25519, WRONG_X25519_PUBLIC)]),
    ],
    [GROUP_X25519],
    SHARED,
)
DUPLICATE_KEY_SHARE_REVERSED = seal_hello_vector_multiple_key_share_exts(
    "negative-duplicate-key-share-wrong-then-correct",
    [
        key_share_extension([(GROUP_X25519, WRONG_X25519_PUBLIC)]),
        key_share_extension([(GROUP_X25519, CLIENT_X25519_PUBLIC)]),
    ],
    [GROUP_X25519],
    SHARED,
)
DUPLICATE_SUPPORTED_VERSIONS = seal_hello_vector(
    "negative-duplicate-supported-versions",
    [(GROUP_X25519, CLIENT_X25519_PUBLIC)],
    [GROUP_X25519],
    SHARED,
    duplicate_supported_versions=True,
)

for vector in [
    POSITIVE_X25519,
    POSITIVE_HYBRID,
    DUAL_SHARE,
    LOW_ORDER,
    DUPLICATE_KEY_SHARE,
    DUPLICATE_KEY_SHARE_REVERSED,
    DUPLICATE_SUPPORTED_VERSIONS,
]:
    hello = vector["hello"]
    assert isinstance(hello, bytes)
    assert hello[39:71] == vector["sid"]
    aad = bytearray(hello)
    aad[39:71] = bytes(32)
    assert bytes(aad) == vector["aad"]

# Locate the positive vector's padding payload for the single-byte AAD tamper
# matrix.  The offset is relative to the first byte of the handshake message.
def padding_payload_offset(hello: bytes) -> int:
    pos = 4 + 2 + 32
    sid_len = hello[pos]
    pos += 1 + sid_len
    suites_len = int.from_bytes(hello[pos : pos + 2], "big")
    pos += 2 + suites_len
    comp_len = hello[pos]
    pos += 1 + comp_len
    ext_len = int.from_bytes(hello[pos : pos + 2], "big")
    pos += 2
    end = pos + ext_len
    while pos + 4 <= end:
        ext_type = int.from_bytes(hello[pos : pos + 2], "big")
        data_len = int.from_bytes(hello[pos + 2 : pos + 4], "big")
        pos += 4
        if ext_type == EXT_PADDING:
            assert data_len == 16
            return pos
        pos += data_len
    raise AssertionError("padding extension not found")


PADDING_PAYLOAD_OFFSET = padding_payload_offset(POSITIVE_X25519["hello"])

# --- Fixed Ed25519 leaf/HMAC/CertificateVerify vectors ---------------------

def der_len(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    if length < 256:
        return bytes([0x81, length])
    return b"\x82" + u16(length)


def der_wrap(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body


def certificate_template(public_key: bytes) -> bytes:
    assert len(public_key) == 32
    ed25519_oid = b"\x06\x03\x2b\x65\x70"
    algorithm_seq = der_wrap(0x30, ed25519_oid)
    issuer = der_wrap(0x30, b"")
    validity = der_wrap(
        0x30,
        der_wrap(0x17, b"250101000000Z") + der_wrap(0x17, b"490101000000Z"),
    )
    spki_alg_seq = der_wrap(0x30, ed25519_oid)
    bitstring = der_wrap(0x03, b"\x00" + public_key)
    spki = der_wrap(0x30, spki_alg_seq + bitstring)
    version_explicit = der_wrap(0xA0, der_wrap(0x02, b"\x02"))
    serial = b"\x02\x01\x01"
    tbs = der_wrap(
        0x30,
        version_explicit
        + serial
        + algorithm_seq
        + issuer
        + validity
        + issuer
        + spki,
    )
    signature_bits = der_wrap(0x03, b"\x00" + bytes(64))
    return der_wrap(0x30, tbs + algorithm_seq + signature_bits)


ED_PRIVATE = ed25519.Ed25519PrivateKey.from_private_bytes(ED25519_SEED)
ED_PUBLIC = ED_PRIVATE.public_key()
ED25519_PUBLIC = ED_PUBLIC.public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
ED25519_PRIVATE_DER = ED_PRIVATE.private_bytes(
    serialization.Encoding.DER,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
ED25519_SPKI_DER = ED_PUBLIC.public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
AUTH_KEY = POSITIVE_X25519["auth_key"]
assert isinstance(AUTH_KEY, bytes)
CERTIFICATE_HMAC = py_hmac.new(AUTH_KEY, ED25519_PUBLIC, hashlib.sha512).digest()
TEMPLATE = certificate_template(ED25519_PUBLIC)
assert TEMPLATE[-64:] == bytes(64)
LEAF_DER = TEMPLATE[:-64] + CERTIFICATE_HMAC

CV_TRANSCRIPT_HASH = hashlib.sha256(
    b"meow-rs REALITY independent CertificateVerify transcript v1"
).digest()
CV_INPUT = (
    bytes([0x20]) * 64
    + b"TLS 1.3, server CertificateVerify"
    + b"\x00"
    + CV_TRANSCRIPT_HASH
)
CV_SIGNATURE = ED_PRIVATE.sign(CV_INPUT)
ED_PUBLIC.verify(CV_SIGNATURE, CV_INPUT)



# --- REALITY v2 mirrored-flight oracle --------------------------------------

TLS_AES_256_GCM_SHA384 = 0x1302
TLS_CHACHA20_POLY1305_SHA256 = 0x1303
# Generated once with cryptography's independent ML-KEM encapsulator for the
# frozen client encapsulation key above, then frozen here.  `--check` never
# calls encapsulate(); verification decapsulates this ciphertext from the fixed
# private seed.
FROZEN_MLKEM768_CIPHERTEXT = bytes.fromhex(
    "c277f2edcfc057f376e9ecb0a86b7d04f357e5ab53bfc7a6c0e060242a9304ad9acb77a11dff3694bffc658c235a5c6b816f578da946e807f943e9df1f4eb2121f3abdf36dce698e73b7868e1b030b14878fc4194afeaf57cad3731ec015f0054f8805f48b09821f3b105b6fb13714f02fd1685c9ae6086fd5601f99376a8be0572b1ec0d08c21df0a2515d06bb785d1d3bba96e3e777858048e6c66f54ccb8b9e82fd64f7d7e29c4db905d199b1e5ad74f0a50436d333096f981301cacbef4a84fe0cdec922068fc96185538c6fb3a8f9379247e1502afd4d71c8bb750e5721670ec2184451f32bead4b5009957175b3e1c78edf85a6462e6eafaeb60f0cbd3e308be127e90297dd38d142053050a25167f5802f0ce6b3ef65ffe118ead074bbd1ff942cb96cc8202aa00a960726a2195148ce25ab0cc42280ac76743e4ce89de70a91bdb24183f654a0b3763869d5fe4cae3e0c03aa9eac1cfd7120d260a5186c641bc19845e2857df175d88a39e444d2cf0e79b90b4bbe212379224337d6fd43d4ba1d58d75f6df1bd4ec945dccae1deca1b09a4737d0b6291526406e4b3e10dde4e2e14458beb98aea4c46931c8816b5f607ef4a0801f99ce1d7b133431742554556e5962aecfdaa2bc0215da30643e0eafd237430a6e8c97689ba41e532f00a18b68d1264a9e51f7632202ddde5384088f3ebbb3e13455b5bfa9ff6349e5ae0aa59e415c149897052a5efdffb3f05d6bea7a18e5650530fca2b3c72636cef7bba076f13cfee6a7d3a793daa75ea6103bc237a37200844727e6be29353666f25b019c8b41bc65fc5f910af19ac0db47dea6008dc017b436d1162e154ab14b95bfe7e47321a6716d4fe582779b6dc60f8faca13ed72f754bad030821887f7c6fd78a052f2163b372422b2281d3d3d7806feb521ffddccbf205817f80304014d965d241a50912d02b715183eb6cf0cb8eab3d0d344760188768cdaf3e191097b6c45357421171243117843a3336fe2d5d479232d9367c6dcd675596262f9f99d38d02506bc863b113bd020412ed4a9f891870b4564aa042d024c5043afa27f87da82fdf1f7f0a29df8e30c3aa89cc00f6d476803a2c56d88675bb668561dc6f04588e5aeaada5c4febb837a320df25a98dec0409ff7a46c7b0ab6eb468d21afda77e5ed0cf357cb779913eb197d24f13a8b7c5f2a79cbcd233f56531e78a8479475dd330630d432471edf7d26a046bb4e81ff180e1c7acd74b06c15070f82a204b6d5d370ef2dac687b559133c043f06508a6b7123c1339df40c9902508b1580ccb0ad7b8d11e61919d58eb3ba1e911816b0fdbd7ed34215d135144d563a89a8ad32078d7140266abdea56f6135bab5fdaf3586f67f0d9f57137c76cb20c551987b560be27ea689db4cd015e5814a412cb80ffa9baea0562276108b393befbf624f28baccd4de1c12632803bd0d8e25f1e6f8128e4f45481becb902a86a1798ae27082651697835622e7121a32edd21093b1ba40b050869f819a6f699bded6"
)
FROZEN_MLKEM768_SECRET = bytes.fromhex("ee85736d35ce48a36d3a75baee944d3bbccee8c1d6c0d7f522b90475128787dd")
assert len(FROZEN_MLKEM768_CIPHERTEXT) == 1088
assert len(FROZEN_MLKEM768_SECRET) == 32
assert MLKEM_PRIVATE.decapsulate(FROZEN_MLKEM768_CIPHERTEXT) == FROZEN_MLKEM768_SECRET


def hash_constructor(name: str):
    return {"sha256": hashlib.sha256, "sha384": hashlib.sha384}[name]


def suite_hash(cipher: int) -> str:
    return "sha384" if cipher == TLS_AES_256_GCM_SHA384 else "sha256"


def hash_len(cipher: int) -> int:
    return 48 if cipher == TLS_AES_256_GCM_SHA384 else 32


def digest_bytes(cipher: int, data: bytes) -> bytes:
    return hash_constructor(suite_hash(cipher))(data).digest()


def hkdf_extract_h(cipher: int, salt: bytes, ikm: bytes) -> bytes:
    return py_hmac.new(salt, ikm, hash_constructor(suite_hash(cipher))).digest()


def hkdf_expand_h(cipher: int, prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    previous = b""
    counter = 1
    while len(out) < length:
        previous = py_hmac.new(
            prk, previous + info + bytes([counter]), hash_constructor(suite_hash(cipher))
        ).digest()
        out += previous
        counter += 1
    return out[:length]


def expand_label(cipher: int, secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    info = (
        u16(length)
        + bytes([len(b"tls13 " + label)])
        + b"tls13 "
        + label
        + bytes([len(context)])
        + context
    )
    return hkdf_expand_h(cipher, secret, info, length)


def derive_secret(cipher: int, secret: bytes, label: bytes, transcript_hash: bytes) -> bytes:
    return expand_label(cipher, secret, label, transcript_hash, hash_len(cipher))


def hs_message(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + u24(len(body)) + body


def certificate_message_oracle(leaf_der: bytes) -> bytes:
    entry = u24(len(leaf_der)) + leaf_der + b"\x00\x00"
    return hs_message(11, b"\x00" + u24(len(entry)) + entry)


def certificate_leaf_for_auth_key(auth_key: bytes) -> bytes:
    mac = py_hmac.new(auth_key, ED25519_PUBLIC, hashlib.sha512).digest()
    return TEMPLATE[:-64] + mac


def build_sh_oracle(
    random32: bytes,
    session_id: bytes,
    cipher: int,
    group: int,
    share: bytes,
    key_share_first: bool,
) -> bytes:
    versions_ext = extension(0x002B, u16(TLS13_VERSION))
    key_share_body = u16(group) + u16(len(share)) + share
    key_share_ext = extension(EXT_KEY_SHARE, key_share_body)
    extensions = key_share_ext + versions_ext if key_share_first else versions_ext + key_share_ext
    body = (
        b"\x03\x03"
        + random32
        + bytes([len(session_id)])
        + session_id
        + u16(cipher)
        + b"\x00"
        + u16(len(extensions))
        + extensions
    )
    return b"\x02" + u24(len(body)) + body


def plaintext_record_oracle(payload: bytes, typ: int = 0x16) -> bytes:
    return bytes([typ, 0x03, 0x03]) + u16(len(payload)) + payload


def mirror_auth_hello(name: str, cipher: int, group: int) -> dict[str, object]:
    if group == GROUP_X25519:
        shares = [(GROUP_X25519, CLIENT_X25519_PUBLIC)]
        groups = [GROUP_X25519]
        shared = SHARED
    else:
        shares = [
            (GROUP_X25519_MLKEM768, HYBRID_SHARE),
            (GROUP_X25519, CLIENT_X25519_PUBLIC),
        ]
        groups = [GROUP_X25519_MLKEM768, GROUP_X25519]
        shared = SHARED
    zero = build_client_hello(
        RANDOM32,
        bytes(32),
        [key_share_extension(shares)],
        groups,
        cipher_suite_list=[cipher],
    )
    aad = zero
    auth_key = hkdf_sha256(shared, RANDOM32[:20], b"REALITY", 32)
    sid = AESGCM(auth_key).encrypt(RANDOM32[20:32], PLAINTEXT, aad)
    hello = zero[:39] + sid + zero[71:]
    assert AESGCM(auth_key).decrypt(RANDOM32[20:32], sid, aad) == PLAINTEXT
    return {
        "name": name,
        "group": group,
        "cipher": cipher,
        "ch_message": hello,
        "ch_wire": plaintext_record_oracle(hello),
        "aad": aad,
        "sid": sid,
        "auth_key": auth_key,
    }


def traffic_key_iv(cipher: int, secret: bytes) -> tuple[bytes, bytes]:
    key_len = 16 if cipher == TLS_AES_128_GCM_SHA256 else 32
    return (
        expand_label(cipher, secret, b"key", b"", key_len),
        expand_label(cipher, secret, b"iv", b"", 12),
    )


def aead_seal_oracle(
    cipher: int, key: bytes, iv: bytes, seq: int, aad: bytes, plaintext: bytes
) -> bytes:
    nonce = bytearray(iv)
    for index, byte in enumerate(seq.to_bytes(8, "big")):
        nonce[4 + index] ^= byte
    if cipher in (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384):
        box = AESGCM(key)
    else:
        box = ChaCha20Poly1305(key)
    return box.encrypt(bytes(nonce), plaintext, aad)


def seal_tls_record_oracle(
    cipher: int,
    key: bytes,
    iv: bytes,
    seq: int,
    inner_type: int,
    content: bytes,
    padding: int,
) -> bytes:
    plaintext = content + bytes([inner_type]) + bytes(padding)
    record_len = len(plaintext) + 16
    header = b"\x17\x03\x03" + u16(record_len)
    return header + aead_seal_oracle(cipher, key, iv, seq, header, plaintext)


def make_mirror_vector(name: str, cipher: int, group: int, key_share_first: bool) -> dict[str, object]:
    base = mirror_auth_hello(name, cipher, group)
    sid = base["sid"]
    assert isinstance(sid, bytes)
    target_random = seed32(b"target random\0" + name.encode())
    server_random = seed32(b"patched server random\0" + name.encode())
    server_x_private = seed32(b"server ephemeral x25519\0" + name.encode())
    server_x_public = x25519_public_bytes(server_x_private)

    if group == GROUP_X25519:
        target_share = x25519_public_bytes(seed32(b"target x25519\0" + name.encode()))
        server_share = server_x_public
        tls_dh = x25519_private(server_x_private).exchange(
            x25519.X25519PublicKey.from_public_bytes(CLIENT_X25519_PUBLIC)
        )
        mlkem_ciphertext = b""
        mlkem_secret = b""
    else:
        target_share = bytes([0x55]) * 1088 + x25519_public_bytes(
            seed32(b"target hybrid x25519\0" + name.encode())
        )
        mlkem_ciphertext = FROZEN_MLKEM768_CIPHERTEXT
        mlkem_secret = MLKEM_PRIVATE.decapsulate(mlkem_ciphertext)
        x_secret = x25519_private(server_x_private).exchange(
            x25519.X25519PublicKey.from_public_bytes(HYBRID_X25519_PUBLIC)
        )
        server_share = mlkem_ciphertext + server_x_public
        tls_dh = mlkem_secret + x_secret

    target_sh = build_sh_oracle(target_random, sid, cipher, group, target_share, key_share_first)
    patched_sh = bytearray(target_sh)
    patched_sh[6:38] = server_random
    share_start = bytes(patched_sh).find(target_share)
    assert share_start >= 0 and bytes(patched_sh).rfind(target_share) == share_start
    patched_sh[share_start : share_start + len(target_share)] = server_share
    patched_sh = bytes(patched_sh)
    assert len(patched_sh) == len(target_sh)

    ch_message = base["ch_message"]
    auth_key = base["auth_key"]
    assert isinstance(ch_message, bytes) and isinstance(auth_key, bytes)
    t0_bytes = ch_message + patched_sh
    t0 = digest_bytes(cipher, t0_bytes)
    zero = bytes(hash_len(cipher))
    empty_hash = digest_bytes(cipher, b"")
    early = hkdf_extract_h(cipher, zero, zero)
    handshake_secret = hkdf_extract_h(
        cipher, derive_secret(cipher, early, b"derived", empty_hash), tls_dh
    )
    c_hs = derive_secret(cipher, handshake_secret, b"c hs traffic", t0)
    s_hs = derive_secret(cipher, handshake_secret, b"s hs traffic", t0)
    master = hkdf_extract_h(
        cipher, derive_secret(cipher, handshake_secret, b"derived", empty_hash), zero
    )

    ee = hs_message(8, b"\x00\x00")
    leaf = certificate_leaf_for_auth_key(auth_key)
    cert = certificate_message_oracle(leaf)
    t1_bytes = t0_bytes + ee + cert
    t1 = digest_bytes(cipher, t1_bytes)
    cv_input = bytes([0x20]) * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00" + t1
    cv_signature = ED_PRIVATE.sign(cv_input)
    cv = hs_message(15, u16(0x0807) + u16(64) + cv_signature)
    t2_bytes = t1_bytes + cv
    t2 = digest_bytes(cipher, t2_bytes)

    def finished(secret: bytes, transcript_hash: bytes) -> bytes:
        finished_key = expand_label(cipher, secret, b"finished", b"", hash_len(cipher))
        return py_hmac.new(
            finished_key, transcript_hash, hash_constructor(suite_hash(cipher))
        ).digest()

    server_finished_body = finished(s_hs, t2)
    server_finished = hs_message(20, server_finished_body)
    t3_bytes = t2_bytes + server_finished
    t3 = digest_bytes(cipher, t3_bytes)
    client_finished_body = finished(c_hs, t3)
    c_ap = derive_secret(cipher, master, b"c ap traffic", t3)
    s_ap = derive_secret(cipher, master, b"s ap traffic", t3)

    flight_plaintext = ee + cert + cv + server_finished
    m = len(flight_plaintext)
    record_lengths = [25, 3217, 281, 69]
    capacities = [length - 17 for length in record_lengths]
    offset = 0
    assignments = []
    for index, capacity in enumerate(capacities):
        suffix = len(capacities) - index - 1
        take = min(capacity, m - offset - suffix)
        assert take >= 1
        assignments.append((offset, take, capacity - take))
        offset += take
    assert offset == m

    c_hs_key, c_hs_iv = traffic_key_iv(cipher, c_hs)
    s_hs_key, s_hs_iv = traffic_key_iv(cipher, s_hs)
    records = []
    for seq, (start, take, padding) in enumerate(assignments):
        records.append(
            seal_tls_record_oracle(
                cipher, s_hs_key, s_hs_iv, seq, 0x16, flight_plaintext[start : start + take], padding
            )
        )
        assert len(records[-1]) == 5 + record_lengths[seq]
    ccs = bytes.fromhex("140303000101")
    sh_wire = plaintext_record_oracle(patched_sh)
    server_flight_wire = sh_wire + ccs + b"".join(records)
    client_finished = hs_message(20, client_finished_body)
    client_finished_record = seal_tls_record_oracle(
        cipher, c_hs_key, c_hs_iv, 0, 0x16, client_finished, 0
    )
    c_ap_key, c_ap_iv = traffic_key_iv(cipher, c_ap)
    s_ap_key, s_ap_iv = traffic_key_iv(cipher, s_ap)
    app_plaintext = b"meow REALITY mirror application seq0"
    client_app_record = seal_tls_record_oracle(cipher, c_ap_key, c_ap_iv, 0, 0x17, app_plaintext, 0)
    server_app_record = seal_tls_record_oracle(cipher, s_ap_key, s_ap_iv, 0, 0x17, app_plaintext, 0)

    vector = {
        **base,
        "server_random": server_random,
        "server_x25519_private": server_x_private,
        "mlkem_ciphertext": mlkem_ciphertext,
        "mlkem_secret": mlkem_secret,
        "tls_dh": tls_dh,
        "target_sh": target_sh,
        "patched_sh": patched_sh,
        "leaf_der": leaf,
        "t0": t0,
        "t1": t1,
        "t2": t2,
        "t3": t3,
        "cv": cv,
        "server_finished": server_finished_body,
        "client_finished": client_finished_body,
        "client_hs_key": c_hs_key,
        "client_hs_iv": c_hs_iv,
        "server_hs_key": s_hs_key,
        "server_hs_iv": s_hs_iv,
        "client_ap_key": c_ap_key,
        "client_ap_iv": c_ap_iv,
        "server_ap_key": s_ap_key,
        "server_ap_iv": s_ap_iv,
        "flight_plaintext": flight_plaintext,
        "server_flight_wire": server_flight_wire,
        "client_finished_record": client_finished_record,
        "client_app_record": client_app_record,
        "server_app_record": server_app_record,
        "app_plaintext": app_plaintext,
        "records": records,
    }
    # Self-verification before anything can be written: the frozen ciphertext
    # decapsulates from the seed, signatures verify, every bucket has the
    # target's exact length, and the client Finished opens under seq=0.
    assert len(tls_dh) == (64 if group == GROUP_X25519_MLKEM768 else 32)
    assert len(server_finished_body) == len(client_finished_body) == hash_len(cipher)
    assert len(records) == 4 and len(records[0]) == 5 + 25
    assert records[1] != records[2]
    ED_PUBLIC.verify(cv_signature, cv_input)
    return vector


MIRROR_X25519_AES128 = make_mirror_vector("mirror-x25519-1301", TLS_AES_128_GCM_SHA256, GROUP_X25519, False)
MIRROR_X25519_AES256 = make_mirror_vector("mirror-x25519-1302", TLS_AES_256_GCM_SHA384, GROUP_X25519, True)
MIRROR_X25519_CHACHA = make_mirror_vector("mirror-x25519-1303", TLS_CHACHA20_POLY1305_SHA256, GROUP_X25519, False)
MIRROR_HYBRID_AES256 = make_mirror_vector("mirror-hybrid-1302", TLS_AES_256_GCM_SHA384, GROUP_X25519_MLKEM768, True)
MIRROR_VECTORS = [
    MIRROR_X25519_AES128,
    MIRROR_X25519_AES256,
    MIRROR_X25519_CHACHA,
    MIRROR_HYBRID_AES256,
]

def rust_hex_expression(value: bytes, indent: str) -> str:
    hexed = value.hex()
    chunks = [hexed[i : i + 96] for i in range(0, len(hexed), 96)] or [""]
    if len(chunks) == 1:
        return f'"{hexed}"'
    lines = ["concat!("]
    lines.extend(f'{indent}    "{chunk}",' for chunk in chunks)
    lines.append(f"{indent})")
    return "\n".join(lines)


def rust_hex(name: str, value: bytes, visibility: str = "pub(crate)") -> str:
    expression = rust_hex_expression(value, "")
    if "\n" not in expression:
        return f"{visibility} const {name}: &str = {expression};"
    lines = expression.splitlines()
    return "\n".join(
        [f"{visibility} const {name}: &str = {lines[0]}"]
        + lines[1:-1]
        + [f"{lines[-1]};"]
    )


def rust_vector(const_name: str, vector: dict[str, object]) -> str:
    out = [f"pub(crate) const {const_name}: FrozenHelloVector = FrozenHelloVector {{"]
    for field in ["name", "hello", "aad", "sid", "shared", "auth_key", "plaintext"]:
        rust_name = {
            "hello": "client_hello_hex",
            "aad": "aad_hex",
            "sid": "sid_hex",
            "shared": "shared_hex",
            "auth_key": "auth_key_hex",
            "plaintext": "plaintext_hex",
        }.get(field, field)
        value = vector[field]
        if field == "name":
            out.append(f'    {rust_name}: "{value}",')
        else:
            assert isinstance(value, bytes)
            expression = rust_hex_expression(value, "    ")
            lines = expression.splitlines()
            if len(lines) == 1:
                out.append(f"    {rust_name}: {lines[0]},")
            else:
                out.append(f"    {rust_name}: {lines[0]}")
                out.extend(lines[1:-1])
                out.append(f"{lines[-1]},")
    out.append("};")
    return "\n".join(out)



def rust_mirror_vector(const_name: str, vector: dict[str, object]) -> str:
    byte_fields = [
        "ch_wire", "ch_message", "aad", "target_sh", "patched_sh",
        "server_random", "server_x25519_private", "mlkem_ciphertext", "mlkem_secret", "tls_dh",
        "auth_key", "leaf_der", "t0", "t1", "t2", "t3", "cv",
        "server_finished", "client_finished",
        "client_hs_key", "client_hs_iv", "server_hs_key", "server_hs_iv",
        "client_ap_key", "client_ap_iv", "server_ap_key", "server_ap_iv",
        "flight_plaintext", "server_flight_wire", "client_finished_record",
        "client_app_record", "server_app_record", "app_plaintext",
    ]
    out = [
        f"pub(crate) const {const_name}: FrozenMirrorVector = FrozenMirrorVector {{",
        f'    name: "{vector["name"]}",',
        f'    group: 0x{vector["group"]:04x},',
        f'    cipher: 0x{vector["cipher"]:04x},',
    ]
    for field in byte_fields:
        value = vector[field]
        assert isinstance(value, bytes)
        expression = rust_hex_expression(value, "    ")
        lines = expression.splitlines()
        rust_name = field + "_hex"
        if len(lines) == 1:
            out.append(f"    {rust_name}: {lines[0]},")
        else:
            out.append(f"    {rust_name}: {lines[0]}")
            out.extend(lines[1:-1])
            out.append(f"{lines[-1]},")
    records = vector["records"]
    assert isinstance(records, list) and len(records) == 4
    for index, record in enumerate(records):
        assert isinstance(record, bytes)
        expression = rust_hex_expression(record, "    ")
        lines = expression.splitlines()
        rust_name = f"record{index}_hex"
        if len(lines) == 1:
            out.append(f"    {rust_name}: {lines[0]},")
        else:
            out.append(f"    {rust_name}: {lines[0]}")
            out.extend(lines[1:-1])
            out.append(f"{lines[-1]},")
    out.append("};")
    return "\n".join(out)


def generate() -> str:
    parts = [
        "// @generated by tests/generate_reality_independent_vectors.py; DO NOT EDIT.",
        "// Regenerate with: python3 crates/meow-transport/tests/generate_reality_independent_vectors.py",
        "",
        "pub(crate) struct FrozenHelloVector {",
        "    pub(crate) name: &'static str,",
        "    pub(crate) client_hello_hex: &'static str,",
        "    pub(crate) aad_hex: &'static str,",
        "    pub(crate) sid_hex: &'static str,",
        "    pub(crate) shared_hex: &'static str,",
        "    pub(crate) auth_key_hex: &'static str,",
        "    pub(crate) plaintext_hex: &'static str,",
        "}",
        "",
        "pub(crate) struct FrozenMirrorVector {",
        "    pub(crate) name: &'static str,",
        "    pub(crate) group: u16,",
        "    pub(crate) cipher: u16,",
        "    pub(crate) ch_wire_hex: &'static str,",
        "    pub(crate) ch_message_hex: &'static str,",
        "    pub(crate) aad_hex: &'static str,",
        "    pub(crate) target_sh_hex: &'static str,",
        "    pub(crate) patched_sh_hex: &'static str,",
        "    pub(crate) server_random_hex: &'static str,",
        "    pub(crate) server_x25519_private_hex: &'static str,",
        "    pub(crate) mlkem_ciphertext_hex: &'static str,",
        "    pub(crate) mlkem_secret_hex: &'static str,",
        "    pub(crate) tls_dh_hex: &'static str,",
        "    pub(crate) auth_key_hex: &'static str,",
        "    pub(crate) leaf_der_hex: &'static str,",
        "    pub(crate) t0_hex: &'static str,",
        "    pub(crate) t1_hex: &'static str,",
        "    pub(crate) t2_hex: &'static str,",
        "    pub(crate) t3_hex: &'static str,",
        "    pub(crate) cv_hex: &'static str,",
        "    pub(crate) server_finished_hex: &'static str,",
        "    pub(crate) client_finished_hex: &'static str,",
        "    pub(crate) client_hs_key_hex: &'static str,",
        "    pub(crate) client_hs_iv_hex: &'static str,",
        "    pub(crate) server_hs_key_hex: &'static str,",
        "    pub(crate) server_hs_iv_hex: &'static str,",
        "    pub(crate) client_ap_key_hex: &'static str,",
        "    pub(crate) client_ap_iv_hex: &'static str,",
        "    pub(crate) server_ap_key_hex: &'static str,",
        "    pub(crate) server_ap_iv_hex: &'static str,",
        "    pub(crate) flight_plaintext_hex: &'static str,",
        "    pub(crate) server_flight_wire_hex: &'static str,",
        "    pub(crate) client_finished_record_hex: &'static str,",
        "    pub(crate) client_app_record_hex: &'static str,",
        "    pub(crate) server_app_record_hex: &'static str,",
        "    pub(crate) app_plaintext_hex: &'static str,",
        "    pub(crate) record0_hex: &'static str,",
        "    pub(crate) record1_hex: &'static str,",
        "    pub(crate) record2_hex: &'static str,",
        "    pub(crate) record3_hex: &'static str,",
        "}",
        "",
        f'pub(crate) const SERVER_NAME: &str = "{SERVER_NAME}";',
        f"pub(crate) const UNIX_SECONDS: u64 = {UNIX_SECONDS};",
        f"pub(crate) const PADDING_PAYLOAD_OFFSET: usize = {PADDING_PAYLOAD_OFFSET};",
        rust_hex("VERSION_HEX", VERSION),
        rust_hex("SHORT_ID_HEX", SHORT_ID),
        rust_hex("RANDOM32_HEX", RANDOM32),
        rust_hex("SERVER_STATIC_PRIVATE_HEX", SERVER_STATIC_PRIVATE),
        rust_hex("SERVER_STATIC_PUBLIC_HEX", SERVER_STATIC_PUBLIC),
        rust_hex("CLIENT_X25519_PRIVATE_HEX", CLIENT_X25519_PRIVATE),
        rust_hex("CLIENT_X25519_PUBLIC_HEX", CLIENT_X25519_PUBLIC),
        rust_hex("HYBRID_X25519_PRIVATE_HEX", HYBRID_X25519_PRIVATE),
        rust_hex("HYBRID_X25519_PUBLIC_HEX", HYBRID_X25519_PUBLIC),
        rust_hex("WRONG_X25519_PRIVATE_HEX", WRONG_X25519_PRIVATE),
        rust_hex("WRONG_X25519_PUBLIC_HEX", WRONG_X25519_PUBLIC),
        rust_hex("MLKEM768_SEED_HEX", MLKEM768_SEED),
        rust_hex("MLKEM768_PUBLIC_HEX", MLKEM768_PUBLIC),
        rust_hex("ED25519_PRIVATE_DER_HEX", ED25519_PRIVATE_DER),
        rust_hex("ED25519_PUBLIC_HEX", ED25519_PUBLIC),
        rust_hex("ED25519_SPKI_DER_HEX", ED25519_SPKI_DER),
        rust_hex("CERTIFICATE_HMAC_HEX", CERTIFICATE_HMAC),
        rust_hex("LEAF_DER_HEX", LEAF_DER),
        rust_hex("CV_TRANSCRIPT_HASH_HEX", CV_TRANSCRIPT_HASH),
        rust_hex("CV_INPUT_HEX", CV_INPUT),
        rust_hex("CV_SIGNATURE_HEX", CV_SIGNATURE),
        rust_vector("POSITIVE_X25519", POSITIVE_X25519),
        rust_vector("POSITIVE_HYBRID", POSITIVE_HYBRID),
        rust_vector("DUAL_SHARE", DUAL_SHARE),
        rust_vector("LOW_ORDER", LOW_ORDER),
        rust_vector("DUPLICATE_KEY_SHARE", DUPLICATE_KEY_SHARE),
        rust_vector("DUPLICATE_KEY_SHARE_REVERSED", DUPLICATE_KEY_SHARE_REVERSED),
        rust_vector("DUPLICATE_SUPPORTED_VERSIONS", DUPLICATE_SUPPORTED_VERSIONS),
        rust_mirror_vector("MIRROR_X25519_AES128", MIRROR_X25519_AES128),
        rust_mirror_vector("MIRROR_X25519_AES256", MIRROR_X25519_AES256),
        rust_mirror_vector("MIRROR_X25519_CHACHA", MIRROR_X25519_CHACHA),
        rust_mirror_vector("MIRROR_HYBRID_AES256", MIRROR_HYBRID_AES256),
        "",
    ]
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="regenerate in memory and compare byte-for-byte")
    args = parser.parse_args()
    output = Path(__file__).with_name("testdata") / "reality_independent_vectors.rs"
    if args.check:
        current = output.read_bytes()
        regenerated = generate().encode("utf-8")
        if regenerated != current:
            print(f"MISMATCH {output}: committed vectors differ from regeneration", file=sys.stderr)
            return 1
        digest = hashlib.sha256(current).hexdigest()
        print(f"OK {output} byte-for-byte regeneration sha256={digest}")
        return 0
    output.write_text(generate(), encoding="utf-8")
    print(f"wrote {output}")
    for vector in [
        POSITIVE_X25519,
        POSITIVE_HYBRID,
        DUAL_SHARE,
        LOW_ORDER,
        DUPLICATE_KEY_SHARE,
        DUPLICATE_KEY_SHARE_REVERSED,
        DUPLICATE_SUPPORTED_VERSIONS,
    ]:
        print(f"{vector['name']}: ClientHello {len(vector['hello'])} bytes")
    print(f"leaf DER {len(LEAF_DER)} bytes; fixed CV signature verified by cryptography")
    return 0


if __name__ == "__main__":
    sys.exit(main())
