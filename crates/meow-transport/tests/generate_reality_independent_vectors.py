#!/usr/bin/env python3
"""Generate the frozen REALITY server wire vectors used by unit tests.

The oracle is intentionally outside meow-rs: Python cryptography performs the
X25519, HKDF/HMAC, AES-256-GCM, ML-KEM-768 and Ed25519 operations while this
script serializes the ClientHello and certificate template byte-for-byte from
the specification.  All seeds are fixed labels, so regenerating is
byte-for-byte reproducible.  The script self-checks every vector and fails
before writing if the independent verifier rejects it.
"""

from pathlib import Path
import hashlib
import hmac as py_hmac

from cryptography.hazmat.primitives.asymmetric import ed25519, mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization


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

    cipher_suites = u16(TLS_AES_128_GCM_SHA256)
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
        "",
    ]
    return "\n".join(parts)


def main() -> None:
    output = Path(__file__).with_name("testdata") / "reality_independent_vectors.rs"
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


if __name__ == "__main__":
    main()
