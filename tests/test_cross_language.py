"""
Cross-language tests for the default Encryptor (AES-256-GCM).

Every member of the family (GoCrypt, NodeCrypt, RustCrypt, PHPCrypt, PyCrypt)
writes the same wire format:

    base64( salt(16) || nonce(12) || ciphertext || tag(16) )

with the key derived by PBKDF2-HMAC-SHA256 (10000 iterations, 32 bytes).
Round-tripping inside PyCrypt alone cannot catch a format drift, so these
tests pin PyCrypt against values produced by the other implementations.
"""

import base64

import pytest

from pycrypt import Encryptor


# Produced by GoCrypt v1.0.0 (commit 2599b0a) via RustCrypt's
# scripts/gen-vectors, file tests/fixtures/gocrypt_vectors.json.
GOCRYPT_PASSWORD = "rustcrypt-test-2026"

GOCRYPT_VECTORS = [
    (
        "hello",
        "ENC(kU/jNgiOOc9euKgZ2vAjYlpKoahu4KXaaoJ8XL75fs2AwbzwVRF4d2ey0pqQdVNT5Q==)",
    ),
    (
        "Password123!",
        "ENC(USVMu7W75yYW2qdlQ7EW7ZD1Zdqs1FekaJ76froL3O/qT+qwTp9hBgV6OnqHbIWs6GlG07Sn7y4=)",
    ),
    (
        "0123456789" * 20,
        "ENC(O8BSZmxvPDR3ToSBkqaxCUcdL+mFfxTtSW2g5vug1FK+KHWm8Zf57ySNE7HAHyc7X7yn6adbnBWN"
        "+eWHWQgFA1bvvPbUMswKsTfZZ4QFzVgXGAR4R8eyLA1mFBx218eEgIIJE+8fMzY/dMa8y5+4PW0JwDfK"
        "LT/lYcrhCeapOJIlYqoyNyxRtt7j+TXDIgnptQTiOuVXrQepLWOkFnoFQEiDMcvyGQzwytop3DvZmXI5"
        "qslqYaOOBrxos4FYoRtINw2MWLVbBNu1C8VOhH4syiS0WuFlu9tPX8NwnVZ3Wx5WXCfbODWNKwq47e5s"
        "JG/TiLVs+g==)",
    ),
    (
        "Selamat pagi, Fariz \U0001F980",
        "ENC(jNozHiCOJXeffgcqMd30IPii41YZzmNYG8Trv0EdqDN4IxD6EOquGrz1GCh80MVdLigyrcDnk5Xa"
        "Mk+0CE47tjFDW1Y=)",
    ),
]

# Deterministic GoCrypt vectors (fixed salt and nonce) from the same fixture:
# (salt_hex, nonce_hex, iterations, key_size, plaintext, encoded)
GOCRYPT_FIXED_VECTORS = [
    (
        "000102030405060708090a0b0c0d0e0f",
        "a1a2a3a4a5a6a7a8a9aaabac",
        10000,
        32,
        "hello",
        "AAECAwQFBgcICQoLDA0OD6Gio6SlpqeoqaqrrJ3o7pMIu2wqz7VwwkKG/A7F2Zq+pQ==",
    ),
    (
        "000102030405060708090a0b0c0d0e0f",
        "a1a2a3a4a5a6a7a8a9aaabac",
        10000,
        32,
        "Selamat pagi, Fariz \U0001F980",
        "AAECAwQFBgcICQoLDA0OD6Gio6SlpqeoqaqrrKbo7p4KQc+LlxMar3c2u+xO71zTs29C5ED2LDe15EKg"
        "1nN7i4cF4lw=",
    ),
    (
        "0102030405060708",
        "a1a2a3a4a5a6a7a8a9aaabac",
        1000,
        16,
        "hello",
        "AQIDBAUGBwihoqOkpaanqKmqq6waSwk/UnLjC6822s2kiO+ERH1KfX4=",
    ),
]

TEST_PASSWORD = "pycrypt-test-2026"

# Produced by the NodeCrypt CLI (nodecrypt-jasypt 1.0.0):
#   nodecrypt encrypt -p "pycrypt-test-2026" -v "<plaintext>"
NODECRYPT_VECTORS = [
    (
        "Fariz",
        "ENC(i9+lkLtDuBxnlOUSmtKKN0cPk4ssw2SYU+hZUUw2puo1QAuGd8BuzuvYQIyiBg0HfA==)",
    ),
    (
        "Selamat pagi, Fariz \U0001F980",
        "ENC(HgEfwmlObMJ7/kp0+lAE0BNfDrNqfsxEu0LHAgKf69GREXA3GntyB5kIWrmwb2hbPCsUXuyRM5E5"
        "FTlaojAE/fIZCLs=)",
    ),
]

# Produced by PyCrypt 1.0.0, which wrote a 16-byte GCM nonce. No other family
# member can read these, but PyCrypt must keep decrypting them.
PYCRYPT_1_0_0_VECTORS = [
    (
        "Fariz",
        "ENC(10qxV3NEkzRqK7Z441J4okLqZ74swZ0tN0udLwkPL8YKM/d2rJhxE22LiIT6vWLbuLtAncg=)",
    ),
    (
        "Selamat pagi, Fariz \U0001F980",
        "ENC(M/XabENjO69+7jnJGuO1ZbmXIR31Gr7EU7Dw6QAqAqE+qaN9dPHJ9vw5bUMhNKyWOwzdTUDvSx3p"
        "Lu3jzgF5gcCytuPxtojV)",
    ),
]


@pytest.mark.parametrize("plaintext,encrypted", GOCRYPT_VECTORS)
def test_decrypts_gocrypt_values(plaintext, encrypted):
    assert Encryptor(GOCRYPT_PASSWORD).decrypt_prefixed(encrypted) == plaintext


@pytest.mark.parametrize("plaintext,encrypted", NODECRYPT_VECTORS)
def test_decrypts_nodecrypt_values(plaintext, encrypted):
    assert Encryptor(TEST_PASSWORD).decrypt_prefixed(encrypted) == plaintext


@pytest.mark.parametrize(
    "salt_hex,nonce_hex,iterations,key_size,plaintext,encoded", GOCRYPT_FIXED_VECTORS
)
def test_encryption_matches_gocrypt_byte_for_byte(
    salt_hex, nonce_hex, iterations, key_size, plaintext, encoded
):
    salt = bytes.fromhex(salt_hex)
    enc = Encryptor(
        GOCRYPT_PASSWORD,
        iterations=iterations,
        salt_size=len(salt),
        key_size=key_size,
    )

    got = enc._encrypt_with_salt_nonce(salt, bytes.fromhex(nonce_hex), plaintext)

    assert got == encoded
    assert enc.decrypt(encoded) == plaintext


@pytest.mark.parametrize("plaintext", ["Fariz", "Selamat pagi, Fariz \U0001F980"])
def test_output_uses_12_byte_nonce(plaintext):
    enc = Encryptor(TEST_PASSWORD)

    raw = base64.b64decode(enc.encrypt(plaintext))

    # salt(16) + nonce(12) + ciphertext + tag(16)
    assert len(raw) == 16 + 12 + len(plaintext.encode("utf-8")) + 16


@pytest.mark.parametrize("plaintext,encrypted", PYCRYPT_1_0_0_VECTORS)
def test_still_decrypts_pycrypt_1_0_0_values(plaintext, encrypted):
    assert Encryptor(TEST_PASSWORD).decrypt_prefixed(encrypted) == plaintext


@pytest.mark.parametrize(
    "encrypted", [v for _, v in NODECRYPT_VECTORS + PYCRYPT_1_0_0_VECTORS]
)
def test_wrong_password_fails_for_both_layouts(encrypted):
    with pytest.raises(ValueError, match="Decryption failed"):
        Encryptor("wrong-password").decrypt_prefixed(encrypted)


@pytest.mark.parametrize("raw_len", [0, 10, 16 + 12 + 15])
def test_too_short_input_raises_value_error(raw_len):
    encoded = base64.b64encode(b"\x00" * raw_len).decode("ascii") or "AA=="

    with pytest.raises(ValueError, match="Decryption failed"):
        Encryptor(TEST_PASSWORD).decrypt(encoded)
