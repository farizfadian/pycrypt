# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.1] - 2026-11-19

### Fixed
- **`Encryptor` (AES-256-GCM, the CLI default) now uses a 12-byte GCM nonce**, the
  same as GoCrypt, NodeCrypt, RustCrypt and PHPCrypt. PyCrypt 1.0.0 relied on
  pycryptodome's default 16-byte nonce, so `ENC(...)` values from the other
  family members failed with `Decryption failed: MAC check failed`, and values
  written by PyCrypt could not be read by them.
- Wire format (unchanged for the rest of the family):
  `base64(salt(16) || nonce(12) || ciphertext || tag(16))`, key from
  PBKDF2-HMAC-SHA256 with 10000 iterations.

### Compatibility
- Values written by PyCrypt 1.0.0 still decrypt in 1.0.1 (the 16-byte-nonce
  layout is tried as a fallback). Other family members never could read them;
  re-encrypt with 1.0.1 to share them across languages.
- Values written by 1.0.1 cannot be read by PyCrypt 1.0.0. Upgrade every
  Python reader before you write new values.
- `JasyptEncryptor` and `JasyptStrongEncryptor` are unchanged.

### Added
- Cross-language tests that pin `Encryptor` against GoCrypt and NodeCrypt
  values (`tests/test_cross_language.py`).

---

## [1.0.0] - 2024-12-28

### 🎉 Initial Release

First public release of PyCrypt - Jasypt-like encryption for Python.

### Added

#### Core Features
- **AES-256-GCM Encryption** (`Encryptor`) - Modern, secure encryption for new projects
- **Jasypt Compatible** (`JasyptEncryptor`) - PBEWithMD5AndDES for Java Jasypt compatibility
- **Jasypt Strong** (`JasyptStrongEncryptor`) - PBEWithHmacSHA256AndAES_256

#### ENC(...) Pattern
- `ENC(base64value)` format matching Jasypt/Spring Boot
- `is_encrypted()` helper function
- `encrypt_with_prefix()` and `decrypt_prefixed()` methods

#### Config Loaders
- `.env` file loader with auto-decryption
- Simple YAML file loader
- JSON file loader with recursive decryption
- `set_to_env()` to load config to environment variables

#### Batch Operations
- `decrypt_map()` - Decrypt all values in a dictionary
- `decrypt_all_in_string()` - Decrypt all ENC(...) values in a string

#### CLI Tool
- `pycrypt encrypt` - Encrypt single value
- `pycrypt decrypt` - Decrypt single value
- `pycrypt encrypt-file` - Encrypt all values in a file
- `pycrypt decrypt-file` - Decrypt all ENC(...) values in a file
- Support for `--jasypt` and `--jasypt-strong` flags
- Support for `PYCRYPT_PASSWORD` environment variable

#### Cross-Language Compatibility
- Compatible with GoCrypt (Go)
- Compatible with Java Jasypt
- Shared `ENC(...)` format across all languages

### Dependencies
- `pycryptodome>=3.19.0`

---

Made with ❤️ from Claude AI for Python developers who need Jasypt
