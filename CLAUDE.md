# CLAUDE.md - Complete Development Context for PyCrypt

> **IMPORTANT**: This file contains ALL context needed for Claude AI to understand and work on PyCrypt.

---

## 🎯 Project Summary

**PyCrypt** is a Jasypt-like encryption library for Python, part of a cross-language encryption family.

```
Owner       : Fariz Fadian (github.com/farizfadian)
Repository  : github.com/farizfadian/pycrypt
Language    : Python 3.8+
License     : MIT
Package     : pycrypt-jasypt (PyPI)
Dependencies: pycryptodome>=3.19.0
Created     : December 2024
Status      : ✅ PUBLISHED & TESTED (v1.0.1)
Install     : pip install pycrypt-jasypt
Registry    : PyPI (pypi.org/project/pycrypt-jasypt/)
Release     : Auto-publish via GitHub Actions on tag push (v*)
Token       : PYPI_API_TOKEN in GitHub Secrets (✅ Active, no expiry)
```

---

## 🔗 Cross-Language Family (ALL SAME ENC() FORMAT!)

```
┌─────────────────────────────────────────────────────────────────┐
│                 Jasypt Encryption Library Family                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   🐹 GoCrypt    github.com/farizfadian/gocrypt     (Go)         │
│   🐍 PyCrypt    github.com/farizfadian/pycrypt     (Python)     │
│   📦 NodeCrypt  github.com/farizfadian/nodecrypt   (Node.js)    │
│   🐘 PHPCrypt   github.com/farizfadian/phpcrypt    (PHP)        │
│   🦀 RustCrypt  github.com/farizfadian/rustcrypt   (Rust)       │
│   ☕ Jasypt     jasypt.org                         (Java)       │
│                                                                  │
│   SAME MODE ON BOTH SIDES: default, --jasypt, --jasypt-strong  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

An `ENC(...)` value does not record its algorithm, so both sides must use the same mode.
Verified 2026-11-19 with the released CLIs (PyCrypt 1.0.1, GoCrypt, RustCrypt, NodeCrypt, Jasypt 1.9.3 jar):

| Mode (CLI flag) | Class | Go / Node / Rust / PHP | Java Jasypt |
|-----------------|-------|------------------------|-------------|
| (none) | `Encryptor` | ✅ since PyCrypt 1.0.1 | ❌ no such mode |
| `--jasypt` | `JasyptEncryptor` | ✅ (NodeCrypt on Node 17+ needs `NODE_OPTIONS=--openssl-legacy-provider`) | ✅ |
| `--jasypt-strong` | `JasyptStrongEncryptor` | ✅ | ❌ Java writes a random IV after the salt |

PHPCrypt was checked by reading its code only; PHP was not installed on the test machine.

### Default-mode wire format (must match the family byte for byte)

- `base64(salt(16) || nonce(12) || ciphertext || tag(16))`, key = PBKDF2-HMAC-SHA256, 10000 iterations, 32 bytes.
- Always pass the 12-byte nonce explicitly: pycryptodome defaults to 16 bytes. That was the 1.0.0 bug.
  1.0.1 still decrypts 1.0.0's 16-byte layout as a fallback.
- Golden vectors come from GoCrypt via RustCrypt's `tests/fixtures/gocrypt_vectors.json`.
  `tests/test_cross_language.py` pins PyCrypt against them. Tests that only round-trip inside PyCrypt cannot catch format drift.

---

## 📁 Project Structure

```
pycrypt/
├── src/pycrypt/
│   ├── __init__.py
│   ├── encryptor.py        # AES-256-GCM (Encryptor)
│   ├── jasypt_compat.py    # JasyptEncryptor, JasyptStrongEncryptor
│   ├── config_loader.py    # Load .env, YAML, JSON
│   ├── cli.py              # CLI tool
│   └── utils.py            # is_encrypted()
├── tests/
├── pyproject.toml
└── README.md
```

---

## 🔐 Three Encryptors

| Class | Algorithm | Family compatible? | Java Compatible? |
|-------|-----------|--------------------|------------------|
| `Encryptor` | AES-256-GCM | ✅ YES (1.0.1+) | ❌ NO |
| `JasyptEncryptor` | PBEWithMD5AndDES | ✅ YES | ✅ YES |
| `JasyptStrongEncryptor` | AES-256-CBC | ✅ YES | ❌ NO |

---

## 💻 Commands

```bash
# Install dev
pip install -e ".[dev]"

# Test
pytest

# CLI
pycrypt encrypt -p password -v "secret" --jasypt
```

---

## 📝 API Reference

```python
from pycrypt import JasyptEncryptor, ConfigLoader, is_encrypted

# Create
enc = JasyptEncryptor(password)

# Encrypt/Decrypt
encrypted = enc.encrypt_with_prefix(plaintext)  # ENC(...)
plaintext = enc.decrypt_prefixed("ENC(...)")

# Batch
decrypted_map = enc.decrypt_map(config_dict)

# Config
loader = ConfigLoader(password)
config = loader.load_env_file(".env")
```

---

## 📦 Dependencies

- `pycryptodome>=3.19.0`

---

## 📦 Publish & Release Status

| Item | Status |
|------|--------|
| Published | ✅ v1.0.1 on PyPI |
| Install | `pip install pycrypt-jasypt` |
| Import | `from pycrypt import JasyptEncryptor` (the PyPI name is `pycrypt-jasypt`, the package is `pycrypt`) |
| CI | ✅ GitHub Actions (multi-OS, multi-Python version; 3.8/3.9 run on ubuntu-24.04 because Ubuntu 26.04 has no builds for them) |
| Release | ✅ Auto-publish on `git tag v*` + `git push origin v*` |
| Token | PYPI_API_TOKEN in GitHub Secrets (✅ Active, no expiry) |
| Cross-language tested | ✅ See the mode table above (Python ↔ Go/Node/Rust both ways; Java for `--jasypt`) |

### How to release a new version:
```bash
git tag v1.x.x
git push origin v1.x.x
# GitHub Actions auto-publishes to PyPI
```

---

## 📋 Full Context Reference

For complete cross-language context, see:
the maintainer's private family context document (`JASYPT-MULTI-LANGUAGE-CONTEXT.md`, kept outside this repository)

---

<p align="center"><b>Made with ❤️ from Claude AI</b></p>
