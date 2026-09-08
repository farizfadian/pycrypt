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
Status      : ✅ PUBLISHED & TESTED (v1.0.0)
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
│   ☕ Jasypt     jasypt.org                         (Java)       │
│                                                                  │
│   ALL USE JasyptEncryptor FOR CROSS-LANGUAGE COMPATIBILITY!    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

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

| Class | Algorithm | Java Compatible? |
|-------|-----------|------------------|
| `Encryptor` | AES-256-GCM | ❌ NO |
| `JasyptEncryptor` | PBEWithMD5AndDES | ✅ YES |
| `JasyptStrongEncryptor` | AES-256-CBC | ✅ YES |

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

---

## 📦 Publish & Release Status

| Item | Status |
|------|--------|
| Published | ✅ v1.0.0 on PyPI |
| Install | `pip install pycrypt-jasypt` |
| Import | `from pycrypt_jasypt import JasyptEncryptor` (underscore!) |
| CI | ✅ GitHub Actions (multi-OS, multi-Python version) |
| Release | ✅ Auto-publish on `git tag v*` + `git push origin v*` |
| Token | PYPI_API_TOKEN in GitHub Secrets (✅ Active, no expiry) |
| Cross-language tested | ✅ Encrypt in Python → Decrypt in Go/Node/PHP/Java |

### How to release a new version:
```bash
git tag v1.x.x
git push origin v1.x.x
# GitHub Actions auto-publishes to PyPI
```

---

## 📋 Full Context Reference

For complete cross-language context, see:
`C:\Users\Fariz Fadian\Documents\Fariz\PRIVATE\JASYPT-MULTI-LANGUAGE-CONTEXT.md`

---

<p align="center"><b>Made with ❤️ from Claude AI</b></p>
