# PyCrypt 🔐

[![CI](https://github.com/farizfadian/pycrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/farizfadian/pycrypt/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/pycrypt-jasypt.svg)](https://badge.fury.io/py/pycrypt-jasypt)
[![Python Version](https://img.shields.io/pypi/pyversions/pycrypt-jasypt.svg)](https://pypi.org/project/pycrypt-jasypt/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Jasypt-like encryption library for Python** - Encrypt your application configuration with the familiar `ENC(...)` pattern used in Spring Boot applications.

> **Made with ❤️ from Claude AI for Python developers who need Jasypt**

---

## 🎯 Why PyCrypt?

If you're coming from Java/Spring Boot world and need to share encrypted configuration with Python applications, PyCrypt is for you! It provides:

- ✅ **Familiar `ENC(...)` pattern** - Just like Jasypt in Spring Boot
- ✅ **Java Jasypt compatibility** - Decrypt values encrypted by Java
- ✅ **Multiple encryption algorithms** - From legacy Jasypt to modern AES-256-GCM
- ✅ **Config file loaders** - Load .env, YAML, JSON with auto-decryption
- ✅ **CLI tool included** - Encrypt/decrypt from command line
- ✅ **Cross-platform** - Works with GoCrypt (Go), RustCrypt (Rust) and Java Jasypt

---

## 📦 Installation

```bash
pip install pycrypt-jasypt
```

---

## 🚀 Quick Start

### Basic Encryption/Decryption

```python
from pycrypt import Encryptor

# Create encryptor with password
enc = Encryptor("mySecretPassword")

# Encrypt
encrypted = enc.encrypt_with_prefix("db_password_123")
print(encrypted)  # ENC(base64encodedvalue...)

# Decrypt
decrypted = enc.decrypt_prefixed(encrypted)
print(decrypted)  # db_password_123
```

### Loading Encrypted Configuration

```python
from pycrypt import ConfigLoader
import os

# .env file:
# DATABASE_HOST=localhost
# DATABASE_PASSWORD=ENC(AbCdEf123456...)

loader = ConfigLoader(os.getenv("PYCRYPT_PASSWORD"))
config = loader.load_env_file(".env")

print(config["DATABASE_PASSWORD"])  # actual_password
```

---

## 🔐 Encryption Algorithms

| Encryptor | Algorithm | Security | Use Case |
|-----------|-----------|----------|----------|
| `Encryptor` | AES-256-GCM | ⭐⭐⭐⭐⭐ | **Recommended** for new projects |
| `JasyptStrongEncryptor` | PBEWithHmacSHA256AndAES_256 | ⭐⭐⭐⭐ | Jasypt strong compatibility |
| `JasyptEncryptor` | PBEWithMD5AndDES | ⭐⭐ | Legacy Jasypt compatibility |

### Choose the Right Algorithm

```python
from pycrypt import Encryptor, JasyptEncryptor, JasyptStrongEncryptor

# RECOMMENDED: For new Python projects
enc = Encryptor(password)

# For compatibility with Java Jasypt (default algorithm)
enc = JasyptEncryptor(password)

# For compatibility with Java Jasypt (strong encryption)
enc = JasyptStrongEncryptor(password)
```

---

## ☕ Java Jasypt Compatibility

### ⚠️ Important: Compatibility Matrix

```
┌─────────────────────────────────────────────────────────────────┐
│            ENCRYPT WITH → DECRYPT WITH                          │
├─────────────────────────────────────────────────────────────────┤
│ Java Jasypt (default)  → JasyptEncryptor        ✅ YES          │
│ Java Jasypt (strong)   → JasyptStrongEncryptor  ✅ YES          │
│ Java Jasypt (default)  → Encryptor              ❌ NO           │
│ Encryptor              → Java Jasypt            ❌ NO           │
│ JasyptEncryptor        → Java Jasypt            ✅ YES          │
│ GoCrypt JasyptEnc      → JasyptEncryptor        ✅ YES          │
│ RustCrypt JasyptEnc    → JasyptEncryptor        ✅ YES          │
└─────────────────────────────────────────────────────────────────┘
```

### Decrypt Values from Java

```python
from pycrypt import JasyptEncryptor

# Your Java application.properties has:
# db.password=ENC(xxxFromJavaxxx)

enc = JasyptEncryptor(same_password_as_java)
decrypted = enc.decrypt_prefixed("ENC(xxxFromJavaxxx)")  # ✅ Works!
```

### Share Config with Go (GoCrypt)

```python
from pycrypt import JasyptEncryptor

# Use JasyptEncryptor so both Python and Go can read
enc = JasyptEncryptor(shared_password)
encrypted = enc.encrypt_with_prefix("shared_secret")

# This ENC(...) value can be decrypted by:
# - Python: using JasyptEncryptor
# - Go: using gocrypt.NewJasyptEncryptor
# - Java: using Jasypt library
```

---

## 📖 Usage Guide

### Configuration Files

#### .env File

```env
# config.env
DATABASE_HOST=localhost
DATABASE_PASSWORD=ENC(AbCdEf123456...)
API_KEY=ENC(XyZ789...)
```

```python
from pycrypt import ConfigLoader

loader = ConfigLoader(password)
config = loader.load_env_file("config.env")
print(config["DATABASE_PASSWORD"])  # decrypted value
```

#### JSON File

```python
config = loader.load_json("config.json")
```

#### Set to Environment Variables

```python
loader.set_to_env(".env")
# Now use os.getenv()
db_password = os.getenv("DATABASE_PASSWORD")
```

### Decrypt Map

```python
config = {
    "host": "localhost",
    "password": "ENC(encrypted_value)",
}

decrypted = enc.decrypt_map(config)
print(decrypted["password"])  # plaintext
```

### Check if Value is Encrypted

```python
from pycrypt import is_encrypted

if is_encrypted(value):
    decrypted = enc.decrypt_prefixed(value)
```

---

## 💻 CLI Tool

### Usage

```bash
# Encrypt a value
pycrypt encrypt -p mySecret -v "database_password"
# Output: ENC(base64value...)

# Decrypt a value
pycrypt decrypt -p mySecret -v "ENC(base64value...)"
# Output: database_password

# Encrypt all values in a file
pycrypt encrypt-file -p mySecret -i .env.plain -o .env.encrypted

# Decrypt all values in a file
pycrypt decrypt-file -p mySecret -i .env.encrypted -o .env.plain

# Use Jasypt-compatible algorithm
pycrypt encrypt -p mySecret -v "secret" --jasypt

# Use environment variable for password
export PYCRYPT_PASSWORD=mySecret
pycrypt encrypt -v "secret_value"
```

---

## ⚙️ Advanced Configuration

### Custom Options

```python
# Encryptor (AES-256-GCM)
enc = Encryptor(
    password,
    iterations=50000,  # default: 10000
    salt_size=32,      # default: 16
    key_size=32,       # 32 = AES-256
)

# Jasypt Compatible
enc = JasyptEncryptor(
    password,
    iterations=2000,   # default: 1000
)

# Jasypt Strong
enc = JasyptStrongEncryptor(
    password,
    iterations=5000,
    salt_size=32,
)
```

---

## 🛡️ Security

### Best Practices

1. **Never hardcode passwords** - Use environment variables
2. **Rotate passwords regularly**
3. **Use strong passwords** (minimum 16 characters)
4. **Use `Encryptor` for new projects** - More secure than Jasypt algorithms

---

## 📚 API Reference

### Encryptor

```python
enc = Encryptor(password, iterations=10000, salt_size=16, key_size=32)

encrypted = enc.encrypt(plaintext)           # Returns base64
encrypted = enc.encrypt_with_prefix(plaintext)  # Returns ENC(base64)
plaintext = enc.decrypt(base64_string)
plaintext = enc.decrypt_prefixed("ENC(...)")
decrypted_str = enc.decrypt_all_in_string(config_string)
decrypted_map = enc.decrypt_map({"key": "ENC(...)"})
```

### JasyptEncryptor

```python
enc = JasyptEncryptor(password, iterations=1000)
# Same methods as Encryptor
```

### JasyptStrongEncryptor

```python
enc = JasyptStrongEncryptor(password, iterations=1000, salt_size=16)
# Same methods as Encryptor
```

### ConfigLoader

```python
loader = ConfigLoader(password)
config = loader.load_env_file(".env")
config = loader.load_yaml("config.yaml")
config = loader.load_json("config.json")
loader.set_to_env(".env")
```

### Utility Functions

```python
from pycrypt import is_encrypted

is_encrypted("ENC(abc)")  # True
is_encrypted("plaintext")  # False
```

---

## 📁 Project Structure

```
pycrypt/
├── src/pycrypt/
│   ├── __init__.py         # Package exports
│   ├── encryptor.py        # AES-256-GCM encryption
│   ├── jasypt_compat.py    # Jasypt compatibility
│   ├── config_loader.py    # Config file loader
│   ├── cli.py              # CLI tool
│   └── utils.py            # Utility functions
├── tests/
│   ├── test_encryptor.py
│   └── test_jasypt_compat.py
├── pyproject.toml
├── README.md
├── LICENSE
└── CLAUDE.md
```

---

## 🧪 Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=pycrypt
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔗 Related Projects

- [GoCrypt](https://github.com/farizfadian/gocrypt) - Jasypt-like encryption for Go
- [NodeCrypt](https://github.com/farizfadian/nodecrypt) - Jasypt-like encryption for Node.js
- [PHPCrypt](https://github.com/farizfadian/phpcrypt) - Jasypt-like encryption for PHP
- [RustCrypt](https://github.com/farizfadian/rustcrypt) - Jasypt-like encryption for Rust
- [Jasypt](http://www.jasypt.org/) - Original Java library

---

<p align="center">
  <b>Made with ❤️ from Claude AI for Python developers who need Jasypt</b>
</p>
