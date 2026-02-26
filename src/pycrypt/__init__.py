"""
PyCrypt - Jasypt-like encryption library for Python.

Encrypt your application configuration with the familiar ENC(...) pattern
used in Spring Boot applications.

Example:
    >>> from pycrypt import Encryptor
    >>> enc = Encryptor("myPassword")
    >>> encrypted = enc.encrypt_with_prefix("db_password")
    >>> print(encrypted)  # ENC(base64...)
    >>> decrypted = enc.decrypt_prefixed(encrypted)
    >>> print(decrypted)  # db_password

For Java Jasypt compatibility:
    >>> from pycrypt import JasyptEncryptor
    >>> enc = JasyptEncryptor("myPassword")
    >>> decrypted = enc.decrypt_prefixed("ENC(fromJava)")

Made with ❤️ from Claude AI for Python developers who need Jasypt.
"""

from .encryptor import Encryptor
from .jasypt_compat import JasyptEncryptor, JasyptStrongEncryptor
from .config_loader import ConfigLoader
from .utils import is_encrypted

__version__ = "1.0.0"
__author__ = "Fariz Fadian"
__email__ = "farislash@gmail.com"

__all__ = [
    "Encryptor",
    "JasyptEncryptor", 
    "JasyptStrongEncryptor",
    "ConfigLoader",
    "is_encrypted",
]
