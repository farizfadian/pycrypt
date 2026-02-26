"""
Jasypt-compatible encryption module.

This module provides compatibility with Java Jasypt library,
allowing Python to decrypt values encrypted by Java and vice versa.
"""

import os
import base64
import hashlib
from typing import Dict

from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

from .utils import ENC_PREFIX, ENC_SUFFIX, is_encrypted, ENC_PATTERN


class JasyptEncryptor:
    """
    Jasypt-compatible encryptor using PBEWithMD5AndDES.
    
    This encryptor is compatible with Java Jasypt's default algorithm.
    Use this when you need to decrypt values encrypted by Java Jasypt
    or when Go/Java applications need to read the same encrypted config.
    
    WARNING: This algorithm is considered weak by modern standards.
    Use only for backward compatibility with existing Jasypt-encrypted values.
    
    Example:
        >>> enc = JasyptEncryptor("myPassword")
        >>> # Decrypt value from Java
        >>> decrypted = enc.decrypt_prefixed("ENC(fromJava)")
        
        >>> # Encrypt for Java compatibility
        >>> encrypted = enc.encrypt_with_prefix("secret")
    """
    
    DEFAULT_ITERATIONS = 1000
    SALT_SIZE = 8  # DES uses 8-byte salt
    
    def __init__(self, password: str, iterations: int = DEFAULT_ITERATIONS):
        """
        Initialize the JasyptEncryptor.
        
        Args:
            password: The encryption password
            iterations: Key derivation iteration count (default: 1000)
            
        Raises:
            ValueError: If password is empty
        """
        if not password:
            raise ValueError("Password cannot be empty")
        
        self.password = password
        self.iterations = iterations
    
    def _derive_key_and_iv(self, salt: bytes) -> tuple:
        """
        Derive key and IV using PBKDF1 with MD5 (Jasypt's method).
        
        This implements the OpenSSL EVP_BytesToKey function used by Jasypt.
        """
        data = self.password.encode('utf-8') + salt
        
        # First iteration
        result = hashlib.md5(data).digest()
        
        # Additional iterations
        for _ in range(1, self.iterations):
            result = hashlib.md5(result).digest()
        
        # MD5 produces 16 bytes, split into key (8) and IV (8)
        return result[:8], result[8:16]
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext using PBEWithMD5AndDES (Jasypt compatible).
        
        Args:
            plaintext: The text to encrypt
            
        Returns:
            Base64-encoded ciphertext
        """
        if not plaintext:
            raise ValueError("Plaintext cannot be empty")
        
        # Generate random salt
        salt = os.urandom(self.SALT_SIZE)
        
        # Derive key and IV
        key, iv = self._derive_key_and_iv(salt)
        
        # Create DES cipher in CBC mode
        cipher = DES.new(key, DES.MODE_CBC, iv)
        
        # PKCS5 padding and encrypt
        padded = pad(plaintext.encode('utf-8'), DES.block_size)
        ciphertext = cipher.encrypt(padded)
        
        # Combine salt + ciphertext (Jasypt format)
        combined = salt + ciphertext
        
        return base64.b64encode(combined).decode('utf-8')
    
    def encrypt_with_prefix(self, plaintext: str) -> str:
        """Encrypt and wrap with ENC(...) prefix."""
        encrypted = self.encrypt(plaintext)
        return f"{ENC_PREFIX}{encrypted}{ENC_SUFFIX}"
    
    def decrypt(self, encoded: str) -> str:
        """
        Decrypt Jasypt-encrypted data.
        
        Args:
            encoded: Base64-encoded ciphertext
            
        Returns:
            Decrypted plaintext
        """
        if not encoded:
            raise ValueError("Encoded value cannot be empty")
        
        try:
            # Decode from base64
            combined = base64.b64decode(encoded)
            
            # Minimum size: 8 (salt) + 8 (at least one block)
            if len(combined) < 16:
                raise ValueError("Invalid Jasypt data")
            
            # Extract salt and ciphertext
            salt = combined[:self.SALT_SIZE]
            ciphertext = combined[self.SALT_SIZE:]
            
            # Ciphertext must be multiple of block size
            if len(ciphertext) % DES.block_size != 0:
                raise ValueError("Invalid Jasypt data")
            
            # Derive key and IV
            key, iv = self._derive_key_and_iv(salt)
            
            # Create DES cipher and decrypt
            cipher = DES.new(key, DES.MODE_CBC, iv)
            padded = cipher.decrypt(ciphertext)
            
            # Remove PKCS5 padding
            plaintext = unpad(padded, DES.block_size)
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def decrypt_prefixed(self, value: str) -> str:
        """Decrypt a value with ENC(...) prefix."""
        value = value.strip()
        
        if not value.startswith(ENC_PREFIX) or not value.endswith(ENC_SUFFIX):
            raise ValueError(f"Invalid encrypted format, expected {ENC_PREFIX}...{ENC_SUFFIX}")
        
        encrypted = value[len(ENC_PREFIX):-len(ENC_SUFFIX)]
        return self.decrypt(encrypted)
    
    def decrypt_all_in_string(self, input_str: str) -> str:
        """Decrypt all ENC(...) values in a string."""
        def replace_match(match):
            try:
                return self.decrypt_prefixed(match.group(0))
            except:
                return match.group(0)
        
        return ENC_PATTERN.sub(replace_match, input_str)
    
    def decrypt_map(self, config: Dict[str, str]) -> Dict[str, str]:
        """Decrypt all ENC(...) values in a dictionary."""
        result = {}
        for key, value in config.items():
            if is_encrypted(value):
                try:
                    result[key] = self.decrypt_prefixed(value)
                except:
                    result[key] = value
            else:
                result[key] = value
        return result


class JasyptStrongEncryptor:
    """
    Jasypt-compatible encryptor using PBEWithHmacSHA256AndAES_256.
    
    This is a stronger algorithm compared to the default PBEWithMD5AndDES.
    Use this when Java uses Jasypt's strong encryption.
    
    Example:
        >>> enc = JasyptStrongEncryptor("myPassword")
        >>> encrypted = enc.encrypt_with_prefix("secret")
    """
    
    DEFAULT_ITERATIONS = 1000
    DEFAULT_SALT_SIZE = 16
    KEY_SIZE = 32  # AES-256
    IV_SIZE = 16   # AES block size
    
    def __init__(
        self,
        password: str,
        iterations: int = DEFAULT_ITERATIONS,
        salt_size: int = DEFAULT_SALT_SIZE
    ):
        """
        Initialize the JasyptStrongEncryptor.
        
        Args:
            password: The encryption password
            iterations: Key derivation iteration count (default: 1000)
            salt_size: Salt size in bytes (default: 16)
        """
        if not password:
            raise ValueError("Password cannot be empty")
        
        self.password = password.encode('utf-8')
        self.iterations = iterations
        self.salt_size = salt_size
    
    def _derive_key_and_iv(self, salt: bytes) -> tuple:
        """Derive key and IV using PBKDF2-HMAC-SHA256."""
        # Derive 48 bytes: 32 for key + 16 for IV
        derived = hashlib.pbkdf2_hmac(
            'sha256',
            self.password,
            salt,
            self.iterations,
            dklen=self.KEY_SIZE + self.IV_SIZE
        )
        return derived[:self.KEY_SIZE], derived[self.KEY_SIZE:]
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt using AES-256-CBC with PBKDF2-HMAC-SHA256."""
        if not plaintext:
            raise ValueError("Plaintext cannot be empty")
        
        # Generate random salt
        salt = os.urandom(self.salt_size)
        
        # Derive key and IV
        key, iv = self._derive_key_and_iv(salt)
        
        # Create AES cipher in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # PKCS7 padding and encrypt
        padded = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded)
        
        # Combine salt + ciphertext
        combined = salt + ciphertext
        
        return base64.b64encode(combined).decode('utf-8')
    
    def encrypt_with_prefix(self, plaintext: str) -> str:
        """Encrypt and wrap with ENC(...) prefix."""
        encrypted = self.encrypt(plaintext)
        return f"{ENC_PREFIX}{encrypted}{ENC_SUFFIX}"
    
    def decrypt(self, encoded: str) -> str:
        """Decrypt data encrypted with PBEWithHmacSHA256AndAES_256."""
        if not encoded:
            raise ValueError("Encoded value cannot be empty")
        
        try:
            combined = base64.b64decode(encoded)
            
            if len(combined) < self.salt_size + AES.block_size:
                raise ValueError("Invalid data")
            
            salt = combined[:self.salt_size]
            ciphertext = combined[self.salt_size:]
            
            if len(ciphertext) % AES.block_size != 0:
                raise ValueError("Invalid data")
            
            # Derive key and IV
            key, iv = self._derive_key_and_iv(salt)
            
            # Create AES cipher and decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded = cipher.decrypt(ciphertext)
            
            # Remove PKCS7 padding
            plaintext = unpad(padded, AES.block_size)
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def decrypt_prefixed(self, value: str) -> str:
        """Decrypt a value with ENC(...) prefix."""
        value = value.strip()
        
        if not value.startswith(ENC_PREFIX) or not value.endswith(ENC_SUFFIX):
            raise ValueError(f"Invalid encrypted format, expected {ENC_PREFIX}...{ENC_SUFFIX}")
        
        encrypted = value[len(ENC_PREFIX):-len(ENC_SUFFIX)]
        return self.decrypt(encrypted)
    
    def decrypt_all_in_string(self, input_str: str) -> str:
        """Decrypt all ENC(...) values in a string."""
        def replace_match(match):
            try:
                return self.decrypt_prefixed(match.group(0))
            except:
                return match.group(0)
        
        return ENC_PATTERN.sub(replace_match, input_str)
    
    def decrypt_map(self, config: Dict[str, str]) -> Dict[str, str]:
        """Decrypt all ENC(...) values in a dictionary."""
        result = {}
        for key, value in config.items():
            if is_encrypted(value):
                try:
                    result[key] = self.decrypt_prefixed(value)
                except:
                    result[key] = value
            else:
                result[key] = value
        return result
