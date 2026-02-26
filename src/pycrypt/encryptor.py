"""
Core encryption module using AES-256-GCM.

This is the recommended encryptor for new projects as it provides
authenticated encryption with associated data (AEAD).
"""

import os
import base64
import hashlib
import hmac
from typing import Optional, Dict

from Crypto.Cipher import AES

from .utils import ENC_PREFIX, ENC_SUFFIX, is_encrypted, ENC_PATTERN


class Encryptor:
    """
    AES-256-GCM Encryptor - Recommended for new projects.
    
    This encryptor uses AES-256-GCM which provides authenticated encryption,
    meaning it can detect if the ciphertext has been tampered with.
    
    Example:
        >>> enc = Encryptor("myPassword")
        >>> encrypted = enc.encrypt_with_prefix("secret")
        >>> decrypted = enc.decrypt_prefixed(encrypted)
    
    Note:
        This encryptor is NOT compatible with Java Jasypt.
        For Jasypt compatibility, use JasyptEncryptor.
    """
    
    DEFAULT_ITERATIONS = 10000
    DEFAULT_SALT_SIZE = 16
    DEFAULT_KEY_SIZE = 32  # 256 bits
    
    def __init__(
        self,
        password: str,
        iterations: int = DEFAULT_ITERATIONS,
        salt_size: int = DEFAULT_SALT_SIZE,
        key_size: int = DEFAULT_KEY_SIZE
    ):
        """
        Initialize the Encryptor.
        
        Args:
            password: The encryption password
            iterations: PBKDF2 iteration count (default: 10000)
            salt_size: Salt size in bytes (default: 16)
            key_size: Key size in bytes (default: 32 for AES-256)
        
        Raises:
            ValueError: If password is empty
        """
        if not password:
            raise ValueError("Password cannot be empty")
        
        self.password = password.encode('utf-8')
        self.iterations = iterations
        self.salt_size = salt_size
        self.key_size = key_size
    
    def _derive_key(self, salt: bytes) -> bytes:
        """Derive key from password using PBKDF2-HMAC-SHA256."""
        return hashlib.pbkdf2_hmac(
            'sha256',
            self.password,
            salt,
            self.iterations,
            dklen=self.key_size
        )
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext and return base64-encoded ciphertext.
        
        Args:
            plaintext: The text to encrypt
            
        Returns:
            Base64-encoded ciphertext (salt + nonce + ciphertext + tag)
            
        Raises:
            ValueError: If plaintext is empty
        """
        if not plaintext:
            raise ValueError("Plaintext cannot be empty")
        
        # Generate random salt
        salt = os.urandom(self.salt_size)
        
        # Derive key
        key = self._derive_key(salt)
        
        # Create AES-GCM cipher
        cipher = AES.new(key, AES.MODE_GCM)
        
        # Encrypt
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        
        # Combine: salt + nonce + ciphertext + tag
        combined = salt + cipher.nonce + ciphertext + tag
        
        return base64.b64encode(combined).decode('utf-8')
    
    def encrypt_with_prefix(self, plaintext: str) -> str:
        """
        Encrypt and wrap with ENC(...) prefix.
        
        Args:
            plaintext: The text to encrypt
            
        Returns:
            Encrypted value in format: ENC(base64...)
        """
        encrypted = self.encrypt(plaintext)
        return f"{ENC_PREFIX}{encrypted}{ENC_SUFFIX}"
    
    def decrypt(self, encoded: str) -> str:
        """
        Decrypt base64-encoded ciphertext.
        
        Args:
            encoded: Base64-encoded ciphertext
            
        Returns:
            Decrypted plaintext
            
        Raises:
            ValueError: If decryption fails
        """
        if not encoded:
            raise ValueError("Encoded value cannot be empty")
        
        try:
            # Decode from base64
            combined = base64.b64decode(encoded)
            
            # Extract components
            salt = combined[:self.salt_size]
            nonce = combined[self.salt_size:self.salt_size + 16]
            tag = combined[-16:]
            ciphertext = combined[self.salt_size + 16:-16]
            
            # Derive key
            key = self._derive_key(salt)
            
            # Create cipher and decrypt
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def decrypt_prefixed(self, value: str) -> str:
        """
        Decrypt a value with ENC(...) prefix.
        
        Args:
            value: Encrypted value in format ENC(base64...)
            
        Returns:
            Decrypted plaintext
            
        Raises:
            ValueError: If format is invalid or decryption fails
        """
        value = value.strip()
        
        if not value.startswith(ENC_PREFIX) or not value.endswith(ENC_SUFFIX):
            raise ValueError(f"Invalid encrypted format, expected {ENC_PREFIX}...{ENC_SUFFIX}")
        
        encrypted = value[len(ENC_PREFIX):-len(ENC_SUFFIX)]
        return self.decrypt(encrypted)
    
    def decrypt_all_in_string(self, input_str: str) -> str:
        """
        Decrypt all ENC(...) values in a string.
        
        Args:
            input_str: String containing ENC(...) values
            
        Returns:
            String with all ENC(...) values decrypted
        """
        def replace_match(match):
            try:
                return self.decrypt_prefixed(match.group(0))
            except:
                return match.group(0)  # Keep original on error
        
        return ENC_PATTERN.sub(replace_match, input_str)
    
    def decrypt_map(self, config: Dict[str, str]) -> Dict[str, str]:
        """
        Decrypt all ENC(...) values in a dictionary.
        
        Args:
            config: Dictionary with potentially encrypted values
            
        Returns:
            Dictionary with all ENC(...) values decrypted
        """
        result = {}
        for key, value in config.items():
            if is_encrypted(value):
                try:
                    result[key] = self.decrypt_prefixed(value)
                except:
                    result[key] = value  # Keep original on error
            else:
                result[key] = value
        return result
