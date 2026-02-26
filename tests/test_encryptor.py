"""
Tests for the core Encryptor (AES-256-GCM).
"""

import pytest
from pycrypt import Encryptor, is_encrypted


class TestEncryptor:
    """Tests for Encryptor class."""
    
    def test_encrypt_decrypt_simple(self):
        """Test basic encryption and decryption."""
        enc = Encryptor("mySecretPassword")
        
        plaintext = "hello"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
        assert encrypted != plaintext
    
    def test_encrypt_decrypt_with_spaces(self):
        """Test encryption with spaces."""
        enc = Encryptor("password")
        
        plaintext = "hello world with spaces"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_special_chars(self):
        """Test encryption with special characters."""
        enc = Encryptor("password")
        
        plaintext = "p@$$w0rd!#$%^&*()"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_unicode(self):
        """Test encryption with unicode characters."""
        enc = Encryptor("password")
        
        plaintext = "こんにちは世界 🔐"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_json(self):
        """Test encryption with JSON content."""
        enc = Encryptor("password")
        
        plaintext = '{"username":"admin","password":"secret123"}'
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_connection_string(self):
        """Test encryption with connection string."""
        enc = Encryptor("password")
        
        plaintext = "postgresql://user:pass@localhost:5432/dbname?sslmode=disable"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_with_prefix(self):
        """Test encryption with ENC(...) prefix."""
        enc = Encryptor("password")
        
        plaintext = "mysecret"
        encrypted = enc.encrypt_with_prefix(plaintext)
        
        assert encrypted.startswith("ENC(")
        assert encrypted.endswith(")")
        assert is_encrypted(encrypted)
        
        decrypted = enc.decrypt_prefixed(encrypted)
        assert decrypted == plaintext
    
    def test_wrong_password(self):
        """Test decryption with wrong password fails."""
        enc1 = Encryptor("correctPassword")
        enc2 = Encryptor("wrongPassword")
        
        encrypted = enc1.encrypt("secret")
        
        with pytest.raises(ValueError):
            enc2.decrypt(encrypted)
    
    def test_empty_password_raises(self):
        """Test that empty password raises error."""
        with pytest.raises(ValueError):
            Encryptor("")
    
    def test_empty_value_raises(self):
        """Test that empty value raises error."""
        enc = Encryptor("password")
        
        with pytest.raises(ValueError):
            enc.encrypt("")
        
        with pytest.raises(ValueError):
            enc.decrypt("")
    
    def test_different_encryptions_produce_different_results(self):
        """Test that same plaintext produces different ciphertexts."""
        enc = Encryptor("password")
        plaintext = "same value"
        
        encrypted1 = enc.encrypt(plaintext)
        encrypted2 = enc.encrypt(plaintext)
        
        assert encrypted1 != encrypted2
        
        # But both decrypt to same value
        assert enc.decrypt(encrypted1) == enc.decrypt(encrypted2) == plaintext
    
    def test_decrypt_all_in_string(self):
        """Test decrypting all ENC(...) values in a string."""
        enc = Encryptor("password")
        
        enc1 = enc.encrypt_with_prefix("user123")
        enc2 = enc.encrypt_with_prefix("pass456")
        
        input_str = f"username={enc1}\npassword={enc2}"
        result = enc.decrypt_all_in_string(input_str)
        
        assert "username=user123" in result
        assert "password=pass456" in result
    
    def test_decrypt_map(self):
        """Test decrypting all ENC(...) values in a map."""
        enc = Encryptor("password")
        
        encrypted_pass = enc.encrypt_with_prefix("secretPassword")
        encrypted_key = enc.encrypt_with_prefix("apiKey123")
        
        config = {
            "host": "localhost",
            "port": "5432",
            "password": encrypted_pass,
            "api_key": encrypted_key,
        }
        
        decrypted = enc.decrypt_map(config)
        
        assert decrypted["host"] == "localhost"
        assert decrypted["password"] == "secretPassword"
        assert decrypted["api_key"] == "apiKey123"
    
    def test_custom_iterations(self):
        """Test with custom iteration count."""
        enc = Encryptor("password", iterations=20000)
        
        plaintext = "test"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext


class TestIsEncrypted:
    """Tests for is_encrypted function."""
    
    def test_encrypted_value(self):
        assert is_encrypted("ENC(abc123)") is True
    
    def test_empty_enc(self):
        assert is_encrypted("ENC()") is True
    
    def test_with_spaces(self):
        assert is_encrypted("  ENC(value)  ") is True
    
    def test_plaintext(self):
        assert is_encrypted("plaintext") is False
    
    def test_missing_closing(self):
        assert is_encrypted("ENC(missing") is False
    
    def test_empty_string(self):
        assert is_encrypted("") is False
    
    def test_none(self):
        assert is_encrypted(None) is False
