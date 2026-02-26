"""
Tests for Jasypt-compatible encryptors.
"""

import pytest
from pycrypt import JasyptEncryptor, JasyptStrongEncryptor, is_encrypted


class TestJasyptEncryptor:
    """Tests for JasyptEncryptor (PBEWithMD5AndDES)."""
    
    def test_encrypt_decrypt_simple(self):
        """Test basic encryption and decryption."""
        enc = JasyptEncryptor("mySecretPassword")
        
        plaintext = "hello"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_with_spaces(self):
        """Test encryption with spaces."""
        enc = JasyptEncryptor("password")
        
        plaintext = "hello world"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_special_chars(self):
        """Test encryption with special characters."""
        enc = JasyptEncryptor("password")
        
        plaintext = "p@$$w0rd!#$%"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_unicode(self):
        """Test encryption with unicode."""
        enc = JasyptEncryptor("password")
        
        plaintext = "こんにちは"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_connection_string(self):
        """Test with connection string."""
        enc = JasyptEncryptor("password")
        
        plaintext = "jdbc:mysql://localhost:3306/mydb"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_with_prefix(self):
        """Test encryption with ENC(...) prefix."""
        enc = JasyptEncryptor("password")
        
        plaintext = "myDatabasePassword"
        encrypted = enc.encrypt_with_prefix(plaintext)
        
        assert is_encrypted(encrypted)
        
        decrypted = enc.decrypt_prefixed(encrypted)
        assert decrypted == plaintext
    
    def test_wrong_password(self):
        """Test decryption with wrong password fails."""
        enc1 = JasyptEncryptor("correctPassword")
        enc2 = JasyptEncryptor("wrongPassword")
        
        encrypted = enc1.encrypt("secret")
        
        with pytest.raises(ValueError):
            enc2.decrypt(encrypted)
    
    def test_decrypt_map(self):
        """Test decrypting a map of values."""
        enc = JasyptEncryptor("mapPassword")
        
        enc_pass = enc.encrypt_with_prefix("dbPassword123")
        enc_key = enc.encrypt_with_prefix("apiKey456")
        
        config = {
            "host": "localhost",
            "port": "3306",
            "password": enc_pass,
            "api_key": enc_key,
        }
        
        decrypted = enc.decrypt_map(config)
        
        assert decrypted["host"] == "localhost"
        assert decrypted["password"] == "dbPassword123"
        assert decrypted["api_key"] == "apiKey456"
    
    def test_decrypt_all_in_string(self):
        """Test decrypting all ENC values in a string."""
        enc = JasyptEncryptor("stringPassword")
        
        enc1 = enc.encrypt_with_prefix("user123")
        enc2 = enc.encrypt_with_prefix("pass456")
        
        input_str = f"username={enc1}\npassword={enc2}"
        result = enc.decrypt_all_in_string(input_str)
        
        assert "username=user123" in result
        assert "password=pass456" in result
    
    def test_custom_iterations(self):
        """Test with custom iteration count."""
        enc = JasyptEncryptor("password", iterations=2000)
        
        plaintext = "test value"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext


class TestJasyptStrongEncryptor:
    """Tests for JasyptStrongEncryptor (PBEWithHmacSHA256AndAES_256)."""
    
    def test_encrypt_decrypt_simple(self):
        """Test basic encryption and decryption."""
        enc = JasyptStrongEncryptor("mySecretPassword")
        
        plaintext = "hello"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_with_spaces(self):
        """Test encryption with spaces."""
        enc = JasyptStrongEncryptor("password")
        
        plaintext = "hello world"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_special_chars(self):
        """Test encryption with special characters."""
        enc = JasyptStrongEncryptor("password")
        
        plaintext = "p@$$w0rd!#$%"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_unicode(self):
        """Test encryption with unicode."""
        enc = JasyptStrongEncryptor("password")
        
        plaintext = "こんにちは世界"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_long_text(self):
        """Test encryption with long text."""
        enc = JasyptStrongEncryptor("password")
        
        plaintext = "This is a much longer text for testing AES-256 encryption."
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_with_prefix(self):
        """Test encryption with ENC(...) prefix."""
        enc = JasyptStrongEncryptor("strongPassword")
        
        plaintext = "sensitiveData"
        encrypted = enc.encrypt_with_prefix(plaintext)
        
        assert is_encrypted(encrypted)
        
        decrypted = enc.decrypt_prefixed(encrypted)
        assert decrypted == plaintext
    
    def test_custom_options(self):
        """Test with custom options."""
        enc = JasyptStrongEncryptor(
            "password",
            iterations=5000,
            salt_size=32
        )
        
        plaintext = "test"
        encrypted = enc.encrypt(plaintext)
        decrypted = enc.decrypt(encrypted)
        
        assert decrypted == plaintext
