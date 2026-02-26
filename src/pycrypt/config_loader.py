"""
Configuration file loader with automatic decryption.
"""

import os
import json
from typing import Dict, Any, Optional
from pathlib import Path

from .encryptor import Encryptor
from .utils import is_encrypted


class ConfigLoader:
    """
    Configuration file loader that automatically decrypts ENC(...) values.
    
    Supports .env, YAML (simple), and JSON files.
    
    Example:
        >>> loader = ConfigLoader("myPassword")
        >>> config = loader.load_env_file(".env")
        >>> print(config["DATABASE_PASSWORD"])  # decrypted value
        
        >>> # Load and set as environment variables
        >>> loader.set_to_env(".env")
        >>> print(os.getenv("DATABASE_PASSWORD"))
    """
    
    def __init__(self, password: str, **kwargs):
        """
        Initialize the ConfigLoader.
        
        Args:
            password: The encryption password
            **kwargs: Additional arguments passed to Encryptor
        """
        self.encryptor = Encryptor(password, **kwargs)
    
    def load_env_file(self, filepath: str) -> Dict[str, str]:
        """
        Load and decrypt a .env file.
        
        Args:
            filepath: Path to the .env file
            
        Returns:
            Dictionary of key-value pairs with decrypted values
        """
        config = {}
        
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Split by first =
                if '=' not in line:
                    continue
                
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Remove surrounding quotes
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                
                # Decrypt if encrypted
                if is_encrypted(value):
                    try:
                        value = self.encryptor.decrypt_prefixed(value)
                    except Exception as e:
                        pass  # Keep original on error
                
                config[key] = value
        
        return config
    
    def load_yaml(self, filepath: str) -> Dict[str, str]:
        """
        Load and decrypt a simple YAML file.
        
        Note: This is a simplified YAML parser that handles basic key-value pairs.
        For complex YAML structures, use a full YAML library like PyYAML.
        
        Args:
            filepath: Path to the YAML file
            
        Returns:
            Dictionary of key-value pairs with decrypted values
        """
        config = {}
        
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Split by first :
                if ':' not in line:
                    continue
                
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                # Remove surrounding quotes
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                
                # Decrypt if encrypted
                if is_encrypted(value):
                    try:
                        value = self.encryptor.decrypt_prefixed(value)
                    except Exception as e:
                        pass
                
                config[key] = value
        
        return config
    
    def load_json(self, filepath: str) -> Dict[str, Any]:
        """
        Load and decrypt a JSON configuration file.
        
        Recursively decrypts all ENC(...) string values.
        
        Args:
            filepath: Path to the JSON file
            
        Returns:
            Dictionary with all ENC(...) values decrypted
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        return self._decrypt_recursive(config)
    
    def _decrypt_recursive(self, obj: Any) -> Any:
        """Recursively decrypt all ENC(...) values in an object."""
        if isinstance(obj, str):
            if is_encrypted(obj):
                try:
                    return self.encryptor.decrypt_prefixed(obj)
                except:
                    return obj
            return obj
        elif isinstance(obj, dict):
            return {k: self._decrypt_recursive(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._decrypt_recursive(item) for item in obj]
        else:
            return obj
    
    def set_to_env(self, filepath: str) -> None:
        """
        Load an env file and set values as environment variables.
        
        Args:
            filepath: Path to the .env file
        """
        config = self.load_env_file(filepath)
        for key, value in config.items():
            os.environ[key] = value
