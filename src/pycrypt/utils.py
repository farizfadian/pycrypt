"""
Utility functions for PyCrypt.
"""

import re
from typing import Pattern

# Constants
ENC_PREFIX = "ENC("
ENC_SUFFIX = ")"

# Regex pattern to match ENC(...) values
ENC_PATTERN: Pattern = re.compile(r'ENC\(([^)]+)\)')


def is_encrypted(value: str) -> bool:
    """
    Check if a value is in ENC(...) format.
    
    Args:
        value: The value to check
        
    Returns:
        True if value is in ENC(...) format
        
    Example:
        >>> is_encrypted("ENC(abc123)")
        True
        >>> is_encrypted("plaintext")
        False
    """
    if not value:
        return False
    value = value.strip()
    return value.startswith(ENC_PREFIX) and value.endswith(ENC_SUFFIX)
