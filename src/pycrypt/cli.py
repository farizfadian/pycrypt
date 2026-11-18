"""
PyCrypt CLI - Command line tool for encrypting and decrypting values.

Usage:
    pycrypt encrypt -p <password> -v <value>
    pycrypt decrypt -p <password> -v <encrypted_value>
    pycrypt encrypt-file -p <password> -i <input_file> -o <output_file>
    
Environment variable PYCRYPT_PASSWORD can be used instead of -p flag.

Made with ❤️ from Claude AI for Python developers who need Jasypt.
"""

import argparse
import os
import sys
from typing import Optional

from .encryptor import Encryptor
from .jasypt_compat import JasyptEncryptor, JasyptStrongEncryptor
from .utils import is_encrypted


__version__ = "1.0.1"


def get_password(args_password: Optional[str]) -> str:
    """Get password from args or environment variable."""
    if args_password:
        return args_password
    return os.environ.get('PYCRYPT_PASSWORD', '')


def create_encryptor(password: str, jasypt: bool = False, jasypt_strong: bool = False):
    """Create the appropriate encryptor based on flags."""
    if jasypt:
        return JasyptEncryptor(password)
    elif jasypt_strong:
        return JasyptStrongEncryptor(password)
    else:
        return Encryptor(password)


def cmd_encrypt(args):
    """Handle encrypt command."""
    password = get_password(args.password)
    if not password:
        print("Error: password is required (-p or PYCRYPT_PASSWORD)", file=sys.stderr)
        sys.exit(1)
    
    if not args.value:
        print("Error: value is required (-v)", file=sys.stderr)
        sys.exit(1)
    
    try:
        enc = create_encryptor(password, args.jasypt, args.jasypt_strong)
        
        if args.no_prefix:
            result = enc.encrypt(args.value)
        else:
            result = enc.encrypt_with_prefix(args.value)
        
        print(result)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_decrypt(args):
    """Handle decrypt command."""
    password = get_password(args.password)
    if not password:
        print("Error: password is required (-p or PYCRYPT_PASSWORD)", file=sys.stderr)
        sys.exit(1)
    
    if not args.value:
        print("Error: value is required (-v)", file=sys.stderr)
        sys.exit(1)
    
    try:
        enc = create_encryptor(password, args.jasypt, args.jasypt_strong)
        
        if is_encrypted(args.value):
            result = enc.decrypt_prefixed(args.value)
        else:
            result = enc.decrypt(args.value)
        
        print(result)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_encrypt_file(args):
    """Handle encrypt-file command."""
    password = get_password(args.password)
    if not password:
        print("Error: password is required (-p or PYCRYPT_PASSWORD)", file=sys.stderr)
        sys.exit(1)
    
    if not args.input:
        print("Error: input file is required (-i)", file=sys.stderr)
        sys.exit(1)
    
    try:
        enc = create_encryptor(password, args.jasypt, args.jasypt_strong)
        
        with open(args.input, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        output_lines = []
        for line in lines:
            stripped = line.strip()
            
            # Process lines with KEY=VALUE format
            if '=' in stripped and not stripped.startswith('#'):
                parts = stripped.split('=', 1)
                if len(parts) == 2:
                    key = parts[0]
                    value = parts[1].strip('"\'')
                    
                    # Encrypt if not already encrypted and not empty
                    if not is_encrypted(value) and value:
                        encrypted = enc.encrypt_with_prefix(value)
                        output_lines.append(f"{key}={encrypted}\n")
                        continue
            
            output_lines.append(line)
        
        # Write output
        output_file = args.output if args.output else sys.stdout
        if isinstance(output_file, str):
            with open(output_file, 'w', encoding='utf-8') as f:
                f.writelines(output_lines)
        else:
            for line in output_lines:
                print(line, end='')
                
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_decrypt_file(args):
    """Handle decrypt-file command."""
    password = get_password(args.password)
    if not password:
        print("Error: password is required (-p or PYCRYPT_PASSWORD)", file=sys.stderr)
        sys.exit(1)
    
    if not args.input:
        print("Error: input file is required (-i)", file=sys.stderr)
        sys.exit(1)
    
    try:
        enc = create_encryptor(password, args.jasypt, args.jasypt_strong)
        
        with open(args.input, 'r', encoding='utf-8') as f:
            content = f.read()
        
        decrypted = enc.decrypt_all_in_string(content)
        
        # Write output
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(decrypted)
        else:
            print(decrypted)
                
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        prog='pycrypt',
        description='PyCrypt - Jasypt-like encryption for Python configurations\n\n'
                    'Made with ❤️ from Claude AI for Python developers who need Jasypt',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--version', action='version', version=f'pycrypt {__version__}')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a single value')
    encrypt_parser.add_argument('-p', '--password', help='Encryption password')
    encrypt_parser.add_argument('-v', '--value', required=True, help='Value to encrypt')
    encrypt_parser.add_argument('--no-prefix', action='store_true', help="Don't wrap with ENC(...)")
    encrypt_parser.add_argument('--jasypt', action='store_true', help='Use Jasypt-compatible algorithm')
    encrypt_parser.add_argument('--jasypt-strong', action='store_true', help='Use Jasypt strong algorithm')
    encrypt_parser.set_defaults(func=cmd_encrypt)
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a single value')
    decrypt_parser.add_argument('-p', '--password', help='Encryption password')
    decrypt_parser.add_argument('-v', '--value', required=True, help='Value to decrypt')
    decrypt_parser.add_argument('--jasypt', action='store_true', help='Use Jasypt-compatible algorithm')
    decrypt_parser.add_argument('--jasypt-strong', action='store_true', help='Use Jasypt strong algorithm')
    decrypt_parser.set_defaults(func=cmd_decrypt)
    
    # Encrypt-file command
    encrypt_file_parser = subparsers.add_parser('encrypt-file', help='Encrypt all values in a file')
    encrypt_file_parser.add_argument('-p', '--password', help='Encryption password')
    encrypt_file_parser.add_argument('-i', '--input', required=True, help='Input file path')
    encrypt_file_parser.add_argument('-o', '--output', help='Output file path')
    encrypt_file_parser.add_argument('--jasypt', action='store_true', help='Use Jasypt-compatible algorithm')
    encrypt_file_parser.add_argument('--jasypt-strong', action='store_true', help='Use Jasypt strong algorithm')
    encrypt_file_parser.set_defaults(func=cmd_encrypt_file)
    
    # Decrypt-file command
    decrypt_file_parser = subparsers.add_parser('decrypt-file', help='Decrypt all ENC(...) values in a file')
    decrypt_file_parser.add_argument('-p', '--password', help='Encryption password')
    decrypt_file_parser.add_argument('-i', '--input', required=True, help='Input file path')
    decrypt_file_parser.add_argument('-o', '--output', help='Output file path')
    decrypt_file_parser.add_argument('--jasypt', action='store_true', help='Use Jasypt-compatible algorithm')
    decrypt_file_parser.add_argument('--jasypt-strong', action='store_true', help='Use Jasypt strong algorithm')
    decrypt_file_parser.set_defaults(func=cmd_decrypt_file)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    args.func(args)


if __name__ == '__main__':
    main()
