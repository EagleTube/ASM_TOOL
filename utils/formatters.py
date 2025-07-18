import base64
from typing import Union

class ShellcodeFormatter:
    @staticmethod
    def format_escaped(shellcode: bytes) -> str:
        """Format as \x41\x42\x43 style string"""
        return ''.join(f'\\x{b:02x}' for b in shellcode)
    
    @staticmethod
    def format_inline(shellcode: bytes) -> str:
        """Format as 41 42 43 style string"""
        return ' '.join(f'{b:02x}' for b in shellcode)
    
    @staticmethod
    def format_hex(shellcode: bytes) -> str:
        """Format as 414243 style string"""
        return ''.join(f'{b:02x}' for b in shellcode)
    
    @staticmethod
    def format_raw(shellcode: bytes) -> bytes:
        """Return raw bytes"""
        return shellcode
    
    @staticmethod
    def format_c(shellcode: bytes) -> str:
        """Format as C-style byte array"""
        hex_str = ', '.join(f'0x{b:02x}' for b in shellcode)
        return f"unsigned char shellcode[] = {{ {hex_str} }};"
    
    @staticmethod
    def format_python(shellcode: bytes) -> str:
        """Format as Python bytes"""
        escaped = ShellcodeFormatter.format_escaped(shellcode)
        return f'shellcode = b"{escaped}"'
    
    @staticmethod
    def format_base64(shellcode: bytes) -> str:
        """Format as base64 encoded string"""
        return base64.b64encode(shellcode).decode('utf-8')
    
    @staticmethod
    def format(shellcode: bytes, fmt: str) -> Union[str, bytes]:
        """Format shellcode according to specified format"""
        formatters = {
            "escaped": ShellcodeFormatter.format_escaped,
            "inline": ShellcodeFormatter.format_inline,
            "hex": ShellcodeFormatter.format_hex,
            "raw": ShellcodeFormatter.format_raw,
            "c": ShellcodeFormatter.format_c,
            "python": ShellcodeFormatter.format_python,
            "base64": ShellcodeFormatter.format_base64
        }
        if fmt not in formatters:
            raise ValueError(f"Unsupported format: {fmt}")
        return formatters[fmt](shellcode)