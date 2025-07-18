import hashlib
import socket
from typing import Dict, Any
from constants import *

class ShellcodeValidator:
    @staticmethod
    def validate_shellcode(shellcode: bytes) -> bool:
        """Basic validation of shellcode"""
        if not shellcode:
            raise ValueError("Empty shellcode")
        if len(shellcode) > MAX_SHELLCODE_SIZE:
            raise ValueError(f"Shellcode too large (max {MAX_SHELLCODE_SIZE} bytes)")
        return True
    
    @staticmethod
    def _validate_ip_port(ip: str, port: int) -> bool:
        """Validate IP and port"""
        try:
            socket.inet_aton(ip)
            if not (MIN_PORT <= port <= MAX_PORT):
                return False
            return True
        except socket.error:
            return False    
    
    @staticmethod
    def contains_null_bytes(shellcode: bytes) -> bool:
        """Check for null bytes in shellcode"""
        return b'\x00' in shellcode
    
    @staticmethod
    def get_entropy(data: bytes) -> float:
        """Calculate entropy of data"""
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x)
        return entropy
    
    @staticmethod
    def analyze_shellcode(shellcode: bytes) -> Dict[str, Any]:
        """Perform comprehensive analysis of shellcode"""
        analysis = {
            "length": len(shellcode),
            "null_bytes": ShellcodeValidator.contains_null_bytes(shellcode),
            "entropy": ShellcodeValidator.get_entropy(shellcode),
            "md5": hashlib.md5(shellcode).hexdigest(),
            "sha1": hashlib.sha1(shellcode).hexdigest(),
            "sha256": hashlib.sha256(shellcode).hexdigest()
        }
        return analysis