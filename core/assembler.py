from keystone import Ks, KsError
from constants import KS_ARCHS, KS_MODES
from utils.validator import ShellcodeValidator
from core.optimizer import ShellcodeOptimizer
from core.encoder import ShellcodeEncoder
from core.evasion import EvasionTechniques
from typing import Optional, Dict, Any

class ShellcodeAssembler:
    @staticmethod
    def assemble(asm_code: str, arch: str, mode: str, **kwargs) -> Optional[bytes]:
        """Enhanced assembler with better error handling"""
        asm_code = ShellcodeAssembler._clean_asm(asm_code)
        
        try:
            ks = Ks(KS_ARCHS[arch], KS_MODES[mode])
            encoding, _ = ks.asm(asm_code)
            shellcode = bytes(encoding)
        except KsError as e:
            print(f"[!] Keystone error: {e}")
            return None

        # Validate shellcode before transformations
        try:
            ShellcodeValidator.validate_shellcode(shellcode)
        except ValueError as e:
            print(f"[!] Shellcode validation failed: {e}")
            return None

        # Apply transformations
        if kwargs.get('reverse'):
            shellcode = shellcode[::-1]
            print("[*] Reversed shellcode bytes")

        if kwargs.get('optimize'):
            shellcode = ShellcodeOptimizer.optimize(shellcode, arch, mode)

        if kwargs.get('evasion'):
            shellcode = EvasionTechniques.apply(shellcode, kwargs['evasion'].split(","))

        if kwargs.get('decode_xor') and kwargs.get('xor_key'):
            try:
                key = int(kwargs['xor_key'], 0)
                shellcode = ShellcodeEncoder.encode_bytes(shellcode, "xor", key)
                print("[*] XOR Decoded")
            except Exception as e:
                print(f"[!] XOR decode failed: {e}")
                return None

        return shellcode

    @staticmethod
    def _clean_asm(code: str) -> str:
        """Enhanced assembly code cleaning"""
        lines = []
        for line in code.splitlines():
            # Remove comments
            line = line.split(';')[0].strip()
            if line:
                lines.append(line)
        return '\n'.join(lines)