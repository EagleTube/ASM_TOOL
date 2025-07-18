import os
import lief
import pefile
from capstone import *
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Any
from constants import *

class ShellcodeAnalyzer:
    @staticmethod
    def detect_arch_mode(file_path: str) -> Tuple[Optional[str], Optional[str]]:
        """Detect architecture and mode from binary file with enhanced detection"""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
                
            if file_path.endswith(('.exe', '.dll', '.sys')):
                return ShellcodeAnalyzer._detect_pe_arch(file_path)
            else:
                return ShellcodeAnalyzer._detect_elf_arch(file_path)
        except Exception as e:
            print(f"[!] Detection error: {e}")
            return None, None

    @staticmethod
    def _detect_pe_arch(file_path: str) -> Tuple[Optional[str], Optional[str]]:
        """Detect PE file architecture"""
        pe = pefile.PE(file_path)
        if pe.FILE_HEADER.Machine == 0x14c:
            return "x86", "32"
        elif pe.FILE_HEADER.Machine == 0x8664:
            return "x86", "64"
        elif pe.FILE_HEADER.Machine == 0x1c0:  # ARM
            return "arm", "arm"
        elif pe.FILE_HEADER.Machine == 0xaa64:  # ARM64
            return "arm64", "64"
        return None, None

    @staticmethod
    def _detect_elf_arch(file_path: str) -> Tuple[Optional[str], Optional[str]]:
        """Detect ELF file architecture"""
        elf = lief.parse(file_path)
        if elf.header.machine_type == lief.ELF.ARCH.x86:
            return "x86", "64" if elf.header.identity_class == lief.ELF.ELFCLASS64 else "32"
        elif elf.header.machine_type == lief.ELF.ARCH.ARM:
            return "arm", "thumb" if elf.header.identity_data == lief.ELF.ELFDATA2LSB else "arm"
        elif elf.header.machine_type == lief.ELF.ARCH.AARCH64:
            return "arm64", "64"
        elif elf.header.machine_type == lief.ELF.ARCH.MIPS:
            return "mips", "mips64" if elf.header.identity_class == lief.ELF.ELFCLASS64 else "mips32"
        elif elf.header.machine_type == lief.ELF.ARCH.PPC64:
            return "ppc", "ppc64"
        return None, None

    @staticmethod
    def analyze_instructions(md: Cs, code: bytes) -> Tuple[Dict, List, Dict]:
        """Enhanced instruction analysis with more details"""
        dangerous = defaultdict(list)
        syscalls = []
        stats = defaultdict(int)
        
        for insn in md.disasm(code, 0x1000):
            stats['total'] += 1
            stats[insn.mnemonic] += 1
            
            if insn.mnemonic.lower() in DANGEROUS_OPS.get(md.arch_name, []):
                dangerous[insn.mnemonic].append((insn.address, insn.mnemonic, insn.op_str))
                
            if insn.mnemonic.lower() in ["syscall", "svc"] or \
               (insn.mnemonic.lower() == "int" and insn.op_str == "0x80"):
                syscalls.append((insn.address, insn.mnemonic, insn.op_str))
        
        return dangerous, syscalls, stats

    @staticmethod
    def disassemble(hex_code: str, arch: str, mode: str, 
                   reverse: bool = False, analyze: bool = False,
                   stats: bool = False) -> None:
        """Enhanced disassembler with more options"""
        try:
            code = bytes.fromhex(hex_code)
        except ValueError:
            print("[!] Invalid hex format.")
            return
            
        if reverse:
            code = code[::-1]

        try:
            md = Cs(CS_ARCHS[arch], CS_MODES[mode])
            md.detail = True
            md.arch_name = arch

            if analyze or stats:
                dangerous, syscalls, instr_stats = ShellcodeAnalyzer.analyze_instructions(md, code)
                ShellcodeAnalyzer._print_analysis_results(dangerous, syscalls, arch, mode)
                
                if stats:
                    ShellcodeAnalyzer._print_stats(instr_stats)

            print("\n[*] Disassembled:")
            for i in md.disasm(code, 0x1000):
                print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
        except CsError as e:
            print(f"[!] Capstone error: {e}")

    @staticmethod
    def _print_stats(stats: Dict) -> None:
        """Print instruction statistics"""
        print("\n[📊 Instruction Statistics]")
        total = stats.pop('total', 0)
        if total == 0:
            return
            
        print(f"  Total instructions: {total}")
        print("  Top instructions:")
        sorted_ops = sorted(stats.items(), key=lambda x: x[1], reverse=True)[:5]
        for op, count in sorted_ops:
            print(f"    {op}: {count} ({count/total:.1%})")

    @staticmethod
    def _print_analysis_results(dangerous: Dict, syscalls: List, arch: str, mode: str) -> None:
        """Enhanced analysis results printing"""
        print("\n[🔍 Instruction Analysis Results]")
        
        if dangerous:
            print("\n[!] Potentially dangerous operations found:")
            for op, entries in dangerous.items():
                print(f"  {op.upper()}: {len(entries)} occurrences")
                for addr, mnemonic, op_str in entries[:3]:
                    print(f"    0x{addr:x}: {mnemonic} {op_str}")
                if len(entries) > 3:
                    print(f"    ...and {len(entries)-3} more")
        else:
            print("[+] No dangerous operations detected")

        if syscalls:
            print("\n[!] System calls detected:")
            for addr, mnemonic, op_str in syscalls:
                print(f"    0x{addr:x}: {mnemonic} {op_str}")
                if arch in SYSCALLS and mode in SYSCALLS[arch]:
                    print("      Possible syscall numbers:")
                    for name, num in SYSCALLS[arch][mode].items():
                        print(f"        {name}: {num}")
        else:
            print("[+] No system calls detected")