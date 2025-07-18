from enum import Enum, auto
from typing import Dict, List, Callable, Any, Tuple, Optional, Union
from capstone import (
    CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_MIPS, CS_ARCH_PPC,
    CS_MODE_16, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB,
    CS_MODE_MIPS32, CS_MODE_MIPS64
)

MAX_SHELLCODE_SIZE = 4096
DEFAULT_KEY = 0xAA
MIN_PORT = 1
MAX_PORT = 65535

class Architecture(Enum):
    X86 = auto()
    X64 = auto()
    ARM = auto()
    ARM64 = auto()
    MIPS = auto()
    PPC = auto()

class Mode(Enum):
    MODE_16 = auto()
    MODE_32 = auto()
    MODE_64 = auto()
    ARM = auto()
    THUMB = auto()
    MIPS32 = auto()
    MIPS64 = auto()
    PPC32 = auto()
    PPC64 = auto()

class EncodingType(Enum):
    XOR = auto()
    NOT = auto()
    ADD = auto()
    ROT = auto()
    MULTI = auto()
    CHAIN = auto()

class ShellcodeType(Enum):
    REVERSE = auto()
    BIND = auto()
    EXEC = auto()
    DOWNLOAD = auto()
    STAGED = auto()
    CUSTOM = auto()

CS_ARCHS = {
    "x86": CS_ARCH_X86,
    "x64": CS_ARCH_X86,  # still x86 arch, but with CS_MODE_64
    "arm": CS_ARCH_ARM,
    "arm64": CS_ARCH_ARM64,
    "mips": CS_ARCH_MIPS,
    "ppc": CS_ARCH_PPC
}

CS_MODES = {
    "16": CS_MODE_16,
    "32": CS_MODE_32,
    "64": CS_MODE_64,
    "arm": CS_MODE_ARM,
    "thumb": CS_MODE_THUMB,
    "mips32": CS_MODE_MIPS32,
    "mips64": CS_MODE_MIPS64,
    "ppc32": CS_MODE_32,
    "ppc64": CS_MODE_64
}

KS_ARCHS: Dict[str, int] = {
    "x86": 0,    # KS_ARCH_X86
    "x64": 0,    # KS_ARCH_X86
    "arm": 1,    # KS_ARCH_ARM
    "arm64": 2,  # KS_ARCH_ARM64
    "mips": 3,   # KS_ARCH_MIPS
    "ppc": 4     # KS_ARCH_PPC
}

KS_MODES: Dict[str, int] = {
    "16": 1 << 1,    # KS_MODE_16
    "32": 1 << 2,    # KS_MODE_32
    "64": 1 << 3,    # KS_MODE_64
    "arm": 0,        # KS_MODE_ARM
    "thumb": 1 << 4, # KS_MODE_THUMB
    "mips32": 1 << 2,# KS_MODE_MIPS32
    "mips64": 1 << 3,# KS_MODE_MIPS64
    "ppc32": 1 << 2, # KS_MODE_32
    "ppc64": 1 << 3  # KS_MODE_64
}

ENCODERS: Dict[str, Callable[[int, int], int]] = {
    "xor": lambda b, k: b ^ k,
    "not": lambda b, k: ~b & 0xFF,
    "add": lambda b, k: (b + k) & 0xFF,
    "rot": lambda b, k: ((b << k) | (b >> (8 - k))) & 0xFF,
    "multi": lambda b, k: (b * k) & 0xFF,
}

DANGEROUS_OPS: Dict[str, List[str]] = {
    "x86": ["syscall", "int", "sysenter", "call", "jmp", "iret", "sidt", "sgdt"],
    "x64": ["syscall", "sysret", "int", "call", "jmp"],
    "arm": ["svc", "blx", "bl", "bx", "smc"],
    "arm64": ["svc", "blr", "br", "bl", "smc"],
    "mips": ["syscall", "jal", "jalr", "break"],
    "ppc": ["sc", "bl", "bcl", "mtspr"]
}

SYSCALLS: Dict[str, Dict] = {
    "x86": {
        "32": {"execve": 11, "exit": 1, "read": 3, "write": 4, "open": 5, "mmap": 90},
        "64": {"execve": 59, "exit": 60, "read": 0, "write": 1, "open": 2, "mmap": 9}
    },
    "arm": {
        "execve": 11, "exit": 1, "read": 3, "write": 4, "open": 5, "mmap": 192
    },
    "arm64": {
        "execve": 221, "exit": 93, "read": 63, "write": 64, "open": 56, "mmap": 222
    },
    "mips": {
        "execve": 4011, "exit": 4001, "read": 4003, "write": 4004
    }
}
