# language: Python 3, file: launcher.py, target: Cross-Platform
# CLI Launcher and Manager for the PARALELEPIPEDO Toolkit
import os
import sys
import subprocess

def list_tools():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    print("=" * 60)
    print("            PARALELEPIPEDO ATTACK TOOLKIT - LAUNCHER")
    print("=" * 60)
    
    categories = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d)) and not d.startswith('.')]
    
    tools = []
    idx = 1
    for cat in sorted(categories):
        cat_path = os.path.join(base_dir, cat)
        files = [f for f in os.listdir(cat_path) if f.endswith('.py') or f.endswith('.sh')]
        if files:
            print(f"\n[{cat}]")
            for f in sorted(files):
                full_p = os.path.join(cat_path, f)
                tools.append(full_p)
                print(f"  {idx:2d}. {f}")
                idx += 1
                
    root_files = [f for f in os.listdir(base_dir) if (f.endswith('.py') and f != 'launcher.py')]
    if root_files:
        print(f"\n[Root Tools]")
        for f in sorted(root_files):
            full_p = os.path.join(base_dir, f)
            tools.append(full_p)
            print(f"  {idx:2d}. {f}")
            idx += 1

    print("\n" + "=" * 60)
    return tools

def main():
    tools = list_tools()
    choice = input("\nSelect a tool number to run (or 'q' to quit): ").strip()
    if choice.lower() == 'q':
        sys.exit(0)
        
    try:
        num = int(choice)
        if 1 <= num <= len(tools):
            target_script = tools[num - 1]
            print(f"\n[*] Launching: {target_script}\n")
            if target_script.endswith('.py'):
                subprocess.run([sys.executable, target_script])
            else:
                subprocess.run(["bash", target_script])
        else:
            print("[!] Invalid selection.")
    except ValueError:
        print("[!] Please enter a valid number.")

if __name__ == "__main__":
    main()
