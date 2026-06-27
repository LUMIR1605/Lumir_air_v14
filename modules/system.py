import platform
import sys

def check_system():
    print(f"🖥 System : {platform.system()}")
    print(f"⚙️ Wersja : {platform.release()}")
    print(f"🐍 Python : {sys.version.split()[0]}")
    print()
