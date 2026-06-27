from datetime import datetime

def header():
    print("=" * 60)
    print("🧠 LUMIR AIR")
    print("=" * 60)
    print(datetime.now().strftime("📅 %d-%m-%Y %H:%M"))
    print()

def section(title):
    print()
    print("─" * 60)
    print(title)
    print("─" * 60)
