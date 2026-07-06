from datetime import datetime

def header():
    """Print report header"""
    print("=" * 60)
    print("🧠 LUMIR AIR")
    print("=" * 60)
    print(datetime.now().strftime("📅 %d-%m-%Y %H:%M"))
    print()

def section(title):
    """Print report section"""
    print()
    print("─" * 60)
    print(title)
    print("─" * 60)
