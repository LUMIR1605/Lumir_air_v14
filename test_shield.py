from shield.core import analyze
from core.compat import configure_stdio

configure_stdio()

tests = [
    ("test@gmail.com", "email"),
    ("google.com", "domain"),
    ("https://github.com", "url"),
    ("lumir1605", "username"),
    ("+48123456789", "phone"),
]

print("\nLUMIR SHIELD INPUT DETECTION SMOKE TESTS\n")

passed = 0

for value, expected in tests:
    try:
        result = analyze(value)
        actual = result.get("scan_type")

        if actual == expected:
            print(f"✅ {value:30} -> {actual}")
            passed += 1
        else:
            print(f"❌ {value:30} -> {actual} (oczekiwano {expected})")

    except Exception as e:
        print(f"💥 {value}: {e}")

print(f"\nInput detection smoke tests: {passed}/{len(tests)}")

if passed == len(tests):
    print("\nSmoke tests passed. Run pytest for engine regression coverage.")
