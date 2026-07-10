from shield.core import analyze

tests = [
    ("test@gmail.com", "email"),
    ("google.com", "domain"),
    ("https://github.com", "url"),
    ("lumir1605", "username"),
    ("+48123456789", "phone"),
]

print("\n🛡 LUMIR SHIELD TEST SUITE\n")

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

print(f"\nWynik: {passed}/{len(tests)} testów zakończonych sukcesem.")

if passed == len(tests):
    print("\n🏆 ALL TESTS PASSED")
