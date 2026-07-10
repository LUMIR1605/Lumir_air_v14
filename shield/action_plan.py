def build(report):
    score = report["modules"][0]["risk_score"]["score"]

    now = []
    today = []
    later = []

    if score >= 90:
        today.append("Włącz uwierzytelnianie dwuskładnikowe (2FA), jeśli jeszcze go nie używasz.")
        later.append("Sprawdzaj wycieki danych raz w miesiącu.")
        later.append("Używaj unikalnych haseł dla każdego serwisu.")

    elif score >= 70:
        now.append("Zmień hasła do najważniejszych kont.")
        today.append("Włącz 2FA.")
        later.append("Usuń nieużywane konta internetowe.")

    elif score >= 40:
        now.append("Natychmiast zmień hasła.")
        now.append("Sprawdź aktywne sesje logowania.")
        today.append("Włącz 2FA.")
        later.append("Przejrzyj ustawienia prywatności.")

    else:
        now.append("Natychmiast zabezpiecz wszystkie konta.")
        now.append("Zmień hasła i sprawdź urządzenia.")
        today.append("Zweryfikuj adresy e-mail odzyskiwania.")
        later.append("Uruchom pełny audyt bezpieczeństwa.")

    return {
        "now": now,
        "today": today,
        "later": later
    }
