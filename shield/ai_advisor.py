def advise(result):
    risk = result.get("risk", "low")

    advice = []

    if risk == "high":
        advice.extend([
            "Natychmiast zmień hasła.",
            "Włącz uwierzytelnianie dwuskładnikowe (2FA).",
            "Sprawdź aktywne sesje logowania."
        ])

    elif risk == "medium":
        advice.extend([
            "Przejrzyj ustawienia bezpieczeństwa.",
            "Sprawdź, czy używasz unikalnych haseł."
        ])

    else:
        advice.append(
            "Nie wykryto istotnych zagrożeń. Zachowaj dobre praktyki bezpieczeństwa."
        )

    return advice
