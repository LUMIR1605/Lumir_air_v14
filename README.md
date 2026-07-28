# Lumir SHIELD

Lumir SHIELD to aplikacja Windows do bezpiecznej kontroli **własnych danych** cyfrowych. Nie loguje się do kont, nie omija zabezpieczeń i nie wykonuje identyfikacji osób.

## Obsługiwane dane

- **Adres e-mail** — lokalna analiza konfiguracji domeny pocztowej (DNS/MX/SPF/DKIM/DMARC), opcjonalnie HIBP po osobnej konfiguracji klucza oraz opcjonalny lokalny moduł kont po wyraźnej zgodzie.
- **Numer telefonu** — wyłącznie lokalna walidacja formatu i metadanych numeracji. Nie jest to reverse lookup ani identyfikacja właściciela.
- **Nick / username** — walidacja nicku oraz pojedyncze sprawdzenie publicznego profilu GitHub przez oficjalne API. Zgodność nicku nigdy nie jest dowodem tożsamości.

Każdy raport zawiera źródła, status, poziom pewności i wyraźne oznaczenie `niepotwierdzone`, gdy brakuje twardego dowodu.

## Użycie Windows

Zainstaluj `release\LumirShield-Setup-RC6.exe`. Instalator tworzy skrót **Lumir SHIELD** na pulpicie oraz w menu Start. Po uruchomieniu:

1. Wybierz typ danych lub pozostaw automatyczne wykrywanie.
2. Wpisz własny e-mail, numer telefonu albo nick.
3. Potwierdź uprawnienie do skanowania.
4. Kliknij **ROZPOCZNIJ SKAN**.

Raporty JSON, HTML i PDF są zapisywane lokalnie w `%USERPROFILE%\Lumir SHIELD\Reports` — bez używania OneDrive.

## Weryfikacja programistyczna

```powershell
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe test_shield.py
```

## Ograniczenia

Wynik techniczny dotyczy wyłącznie wykonanego zakresu. Niedostępne źródło, limit API lub brak twardego potwierdzenia nie są traktowane jako negatywny wynik.
