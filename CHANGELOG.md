# Changelog

## RC6 — 2026-07-28

- Dodano bezpieczny przepływ skanowania własnego adresu e-mail, numeru telefonu i nicku.
- Dodano walidację oraz normalizację e-maila, telefonu do E.164 i nicku.
- Wymóg zgody właściciela jest egzekwowany przez silnik, a nie tylko interfejs.
- Telefon korzysta wyłącznie z lokalnych metadanych; nie wykonuje reverse lookupu ani identyfikacji osoby.
- Nick korzysta wyłącznie z publicznego endpointu GitHub API; wynik zawsze oznacza własność jako niepotwierdzoną.
- Raporty JSON, HTML i PDF mają osobne nazwy i trafiają lokalnie do `%USERPROFILE%\Lumir SHIELD\Reports`.
- Zbudowano `LumirShield.exe` i `LumirShield-Setup-RC6.exe`.

## 1.0 Preview

### Dodano

- Email Scan
- Domain Scan
- URL Scan
- Username Scan
- Phone Scan
- Breach Scan
- Security Score
- Executive Summary
- Action Plan
- Attack Surface
- HTML Report
- Test Suite

### Status

Projekt jest aktywnie rozwijany.
