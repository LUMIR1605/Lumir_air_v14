# Lumir SHIELD RC6 — raport wdrożenia

## Cel

Wdrożono bezpieczny przepływ kontroli własnych danych dla trzech typów wejścia: adresu e-mail, numeru telefonu i nicku. Silnik Truth Engine oraz formuła scoringu nie zostały zmienione.

## Wdrożony zakres

| Typ | Walidacja i normalizacja | Wykonany zakres | Uczciwe ograniczenie |
|---|---|---|---|
| E-mail | format oraz domena IDNA | DNS/MX/SPF/DKIM/DMARC, opcjonalnie HIBP, opcjonalny lokalny moduł kont | HIBP bez klucza ma status niedostępny; prawdopodobne konta nie są potwierdzeniem i nie zmieniają score. |
| Telefon | numer do formatu E.164 | lokalne metadane numeracji: format, obszar i operator, jeżeli dane są dostępne | brak reverse lookupu, brak identyfikacji osoby i brak potwierdzenia własności. |
| Nick | 1–39 bezpiecznych znaków | jeden publiczny profil GitHub przez oficjalne API | zgodność nicku nie potwierdza tożsamości ani własności konta. |

Każdy moduł przekazuje źródło, status i poziom pewności. Gdy nie ma twardego potwierdzenia, raport używa statusu `niepotwierdzone` lub odpowiedniego statusu źródła zamiast zgadywania.

## Zgoda i prywatność

- GUI wymaga zaznaczenia zgody.
- `shield.multi_scan.run` blokuje wszystkie trzy przepływy bez `consent_declared=True`, więc wymogu nie można obejść przez wywołanie silnika.
- Nie dodano logowania do kont, omijania zabezpieczeń, skanowania prywatnych danych, przeszukiwania wielu serwisów ani identyfikacji osoby po numerze.

## Raporty

Raporty JSON, HTML i PDF zapisują się lokalnie pod:

`%USERPROFILE%\Lumir SHIELD\Reports`

Nie korzystają z folderu Dokumenty, OneDrive ani katalogu instalacyjnego. Każdy skan ma osobny znacznik czasu w nazwie pliku.

## Weryfikacja

- `pytest`: **19 passed**.
- Smoke test wejść: **5/5**.
- `pyflakes`, `compileall` i `git diff --check`: bez błędów.
- Wygenerowano i wizualnie sprawdzono PDF-y dla e-maila, telefonu i nicku.
- EXE: `dist\LumirShield.exe`, SHA-256 `005A28C64FEEA4A119EBAAC8403F90BD301592D33A801DBD62DA8E7020504493`.
- Instalator: `release\LumirShield-Setup-RC6.exe`, SHA-256 `54EE74D3FC2BA17601EF26F0D4EA8E0F42FE209E9907A321749EA4B8A816090A`.

## Pozostałe ryzyko wydaniowe

Polityka kontroli aplikacji bieżącego środowiska blokuje uruchomienie nowo zbudowanego, niepodpisanego EXE. Nie zastosowano obejścia. Przed dystrybucją poza własnym komputerem należy podpisać EXE i instalator certyfikatem code-signing albo przeprowadzić zatwierdzony test instalacyjny na komputerze bez takiej polityki.
