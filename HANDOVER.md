# LUMÍR SHIELD — przekazanie projektu

Audyt wykonano 24 listopada 2026 r. dla `LUMIR1605/Lumir_air_v14`.

## Stan repozytorium i dysku

- GitHub i świeża kopia audytowa wskazały `main` na `1bbbbea` i `shield/account-discovery-v1` na `b65f044`. Wspólny przodek to `ad6eb02`. Od tego punktu `main` ma trzy własne commity, a gałąź Account Discovery dwa (`cf0fe7b`, `b65f044`). [Porównanie GitHub](https://github.com/LUMIR1605/Lumir_air_v14/compare/main...shield/account-discovery-v1)
- `main` zawiera wcześniejsze scalenie Account Discovery (`d881757`), wydanie desktopowe RC6 (`749f887`) i późniejszą poprawkę bezpieczeństwa (`1bbbbea`). Gałąź funkcjonalna dodaje zmiany integracji, raportów HTML/PDF, testów i przykładowych artefaktów.
- Dostępny był dysk środowiska Linux. W udostępnionych katalogach nie znaleziono wcześniejszej kopii projektu. Dysk użytkownika z systemem Windows był niedostępny, więc przegląd wszystkich lokalnych zmian, ich zabezpieczenie i porównanie z GitHubem pozostają otwarte. Świeża kopia audytowa potwierdza jedynie stan zdalny.
- GitHub nie zwrócił wydań w sekcji Releases. Lista tagów zawierała `rc1`. W drzewie `main` są źródła aplikacji i pliki budowania instalatora. Raport RC6 podaje oczekiwane ścieżki `dist/LumirShield.exe` oraz `release/LumirShield-Setup-RC6.exe` i ich sumy SHA-256. Obecność, zgodność i działanie tych binariów na Windows pozostają do sprawdzenia. [Raport wdrożenia RC6](docs/RC6_IMPLEMENTATION_REPORT.md)

## Zależności i testy

- Obie gałęzie mają identyczny `requirements.txt` z dolnymi ograniczeniami wersji. W oddzielnym środowisku Linux z Pythonem 3.12.14 instalacja się powiodła, a `pip check` nie wykazał konfliktów. Główne wersje użyte w audycie to pytest 9.2.0, pyflakes 4.1.0, Jinja2 3.1.6 i ReportLab 5.1.0. CI deklaruje Pythona 3.13.
- `python -m pytest -q --disable-socket tests` z pytest-socket 0.8.1 dał 19 zaliczonych testów na `main` i 23 na gałęzi Account Discovery. Na obu gałęziach przeszły także `compileall` i `pyflakes` dla `shield` i `shield.py`.
- Pierwszy przebieg pytest na gałęzi Account Discovery objął główny `test_shield.py`. Ten plik wywołuje analizę podczas importu także wtedy, gdy pytest dopiero zbiera testy. Gniazda sieciowe Pythona były zablokowane. Wyniki raportowane wyżej pochodzą z ponowionego przebiegu ograniczonego do `tests/`. Przed kolejną pełną kolekcją należy usunąć wywołanie analizy z etapu importu i zapewnić testy z atrapami.
- Holehe jest zewnętrznym poleceniem uruchamianym przez adapter i nie jest zadeklarowane w `requirements.txt`. Testy używają atrap procesu. Budowanie aplikacji i instalatora wymaga PyInstaller oraz Inno Setup. Ich dostępność na Windows oraz rzeczywista praca Holehe pozostają niezweryfikowane.

## Plan integracji po odzyskaniu kopii Windows

1. Wykonać kroki z [NEXT_TASK.md](NEXT_TASK.md). Po zabezpieczeniu prac użyć oddzielnej gałęzi i oddzielnego katalogu roboczego z aktualnego, zweryfikowanego `main` RC6.
2. Porównać `cf0fe7b` i `b65f044` z wcześniejszym scaleniem i zmianami RC6. Przenieść ręcznie brakujące fragmenty obsługi i raportowania Account Discovery wraz z testami. Szczególnej uwagi wymagają nakładające się zmiany w `shield/multi_scan.py`, `shield/pdf_report.py` i ścieżce generowania HTML. Zachować zgodność z aplikacją desktopową, walidacją wejścia, ścieżkami raportów i instalatorem RC6. Wyłączyć artefakty demonstracyjne oraz konfigurację danej instalacji z zakresu zmian.
3. Uruchomić testy bez dostępu sieciowego. Potwierdzić zgodę przed wywołaniem źródła, prawidłowe pokazanie prawdopodobnych usług, pustego wyniku, braku Holehe, limitu czasu i błędu procesu. Sprawdzić wynik oceny, oba formaty raportów oraz regresję dotychczasowych ścieżek aplikacji RC6.
4. Na Windows sprawdzić start aplikacji i wygenerować lokalne raporty z danymi testowymi. Zbudować instalator w osobnym katalogu, zweryfikować jego sumę SHA-256 i ścieżkę instalacji. Ewentualną próbę rzeczywistego Holehe wykonać dopiero po odrębnej zgodzie.

Etap odzyskiwania kończy się przed integracją kodu.

[Stan projektu](PROJECT_STATUS.md) · [Najbliższe zadanie](NEXT_TASK.md) · [Zasady pracy](WORKFLOW.md)
