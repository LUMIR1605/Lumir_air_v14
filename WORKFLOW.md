# Zasady pracy

- Zacznij od [HANDOVER.md](HANDOVER.md), [PROJECT_STATUS.md](PROJECT_STATUS.md) i [NEXT_TASK.md](NEXT_TASK.md). Aktualizuj je po każdym etapie, zapisując podstawę ustaleń, wyniki testów i otwarte pozycje.
- Przed zmianami sprawdź stan kopii użytkownika. Gdy istnieją lokalne prace, zabezpiecz je w zweryfikowanej kopii prywatnej. Pracuj w osobnej kopii lub katalogu roboczym z ustalonego commitu. Zachowaj pliki użytkownika. Obowiązuje zakaz `git reset --hard` i force push.
- W osobnym środowisku Pythona instaluj zależności z `requirements.txt`. Do testów regresji używaj atrap źródeł i blokady gniazd sieciowych. Zapisuj wersję Pythona, polecenia i wyniki. Kompilację i pyflakes przeprowadzaj zgodnie z `.github/workflows/shield-tests.yml`.
- Weryfikuj artefakty Windows z lokalnego dysku. Zachowaj obecne ustawienia zabezpieczeń Windows. Rzeczywisty skan wymaga uprzedniej zgody.
- Przed publikacją sprawdź różnicę względem bazy. Publikuj tylko uzgodnione pliki. Dane osobowe, klucze, lokalne konfiguracje, raporty robocze i kopie zapasowe przechowuj prywatnie.
