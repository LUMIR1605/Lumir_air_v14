# Workflow RC7

1. Odczytaj AGENTS i handover; sprawdź git status i bazę gałęzi. Zachowaj wcześniejsze kopie.
2. Wprowadzaj selektywne zmiany wyłącznie w izolowanej kopii. Nie resetuj oryginalnej gałęzi użytkownika.
3. Używaj istniejącego zgodnego Pythona albo projektowego venv. Zestaw przetestowanych pakietów: requirements-rc7.txt. Nie instaluj globalnie.
4. Testy: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1, python -B -m pytest -q -p no:cacheprovider. conftest blokuje sieć i procesy przed kolekcją. Mocki zastępują źródła.
5. Sprawdź pyflakes zmienionych modułów, pip check i git diff --check. Dla raportów użyj generatora tools/demo_reports.py z PYTHONPATH wskazującym repo i katalogiem wyjściowym poza repo.
6. Obejrzyj HTML desktop/mobile i wszystkie strony PDF; nie uznawaj ekstrakcji tekstu za test wyglądu.
7. Przejrzyj cały diff, nowe pliki i listę staged pod kątem danych, sekretów i regresji. Raporty rzeczywiste pozostają lokalne. Publikuj wyłącznie przeglądnięty kod, testy i dokumentację.
8. Commit i push tylko na gałąź roboczą, bez force i merge. Potwierdź SHA gałęzi zdalnej. Zaktualizuj HANDOVER/STATUS/NEXT_TASK.

Wycofanie: wróć do istniejącej aplikacji RC6. Zachowaj kopię RC7 do analizy; nie usuwaj ani nie resetuj oryginałów.
