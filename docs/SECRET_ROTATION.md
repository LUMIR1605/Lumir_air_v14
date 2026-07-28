# Obowiązkowa rotacja klucza YouTube

## Dlaczego

Plik `config/music_api.json` był śledzony przez Git i w co najmniej jednym historycznym commicie zawierał niepusty klucz `youtube.api_key`. Traktuj ten klucz jako ujawniony, nawet jeśli repozytorium było przez pewien czas prywatne.

## Co zrobić przed pushem RC6

1. Otwórz Google Cloud Console na koncie właściciela projektu.
2. Wybierz projekt używany przez starszy moduł muzyczny Lumir Air.
3. Wejdź do **APIs & Services → Credentials**.
4. Znajdź stary klucz YouTube Data API i go **unieważnij albo usuń**.
5. Jeżeli ten moduł ma nadal działać, utwórz nowy ograniczony klucz: ogranicz go do YouTube Data API i do wymaganych aplikacji lub adresów IP.
6. Lokalnie skopiuj `config/music_api.example.json` jako `config/music_api.json` i wpisz nowy klucz. Nie dodawaj tego pliku do Git.

## Historia Git

Ten etap nie przepisuje historii Git. Przed publicznym pushem lub udostępnieniem historii należy podjąć osobną decyzję o jej oczyszczeniu z kopii klucza, po utworzeniu kopii bezpieczeństwa repozytorium. Rotacja klucza jest obowiązkowa niezależnie od tej decyzji.
