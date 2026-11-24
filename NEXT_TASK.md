# Najbliższe zadanie

Udostępnić Codexowi środowisko z istniejącym katalogiem projektu i plikami RC6 na Windows. Po uzyskaniu dostępu Codex wykona poniższe kroki bez obsługi terminala przez użytkownika.

1. Zidentyfikować repozytorium po adresie zdalnym oraz sprawdzić gałąź, indeks, zmiany robocze, pliki nieśledzone, wpisy stash i lokalne commity. Uwzględnić ignorowane pliki związane z projektem.
2. Utworzyć prywatną kopię roboczą wraz z metadanymi Git poza katalogiem projektu. Zweryfikować spójność kopii i możliwość odzyskania indeksu oraz plików. Chronić konfiguracje, raporty i klucze przed publikacją.
3. Po zabezpieczeniu prac pobrać referencje GitHub i porównać lokalne gałęzie z ich odpowiednikami bez przełączania aktywnej gałęzi czy scalania.
4. Odszukać plik aplikacji i instalator RC6 oraz porównać ich sumy SHA-256 z [raportem wdrożenia](docs/RC6_IMPLEMENTATION_REPORT.md). Ustalić wersje Pythona i zależności lokalnego środowiska. Zapisać wynik w [HANDOVER.md](HANDOVER.md).

Punkt zatrzymania to udokumentowana kopia, porównanie lokalne i raport o plikach RC6. Integracja kodu stanowi kolejny etap.
