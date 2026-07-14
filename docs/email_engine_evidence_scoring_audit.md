# Email Engine Evidence Scoring Audit

## Cel

Zastapienie mapy `LOW=95` punktacja oparta na rzeczywistych kontrolach DNS.

## Zmiany

- `shield.email_scan.scan`: score basis dla formatu, MX, SPF, DMARC i DKIM; DNS timeout, brak odpowiedzi i NXDOMAIN maja rozne kody.
- `shield.domain_scan.scan`: Domain DNS Availability z kontrolami resolution, A/AAAA, MX i NS; bez HTTPS i web probing.
- `shield.truth.assessment`: module coverage i control coverage oraz blokada pelnego verdictu przy insufficient reliability.
- `shield.py`: terminal przedstawia assessment V3, oba coverage i statusy modulow.

## Ograniczenia i zablokowane funkcje

Account exposure pozostaje `blocked`. Holehe, Sherlock, Maigret, enumeracja kont, phone expansion i public web probing pozostaja poza zakresem.

## Zrodla

Aktywne: `local_dns`, `hibp_v3` (tylko z legalnym kluczem). Pending/disabled: `public_web_probe`.

## Przyklad rzeczywistego wyniku

`test@example.com`: module coverage 20%, control coverage 55%, reliability `insufficient`; publiczny verdict nie przedstawia wyniku technicznego jako pelnej oceny.

## Testy regresyjne

`tests/test_truthfulness.py` obejmuje brak klucza HIBP, coverage i walidacje niedozwolonego score dla unavailable modulu. Dalsze testy DNS wymagaja mockow resolvera.
