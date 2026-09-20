# Document Intelligence v1

## IMPLEMENTED

`DocumentIntelligenceCollector` accepts public PDF, TXT, HTML and XHTML only. Fetch size is capped at 2 MB; extracted text is capped; PDF processing is text-only with `pypdf`, strict parsing, at most 100 pages and encrypted-PDF rejection. Executables, archives and macro-enabled suffixes are rejected. JavaScript, macros, archives and embedded files are never executed.

The adapter extracts visible email, phone, domain, dates, title and author metadata. Old contacts remain historical evidence and receive stale review, not deletion.

## NOT IMPLEMENTED

- OCR, DOC/DOCX parsing, archive expansion, macros or embedded-file execution.
