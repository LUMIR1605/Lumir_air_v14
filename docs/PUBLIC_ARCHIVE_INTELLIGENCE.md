# Public Archive Intelligence v1

## IMPLEMENTED

`PublicArchiveCollector` uses the official Common Crawl collection list and a current public CDX index endpoint. Queries are exact, serial and limited to five snapshot candidates. Results include timestamps, URL, MIME/status, digest and WARC location metadata.

Archive results are `TEMPORAL EVIDENCE`: they are marked stale/historical and never describe the current state by themselves. Wayback CDX remains disabled pending a separate automation/availability review.

## NOT IMPLEMENTED

- Archive replay crawling, bulk index scans or current ownership inference.
