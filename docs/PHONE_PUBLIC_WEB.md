# Phone Public Web

## IMPLEMENTED

Production `PhonePublicWebCollector` uses the bounded multi-provider discovery engine with Brave
when configured and DuckDuckGo as an independent fallback. The existing fetch, SSRF/redirect,
numeric-ID rejection, phone-context/structured validation and entity extraction path is unchanged.
Search snippets remain discovery candidates and have no evidence reference. Only a verified target
page can create evidence or a downstream hop.

Private JSON/HTML reports expose provider status, discovery coverage, candidates, verified and
rejected targets. Brave and DuckDuckGo receive the searched phone presentations only when actually
executed. This is public-occurrence research, not subscriber, owner or identity confirmation.

## NOT IMPLEMENTED

- Reverse lookup, subscriber lookup, identity confirmation or CAPTCHA bypass.
