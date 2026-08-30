# Host and URL structure abuse
finding-ids: raw_ip, embedded_credentials, long_url, url_shortener

## Bare IP addresses as hosts
A URL whose host is a literal IP address skips the domain layer entirely. This is normal
for local development and for some appliance and router interfaces, and abnormal for any
public service handling user accounts, because an organization that owns a brand has no
reason to send customers to a number. IP-hosted phishing is typically served straight
from a compromised host or a short-lived virtual machine, which is also why such pages
tend to disappear within days.

## Credentials embedded before the host
The `user:password@host` form in a URL is a legacy authority syntax. Its practical use
today is obfuscation: everything before the `@` is discarded by the parser, so a URL can
be padded with a trusted-looking string while the browser silently connects to whatever
follows the `@`. Modern browsers strip or warn about this form, but it still appears in
mail bodies and redirect chains. Any occurrence in a user-facing link should be treated
as intentional deception rather than a mistake.

## Unusually long URLs
Length is a weak signal read on its own, since analytics parameters and session tokens
routinely produce long legitimate URLs. It matters as a carrier for other techniques:
padding that pushes the real host out of view, encoded payloads, and nested redirect
targets all inflate length. Weight it only in combination with a structural or naming
finding.

## Link shortening services
A shortener replaces the destination with an opaque token, which defeats inspection
before the click and lets the operator change the destination after the link has been
distributed and scanned. The service itself is legitimate and widely used, so the finding
describes reduced visibility rather than malice. The correct response is to resolve the
final destination and analyze that, not to score the shortener domain.
