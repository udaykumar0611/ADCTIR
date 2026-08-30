# Redirect chains
finding-ids: many_redirects

## Why redirect depth matters
Multi-hop redirects are used to separate the link a victim sees from the page they land
on. Intermediate hops filter traffic - by geography, by user agent, by whether the client
looks like a security scanner - so that analysts and crawlers receive a benign page while
targeted users receive the credential form. A long chain also launders reputation, since
the first hop is often a legitimate service that permits open redirects.

## Reading the count accurately
The browser's Navigation Timing API reports the redirect count for the current document,
and it deliberately omits cross-origin hops that occurred before the final navigation.
A reported count is therefore a floor, not a total: three observed redirects mean at least
three happened. Legitimate single sign-on flows also produce several hops, so a high count
on a recognized identity provider is expected behavior and not a finding to escalate on
its own.
