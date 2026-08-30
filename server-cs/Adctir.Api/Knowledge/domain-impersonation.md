# Domain impersonation and lookalike naming
finding-ids: punycode, many_hyphens, sensitive_domain_words, many_subdomains

## Punycode and internationalized domains
Punycode labels begin with the `xn--` prefix and encode non-ASCII characters. The
legitimate use is genuine non-Latin-script domains. The abusive use is the homograph
attack: Unicode code points that render almost identically to Latin letters produce a
domain that looks like a known brand in the address bar while resolving somewhere else
entirely. Because the deception exists only at render time, the encoded form is the
reliable thing to inspect. Any punycode label on a page requesting credentials deserves
manual confirmation of the decoded name.

## Hyphen-padded brand names
Registrars will not sell an attacker the brand domain itself, so campaigns assemble a
string that contains the brand plus qualifiers - the pattern behind names of the form
`brand-security-update-portal`. A high hyphen count is the cheap measurable proxy for
that assembly. Legitimate organizations do register hyphenated domains, so this is a
supporting signal that gains weight in combination with domain age and keyword findings
rather than a conclusion on its own.

## Sensitive keywords in the hostname
Terms such as login, verify, secure, account, update, signin, wallet, and password appear
in hostnames far more often in phishing infrastructure than in production infrastructure.
Real organizations normally place these words in the URL path or on a subdomain of their
existing registered domain, because they already own a memorable name. A hostname that
must announce its own trustworthiness is an inversion of how established brands name
things.

## Excessive subdomain nesting
Subdomains are controlled entirely by whoever owns the registrable domain and cost
nothing to create. Deep nesting is used to push the real registrable domain out of the
visible portion of a truncated address bar, especially on mobile, so that a string like
`accounts.example.com` appears first while the actual owner is an unrelated domain at
the end. Read hostnames from the right: the registrable domain is what matters, and
everything to its left is attacker-controlled text.
