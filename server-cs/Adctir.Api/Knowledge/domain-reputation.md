# Domain age and registration reputation
finding-ids: new_domain, young_domain, higher_risk_tld

## Newly registered domains
Registration age is one of the strongest single predictors available without a commercial
threat feed. Phishing infrastructure is disposable by design: a domain is registered,
used while it is still absent from blocklists, and abandoned once reported. Domains under
thirty days old that host credential forms are a well-established high-risk pattern.
The signal is derived from RDAP registration events, so it is absent for hosts that are
IP literals, internal names, or registries that decline to publish an event date.

## Young but established domains
A domain between one and six months old is meaningfully less suspicious than one
registered last week and meaningfully more suspicious than one registered years ago.
Legitimate new products do launch, so this range should adjust confidence rather than
drive a verdict. Combine it with whether the page requests credentials and whether the
name imitates an existing brand.

## Higher-risk top-level domains
Abuse rates differ sharply between TLDs, driven by registration price, identity
verification, and the registry's responsiveness to abuse reports. Some TLDs carry
additional structural hazard: `.zip` and `.mov` collide with common file extensions,
so a string that a user reads as a filename can resolve as a hostname. Elevated abuse
rate is a population statistic, not a property of the individual site, so it warrants a
small weight only.

## Interpreting a missing age value
When RDAP lookup fails or is disabled, domain age is unknown rather than zero. An unknown
age must not be read as either reassuring or damning; it simply removes one input, and the
remaining findings carry the assessment. Say so explicitly rather than omitting the topic,
because a reader who expects an age check will otherwise assume it passed.
