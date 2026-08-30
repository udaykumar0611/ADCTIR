# Triage and analyst response

## Reading the ADCTIR score
The score is an additive sum of rule weights capped at one hundred, and the bands are
Safe below twenty-five, Suspicious from twenty-five to fifty-nine, and High-Risk at sixty
and above. Because it is additive, several weak structural findings can reach the same
total as one strong finding, and the two situations warrant different responses. Always
read the contributing evidence rather than the number alone, and state which findings
carry the assessment.

## Recommended user actions by band
For a High-Risk result the user should not enter credentials or payment details, should
leave the page, and should reach the intended service by a known-good bookmark or by
typing the address directly. For a Suspicious result the user should verify the
registrable domain against the organization's real domain before entering anything, and
should treat an unexpected arrival at the page - from mail, chat, or an advertisement -
as an additional reason for caution. For a Safe result no action is needed, but the score
describes only the signals collected, not the site's full trustworthiness.

## Reporting and escalation
A stored report preserves the indicators, the rule evidence, and the engine version at
the time of the verdict, which is what makes a later review possible. Escalate to a
security team when credentials were actually entered, when the page imitates an employer
or financial institution, or when the same infrastructure appears across multiple users.
Credential entry converts the incident from a browsing event into an account-compromise
event, and the response is an immediate password change on the real site plus a session
revocation.
