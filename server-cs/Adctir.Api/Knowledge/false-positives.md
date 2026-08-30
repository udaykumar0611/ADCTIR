# Avoiding false positives

## Benign explanations for common findings
Several findings have ordinary causes that an honest assessment must acknowledge.
Internal tools and development hosts legitimately serve plain HTTP over trusted networks.
Content delivery and analytics platforms legitimately use deep subdomain nesting.
Marketing campaigns legitimately use shorteners and long parameterized URLs. Genuine
non-Latin-script sites legitimately use punycode. A new domain is the expected state of
every legitimate service on its launch day.

## Weighing combinations over single signals
Confidence should come from how well findings corroborate a single story, not from how
many fired. A newly registered hyphenated domain containing a brand name and hosting a
password form over plain HTTP is one coherent credential-harvesting story told four ways.
The same four findings scattered across unrelated aspects of a site with a decade-old
domain tell no story at all. State the story when one exists, and say plainly when the
evidence is thin.

## Language discipline in findings
Describe what was observed and what it implies, and avoid asserting intent that the
signals cannot establish. The collected indicators cannot distinguish a phishing site from
a poorly configured legitimate one, and overstating certainty trains users to dismiss
warnings. Prefer concrete conditional guidance - what to check, what not to enter - over
verdict language the evidence does not support.
