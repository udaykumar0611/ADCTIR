# Transport security and credential exposure
finding-ids: no_https, insecure_login

## Pages served without HTTPS
A page delivered over plain HTTP has no transport encryption and no server identity
guarantee. Any network position between the browser and the server - a shared access
point, a compromised router, a hostile ISP - can read the page and rewrite it before it
reaches the user. Absence of HTTPS is not by itself proof of phishing, because a small
number of legacy internal hosts still serve plain HTTP, but on a public site that asks
for any user input it is a strong quality signal and a prerequisite for several
credential-theft techniques.

## Login forms on unencrypted pages
A password field on a non-HTTPS page is materially worse than either signal alone. The
credential is submitted in cleartext unless the form action independently upgrades to
HTTPS, which the browser cannot promise and the user cannot verify. Attackers also use
plain HTTP deliberately: it removes the certificate-issuance step from their setup and
avoids tying the campaign to a domain that a certificate authority has logged in
Certificate Transparency. Treat this combination as a credential-exposure finding, not
merely a configuration weakness.

## What HTTPS does not prove
A valid certificate proves only that the connection is encrypted and that the presented
name matches the certificate. Domain-validated certificates are free and issued in
seconds, so the overwhelming majority of modern phishing sites do serve HTTPS. The
padlock indicator should never be used to argue that a page is legitimate, and its
presence must not reduce the weight given to naming, age, or structural findings.
