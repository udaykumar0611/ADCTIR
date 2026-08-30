# Production Deployment Checklist

The repository runs locally without external services. A public deployment needs the following operator-owned work.

## Backend

1. Run the ASP.NET Core service behind a managed HTTPS reverse proxy or container platform (`dotnet publish -c Release`).
2. Set `ADCTIR_HOST=0.0.0.0` and a platform-assigned port where required.
3. Replace `ThreatStore` JSON persistence with PostgreSQL or another transactional database (EF Core or Npgsql).
4. Add authenticated users or signed extension requests, API quotas, centralized rate limiting, and audit logs.
5. Restrict CORS and extension access to the published Chrome extension ID.
6. Add structured logs, uptime monitoring, backups, retention rules, and report deletion procedures.
7. Connect appropriately licensed malicious-domain feeds. The AI/RAG explanation layer ships in `server-cs/Adctir.Api/ThreatExplainer.cs` and `server-cs/Adctir.Api/Knowledge/` and runs offline by default; to enable model-written wording, set one provider key (`GEMINI_API_KEY`, `OPENROUTER_API_KEY`, or `ANTHROPIC_API_KEY`) in server-side secrets only, review the corpus for your own policy language, and budget for per-explanation API cost. Keep the rule evidence for every verdict regardless of which explainer runs.
8. Disclose AI processing. When a provider key is set, scanned URLs and hostnames are sent to that provider - update the privacy policy and the Chrome Web Store data-use disclosures accordingly, or leave the rules explainer in place to avoid third-party processing entirely. Free tiers may retain prompts for training; review the provider's terms before pointing real user traffic at one.
9. Run security review, dependency scanning, penetration testing, and privacy/legal review.

## Extension

1. Enter the production HTTPS API in Settings and grant its requested host permission.
2. Remove development-only localhost host permissions if the production build does not need them.
3. Replace or finalize store artwork, screenshots, support URLs, and privacy-policy URL.
4. Run the manual test matrix across current Chrome and Edge releases.
5. Create a ZIP containing ONLY the extension files - `manifest.json`, the popup/options/content/background scripts and styles, and `icons/`. It must exclude `server-cs/`, `.env`, `data/`, and backend documentation, or split the extension and server into separate release packages.
6. Upload the extension through the Chrome Web Store publisher account and complete the data-use disclosures.

## Required manual test matrix

- Normal HTTPS page
- HTTP page and HTTP login form
- Punycode, IP-host, sensitive-keyword, long, and highly nested URLs
- Multiple redirects (noting that browser timing rules can hide cross-origin redirects)
- API timeout, API error, malformed response, and offline mock mode
- Explanation with no provider key, with each configured provider, and with a key set to an invalid value
- Report creation and retrieval
- Extension reload with existing tabs
- Unsupported `chrome://`, `file://`, and browser-store pages
- Settings save, production host-permission denial, and session-result clearing

Deployment and store submission cannot be automated from this repository without the operator's hosting, DNS/TLS, database, threat-feed, AI-provider, and Chrome publisher credentials.
