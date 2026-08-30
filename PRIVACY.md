# ADCTIR Privacy Notice

## Data processed during a manual scan

ADCTIR processes the active page's URL, hostname, HTTPS status, reported redirect count, presence or absence of a password input, and URL-pattern findings. It may ask an RDAP service for public domain-registration information.

## Data ADCTIR does not collect

ADCTIR does not read or store passwords, form-field values, cookies, authentication tokens, full page contents, private browsing history, or data from other tabs. Scanning begins only after the user selects **Analyze this page**.

## AI-assisted explanations

Selecting **Explain this result** sends the already-collected indicators to the configured ADCTIR server, which retrieves matching passages from a security-knowledge corpus bundled with the server and composes an explanation. No additional data is collected from the page for this step.

By default the explanation is composed on the server by a deterministic rules explainer, and nothing leaves the ADCTIR server. If the operator configures a provider key (`GEMINI_API_KEY`, `OPENROUTER_API_KEY`, or `ANTHROPIC_API_KEY`), the server instead sends the page URL, hostname, the rule findings, and the retrieved passages to that provider to compose the wording. In that configuration those values are processed by the chosen provider under its own terms, and free tiers in particular may retain prompts or use them to improve services - check the provider's current policy before enabling one for real user traffic. No API key is ever placed in the extension, and the browser never contacts a model provider directly.

`GET /api/health` reports which explainer a given server is running (`ai_generator`, `ai_provider`, `ai_model`), so users and operators can confirm whether AI processing is enabled and where the data goes.

## Storage and transmission

Scan results are kept in browser session storage so they can be restored for the same tab and are cleared when the browser session ends or the user selects **Clear saved scan results**. Reports are transmitted only after the user selects **Report to ADCTIR** and are stored by the configured server.

The bundled local server stores reports in `data/threats.json` relative to the API project. Operators deploying ADCTIR are responsible for access controls, retention rules, deletion procedures, encryption, incident response, and an organization-specific privacy policy.

## Permissions

- `activeTab`: access the tab the user explicitly chose to scan.
- `scripting`: inject the non-sensitive collector on demand.
- `storage`: save settings and temporary per-tab results.
- Localhost access: contact the bundled local API.
- Optional HTTPS site access: contact a production API only after the user grants permission from Settings.
