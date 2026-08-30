# ADCTIR Browser Security Extension

ADCTIR is a Chrome Manifest V3 extension plus an ASP.NET Core threat-analysis API. A user manually scans the active page, reviews an explainable risk score, and can save a threat report for investigation.

## Current capabilities

- On-demand collection of non-sensitive page and URL signals
- Server-side risk analysis with evidence and a versioned rules engine
- Optional RDAP domain-age lookup (failures do not break analysis)
- Safe, Suspicious, and High-Risk results with a 0–100 score
- Retrieval-augmented explanations of a verdict, grounded in a local security-knowledge corpus with per-claim citations
- Optional model-written wording via Gemini, OpenRouter, or Claude, off by default and never required
- Persistent threat reports stored locally as JSON
- Per-tab result restoration and extension-icon badges
- Offline demonstration mode
- Configurable analysis server and privacy settings
- Input validation, request limits, CORS controls, and basic rate limiting
- Automated tests for scoring, validation, API storage, and extension rules

ADCTIR does not read passwords, form values, cookies, page content, or browsing history. See [PRIVACY.md](PRIVACY.md).

## Run the local MVP

Requirements: the .NET 9 SDK and a Chromium-based browser.

1. Open a terminal in this folder.
2. Start the API:

   ```powershell
   dotnet run --project server-cs/Adctir.Api
   ```

3. Confirm that `http://127.0.0.1:5001/api/health` returns an OK response.
4. Open `chrome://extensions`, enable Developer mode, and select **Load unpacked**.
5. Select this folder. If it was already loaded, select **Reload**.
6. Open an HTTP or HTTPS page, select the ADCTIR icon, and choose **Analyze this page**.

The extension defaults to the local API at `http://127.0.0.1:5001`. Its Settings page can switch to offline demonstration mode or an HTTPS production API.

## API

### Analyze a page

`POST /api/threats/analyze`

```json
{
  "indicators": {
    "url": "https://example.com/login",
    "redirect_count": 0,
    "has_login_form": true
  }
}
```

The response includes `risk_score`, `risk_level`, `reasons`, `evidence`, `domain_age_days`, `engine_version`, and normalized indicators.

### Explain a result

`POST /api/threats/explain`

Takes the same indicators, re-runs the analysis, and adds an `explanation` object:

```json
{
  "summary": "secure-login-verify.top scored 83 of 100 (High-Risk) on 5 rule findings...",
  "key_points": [
    {
      "point": "Login forms on unencrypted pages: a password field on a non-HTTPS page...",
      "citation": "transport-security#login-forms-on-unencrypted-pages"
    }
  ],
  "recommended_actions": ["Do not enter credentials, payment details, or personal information on this page."],
  "confidence": "high",
  "risk_level": "High-Risk",
  "risk_score": 83,
  "generator": "rules",
  "provider": null,
  "model": null,
  "passages": [
    {
      "id": "transport-security#login-forms-on-unencrypted-pages",
      "doc_title": "Transport security and credential exposure",
      "section": "Login forms on unencrypted pages",
      "score": 31.62,
      "matched_finding_ids": ["no_https", "insecure_login"]
    }
  ],
  "corpus_version": "adctir-knowledge-1.0.0",
  "explainer_version": "adctir-rag-1.1.0",
  "degraded_reason": null,
  "generated_at": "2026-08-30T15:04:05.000Z"
}
```

`generator` is `"rules"` or `"model"`; `provider` and `model` are non-null only when a model composed the wording. `degraded_reason` is non-null when a model was configured but its output could not be used - the explanation is still complete, just written by the deterministic explainer.

The rules engine remains the only source of `risk_score` and `risk_level`; the explanation cannot change a verdict. Every `citation` names a passage in the `passages` array, and a citation that names anything else is discarded.

`POST /api/threats` accepts `"explain": true` to store an explanation with the report.

### Store a report

`POST /api/threats` accepts the same indicators. The server recalculates the result rather than trusting a client-provided score, stores it in `data/threats.json`, and returns a UUID threat ID.

### Retrieve a report

`GET /api/threats/{threat_id}`

### Health check

`GET /api/health`

## AI/RAG explanations

The score tells a user *what* ADCTIR concluded. The explanation layer tells them *why it matters*, in plain language, without inventing security knowledge.

**Pipeline: retrieve, ground, synthesize.**

1. **Retrieve.** `KnowledgeIndex.cs` runs BM25 over the passages in `Adctir.Api/Knowledge/`. Each passage is tagged with the analyzer finding ids it explains, and a tag match adds a fixed bonus - that is what keeps a passage reachable when the rule wording and the passage wording do not overlap. Selection is coverage-first: each fired finding claims its best passage in descending weight order, then the remaining slots go to the top of the ranking, so no rule that drove the score is left uncited.
2. **Ground.** The retrieved passages are the only knowledge the writer may draw on. Page-derived values are wrapped in an untrusted-data block, with angle brackets neutralized so page text cannot close that block and be read as instructions.
3. **Synthesize.** Either the deterministic writer or a configured model provider composes the wording.

**Why BM25 and not embeddings.** The corpus is a few dozen curated passages. An embedding service would add a network dependency, a second provider key, and an index-build step without improving recall at this size. Retrieval stays offline, deterministic, and unit-testable.

### Scope of the retrieval layer

This is retrieve-then-generate, so it is RAG rather than a prompt wrapper: knowledge lives in an external indexed corpus, a query is built per request, and generation is constrained to what came back. The clearest evidence is that the endpoint works with no model at all.

It is also deliberately at the simple end, and the limits are worth stating plainly:

- Retrieval is lexical (BM25) plus finding-id tags. There is no embedding model, so a passage phrased in entirely different words than the rule will not match on meaning alone - the tags exist to cover exactly that gap.
- The corpus is hand-authored and chunked by markdown heading. There is no ingestion pipeline, no reranker, and no query expansion.
- The query is built from structured rule findings, not free-form user text, which keeps retrieval predictable but narrow.

**The honest caveat.** The whole corpus is roughly 1,850 words, so it would fit in a single prompt. Retrieval is therefore not yet required to fit the context window - the usual reason RAG exists. It still does two real jobs at this size: it defines the set that citation checking validates against, which is what makes a fabricated citation detectable at all, and it means the corpus can grow past the prompt without a rewrite.

**Growth path.** If the corpus grows to a few hundred passages, retrieval becomes load-bearing rather than structural, and that is the change worth making before swapping BM25 for embeddings. Passage count is what makes retrieval necessary; retrieval machinery is not.

**Synthesis backends, one response shape.**

| `generator` | `provider` | Requires | Default model | Cost |
|---|---|---|---|---|
| `rules` | none | nothing | n/a | free, offline |
| `model` | `gemini` | `GEMINI_API_KEY` | `gemini-flash-latest` | free tier |
| `model` | `openrouter` | `OPENROUTER_API_KEY` | `meta-llama/llama-3.3-70b-instruct:free` | free models |
| `model` | `anthropic` | `ANTHROPIC_API_KEY` | `claude-haiku-4-5` | ~$0.004 each |

The default is the rules writer, so the server explains verdicts offline and at zero cost. Setting a key promotes synthesis without changing the response shape, so the extension does not know or care which one ran. When several keys are present the free providers win, so a stray paid key never silently starts spending.

**Enabling a provider.** Keys are read from the process environment, so set them however your shell or host prefers. For local work, `.env.example` lists every variable; export them before starting the API:

```powershell
$env:GEMINI_API_KEY = "your-key-here"
dotnet run --project server-cs/Adctir.Api
```

`.env` is gitignored and is not read automatically by the C# host - it is a reference file for what to set. Confirm which explainer is live:

```powershell
curl http://127.0.0.1:5001/api/health
# {"ok":true,...,"ai_generator":"model","ai_provider":"gemini","ai_model":"gemini-flash-latest"}
```

**Keys stay server-side.** The extension never holds a key and never contacts a model provider directly; it only ever talks to the ADCTIR API. Do not put a key in `config.js`, `options.js`, or any other file that ships in the Chrome ZIP - everything in that package is readable by anyone who installs it.

**Free models and schema support.** Not every free model honors a JSON schema. The parser therefore accepts bare JSON, fenced JSON, and JSON with surrounding prose, and citation checking catches anything that slips through. If a model returns unusable output the endpoint degrades to the rules writer rather than failing.

**What the model is not allowed to do.**

- It cannot change the verdict. `risk_score` and `risk_level` are copied from the rules engine after the call.
- It cannot cite a passage that was not retrieved. Citations are checked against the retrieved set and fabrications are dropped; if nothing survives, the deterministic writer takes over and the response says why in `degraded_reason`.
- It cannot take the endpoint down. Timeouts, rate limits, refusals, malformed JSON, and ungrounded output all fall back to the deterministic writer, and the user still gets a cited explanation.

## Configuration

Backend environment variables:

Set these in the process environment before starting the API.

| Variable | Default | Purpose |
|---|---|---|
| `ADCTIR_HOST` | `127.0.0.1` | Listening interface |
| `ADCTIR_PORT` | `5001` | Listening port |
| `ADCTIR_DATA_FILE` | `data/threats.json` | Report storage path |
| `ADCTIR_ENABLE_RDAP` | `true` | Enable domain-age enrichment |
| `ADCTIR_RDAP_TIMEOUT_MS` | `8000` | Budget for the RDAP lookup, which is two hops (rdap.org redirects to the registry) |
| `GEMINI_API_KEY` | unset | Google AI Studio key (`GOOGLE_API_KEY` also accepted); enables model-written explanations |
| `OPENROUTER_API_KEY` | unset | OpenRouter key; enables model-written explanations |
| `ANTHROPIC_API_KEY` | unset | Anthropic key; enables model-written explanations (paid) |
| `ADCTIR_AI_PROVIDER` | auto | `gemini`, `openrouter`, or `anthropic`; auto-detects in that order from the keys present |
| `ADCTIR_AI_ENABLED` | `true` | Set to `false` to force the rules explainer even when a key is present |
| `ADCTIR_AI_MODEL` | per provider | Overrides the provider's default model |
| `ADCTIR_AI_BASE_URL` | per provider | Overrides the provider's API host; useful for a proxy or a local stub |
| `ADCTIR_AI_TIMEOUT_MS` | `20000` | Per-attempt timeout for the model call (two attempts on retryable errors) |
| `ADCTIR_AI_EFFORT` | unset | Anthropic only; optional `output_config.effort` |

Set `ADCTIR_ENABLE_RDAP=false` for fully offline operation.

## Tests

```powershell
dotnet test server-cs
```

68 tests cover the rules engine, retrieval and coverage, prompt construction and injection hardening, every provider's request shape, citation enforcement, the degradation paths, and the HTTP surface end to end. The suite never touches the network: RDAP is disabled and provider calls run against a stubbed transport.

## Architecture

The extension is plain JavaScript because Chrome runs nothing else. The backend is C#.

**Extension (JavaScript)**

- `content.js`: on-demand, privacy-limited page indicator collector
- `popup.js`: scan, display, report, per-tab state, and error handling
- `api.js`: timeout-aware mock/live API client
- `risk.js`: offline fallback scorer
- `background.js`: per-tab badge updates
- `options.*`: server, mock-mode, privacy, and result-reset settings

**Backend (ASP.NET Core, `server-cs/`)**

- `Adctir.Api/Program.cs`: minimal-API routing, validation, CORS, rate limiting, body cap
- `Adctir.Api/Analyzer.cs`: normalized, explainable analysis plus RDAP enrichment
- `Adctir.Api/KnowledgeIndex.cs`: BM25 retrieval with finding-tag boosting and coverage
- `Adctir.Api/Knowledge/`: the security-knowledge corpus, one markdown document per topic
- `Adctir.Api/ThreatExplainer.cs`: retrieval-augmented explanation, offline by default and model-backed when a key is set
- `Adctir.Api/Providers.cs`: per-vendor request/response mapping for Gemini, OpenRouter, and Claude
- `Adctir.Api/ThreatStore.cs`: serialized and atomic JSON persistence
- `Adctir.Api/Models.cs`: wire contracts, snake_case so the extension needs no changes
- `Adctir.Tests/`: xUnit suite, including in-process HTTP tests via `WebApplicationFactory`

## Production release

The local MVP is complete, but public deployment requires infrastructure and credentials that are intentionally not stored here. Follow [DEPLOYMENT.md](DEPLOYMENT.md) to replace JSON storage, deploy behind HTTPS, add authentication/monitoring, connect licensed threat-intelligence feeds, review the AI provider choice and its data-retention terms, and publish through the Chrome Web Store.
