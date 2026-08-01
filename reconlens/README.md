# ReconLens -- AI Recon & Triage for Burp Suite

A Burp Suite extension (built on the modern **Montoya API**, not the legacy
Jython/Extender API) that turns a giant, undifferentiated pile of proxy
history into a short, prioritized worklist -- and, for the requests that
actually warrant it, gives a tester more than a keyword match to go on.

## Where this stands after a round of review

An earlier version of this only did per-request keyword/shape matching:
"parameter is named `user_id`, maybe IDOR." That's real signal, but it isn't
analysis -- it's a lookup table. A tester with a few seconds of experience
notices the same thing without help. This version adds four things on top
that a lookup table can't do, because they all require looking at more than
one request at a time:

1. **Risk scoring** -- every request gets an explainable 0-100 score (not
   just a list of tags), built from a fixed, documented rubric so a tester
   can see exactly why one request outranks another (see `RiskScorer`).
2. **CRUD / resource correlation** -- a new "By Resource (CRUD)" view groups
   traffic by *resource*, not by literal path: `GET /orders` (list),
   `POST /orders` (create), and `GET/PUT/DELETE /orders/{id}` (read/update/
   delete) are all recognized as one "Orders" resource with full
   object-lifecycle exposure, not several unrelated rows (see
   `ResourceProfiler`).
3. **Response diffing** -- within a group of near-duplicate requests,
   ReconLens now actually parses and compares the JSON response *shapes*:
   identical field names with different values across requests is a real
   IDOR/enumeration signal; byte-identical responses for different inputs is
   a different, also-useful signal (see `ResponseDiffAnalyzer`).
4. **Real JWT decoding** -- not "found a JWT," but the actual algorithm,
   whether an expiry claim exists, and which claims are present (role,
   tenant, email, ...), decoded from the token itself with zero dependencies
   (see `JwtInspector`).

Steps 1-4 are still deterministic correlation, not reasoning -- and this
README says so on purpose, because overclaiming "AI" for a rule engine is
exactly the failure mode worth avoiding. The one place this project asks an
actual model to reason is new too: **"Analyze Resource with AI"** hands
Claude the whole CRUD map, every finding, and every risk score for one
resource at once, and asks it to find relationships a fixed rule can't --
whether two findings combine into something worse, or a plausible business
workflow explains the surface. That's a genuinely different question than
"explain this one request," and it's the part of this project where an LLM's
judgment is actually doing something a human-written rule couldn't.

### On using an open-source project for "intelligence"

I looked, and didn't add one, on purpose. There's no well-scoped
"vulnerability reasoning" library that fits inside a Burp extension --
the realistic options were either irrelevant (general ML/NLP libraries with
no HTTP-security grounding) or would have meant wrapping another tool's
scanner, which is a worse story for a resume project than building the
analysis. Where a library would normally be the pragmatic choice --
JSON parsing, JWT decoding -- I hand-rolled a small parser instead
(`MiniJson`, ~180 lines), because the whole project's zero-runtime-dependency
design (see "Why no JSON library" below) is worth more here than saving an
afternoon, and because writing a small recursive-descent parser is a better
signal of ability than adding a Gson dependency for two call sites. The one
genuine "intelligence" upgrade -- the resource-level Claude analysis -- reuses
the API integration that was already in the project rather than bolting on
something new.

## Features

- **Explains requests** in plain English (fully offline), with a richer
  per-request or per-resource explanation available on demand from the
  Claude API.
- **Highlights interesting parameters** -- auth tokens, object IDs, redirect
  targets, file paths, JWTs, serialized blobs -- by name and by value shape.
- **Suggests candidate vulnerability classes** (IDOR, SSRF, open redirect,
  CORS misconfig, injection, JWT weaknesses, cookie hardening, ...) with a
  one-line rationale and a concrete manual next step. It never fires the
  test itself -- see "What this is not" below.
- **Groups near-duplicate endpoints** so you triage dozens of patterns
  instead of thousands of individual requests, and **groups by resource
  across methods** so you see the full CRUD surface of one shape at a glance.
- **Scores risk explainably**, **diffs responses within a group**, and
  **decodes JWTs** for real, as described above.
- One-click **import of existing Proxy history**, a **"Send to ReconLens"**
  right-click menu item everywhere in Burp, a **Markdown report export**,
  and settings that **persist** across Burp restarts.

## What this is *not*

- **Not an active scanner.** `ReconHttpHandler` is a passive observer -- it
  reads traffic Burp already captured and always returns `continueWith(...)`
  unchanged. It never sends an extra byte to the target on its own.
- **Not a source of confirmed findings.** Every suggestion, score, and diff
  result is a heuristic lead: "this is worth a human trying by hand," not
  "this is a vulnerability." The exported report says so explicitly.
- **Not something to point at systems you're not authorized to test.**
  Same rule as every other tool in Burp.

## Architecture

```
com.reconlens
├── ReconLensExtension        entry point (implements BurpExtension)
├── model/                    plain POJOs -- zero Montoya imports anywhere in here
│   ├── HttpParam, ParamType, Severity
│   ├── ParamFinding, VulnSuggestion, RiskScore
│   ├── ResourceProfile, JwtInfo
│   └── TrafficEntry, EndpointGroup
├── analysis/                  the actual "brains" -- pure logic, unit-testable
│   │                          with plain JUnit, no Burp/Montoya/network needed
│   ├── ParameterAnalyzer         name + value-shape heuristics
│   ├── EndpointGrouper           path normalization (/users/{id}/...)
│   ├── VulnerabilityRuleEngine   parameter + response signals -> vuln leads
│   ├── RiskScorer                explainable 0-100 score, capped per category
│   ├── ResourceProfiler          host+path across every method -> CRUD view
│   ├── ResponseDiffAnalyzer      JSON response-shape diffing within a group
│   ├── JwtInspector               JWT header/payload decode -> alg/claims/warnings
│   ├── MiniJson                   in-house dependency-free JSON parser (package-private)
│   ├── AttackPathSynthesizer     templated cross-signal narrative for a resource
│   ├── RequestExplainer          offline plain-English summary
│   └── EndpointGroupIndex        the in-memory store, shared by handler/UI
├── handler/                    the ONLY package that touches both Montoya
│   │                          types and our own model
│   ├── ReconHttpHandler          implements Montoya's HttpHandler (passive)
│   └── TrafficEntryFactory       Montoya HttpRequest/HttpResponse -> TrafficEntry
├── ai/
│   └── ClaudeClient          optional, opt-in Claude calls: per-request
│                             explanation AND per-resource correlated analysis
├── menu/
│   └── ReconContextMenu      "Send N to ReconLens" on Burp's right-click menu
├── ui/
│   ├── ReconLensTab               "By Endpoint" view: groups | entries | detail
│   ├── ResourcePanel              "By Resource (CRUD)" view: coverage + attack path
│   ├── GroupTableModel, EntryTableModel, ResourceTableModel
│   └── AiSettingsDialog
└── export/
    └── ReportExporter        renders everything captured into Markdown
```

The `model` and `analysis` packages deliberately have **zero** imports from
`burp.api.montoya.*`. That split means the actual detection logic -- the
part that's interesting -- can be built, unit-tested, and iterated on with
plain `javac`/JUnit, no Burp Suite installation and no Montoya jar required.
`TrafficEntryFactory` is the one seam that converts between the two worlds;
`ResponseDiffAnalyzer` and `JwtInspector` both lean on the same in-house
`MiniJson` parser rather than duplicating JSON-handling logic.

### Why no JSON library

Two things in this project need to read JSON: comparing response shapes
(`ResponseDiffAnalyzer`) and decoding JWT segments (`JwtInspector`). Both are
narrow, fixed-shape jobs, so `MiniJson` -- a small recursive-descent parser,
no external dependency -- covers both instead of adding Gson/Jackson (and
the Maven-shade relocation that comes with a real dependency) for two call
sites. `ClaudeClient` uses the same philosophy for the Anthropic API: a
couple dozen lines of hand-rolled escaping/extraction instead of a library,
since the request body is entirely under our control and the response shape
(`content: [{"type":"text","text":"..."}]`) is small and stable.

### Privacy note on the AI features

Both Claude integrations (`explain` and `analyzeResource`) are off by
default, require your own Anthropic API key (from console.anthropic.com --
separate from any claude.ai subscription), and only run when you click a
button for one specific request or resource. By default neither sends raw
request/response bodies -- just method, path, parameter names/types, status
codes, and the local heuristic findings/risk scores. There's a checkbox in
"AI Settings" if you want bodies included in the per-request explanation too.
Nothing about either AI feature is required for the rest of the extension
to work.

## Build & install

Requires JDK 21+ and Maven, plus internet access for the first build (to
pull the `montoya-api` and `junit-jupiter` dependencies).

```bash
mvn package        # -> target/reconlens.jar
mvn test           # runs the offline unit tests in src/test
```

Then in Burp Suite: **Extensions -> Installed -> Add -> Extension type:
Java**, and select `target/reconlens.jar`. A new **ReconLens** tab appears
in the main suite window.

If you add a real third-party dependency later, build with
`mvn package -Pfatjar` instead so it gets bundled into the jar -- Burp only
puts `montoya-api` classes on the classpath, nothing else.

## Using it

1. Load the extension, open the **ReconLens** tab.
2. Click **Import Proxy History** to pull in everything you've already
   browsed through, or keep browsing with capture left on -- new traffic
   streams in live.
3. **"By Endpoint" tab:** the left table groups requests by normalized
   endpoint (method+path); select one to see individual requests on the
   right, and the **Group Insights** tab underneath for cross-request
   response-diff signals and per-request risk scores.
4. Select a request to see its offline explanation, flagged parameters,
   vulnerability leads (**Findings & Leads**), decoded JWTs (**Auth
   Analysis**), and optionally an AI explanation.
5. **"By Resource (CRUD)" tab:** see every host+path shape's method
   coverage at a glance, an offline synthesized attack order, and
   **Analyze Resource with AI** for a second, correlated opinion.
6. **Export Report (.md)** when you're ready to write it up.

## Build notes (read this before you file a bug)

I wrote every Montoya API call in `handler/`, `menu/`, and `ui/` against the
current published Javadoc (targeting `montoya-api` **2026.4**), but this
sandbox has no internet access and no JDK (only a JRE), so I could not run
`javac`/`mvn compile` against the real dependency to confirm it end to end.
Everything in `model/` and `analysis/` I *did* trace through by hand against
the test cases in `AnalysisTest` (23 tests, covering every new class), so
I'm confident in the actual detection/correlation logic. If `mvn compile`
throws an error, it'll almost certainly be one of these Montoya calls, not a
design problem:

- `HttpResponseReceived.initiatingRequest()` -- documented as "additional
  methods to retrieve initiating HttpRequest," exact method name inferred.
- `HttpService.host()` / `.port()` / `.secure()` -- inferred from this
  API's consistent no-`get` naming convention, not seen in a direct snippet.
- `ParsedHttpParameter.name()` / `.value()` / `.type()` -- same, inferred by
  strong analogy to `HttpHeader.name()`/`.value()`, which *is* confirmed.
- `Preferences.setString(...)` -- `getString`/`stringKeys` are confirmed;
  the setter is assumed symmetric. Booleans are deliberately stored as
  `"true"`/`"false"` strings rather than via `Preferences.getBoolean`, since
  I couldn't confirm that method exists.

Any mismatch here should be a one-line rename, not a rewrite. Check
https://portswigger.github.io/burp-extensions-montoya-api/javadoc/ against
whichever call trips the compiler.

`HttpParameterType` mapping stays defensive on purpose --
`TrafficEntryFactory.mapType()` never hardcodes Montoya's enum constant
names; it maps by `.name()` string lookup with a fallback to `UNKNOWN`, so
even a wrong guess there degrades gracefully instead of breaking the build.

## Extending it further

- **Cross-resource correlation.** Right now `analyzeResource` reasons about
  one resource at a time. The natural next step is feeding Claude two or
  three *related* resources together (e.g. `/orders/{id}` and
  `/users/{id}/orders`) to look for hidden relationships between them --
  the "endpoint relationships" idea, generalized past a single shape.
  `ResourceProfiler` already has the host+path grouping; it just isn't
  chained across resources yet.
- **Bulk import performance.** `ReconLensTab.importProxyHistory()` currently
  triggers a full UI refresh per imported entry via the normal listener path
  (harmless at hundreds of requests, wasteful at tens of thousands) -- a
  batch `addAll()` on `EndpointGroupIndex` that fires one notification
  instead of N would fix that.
- **More rules.** Everything in `VulnerabilityRuleEngine` is plain Java, not
  config-driven -- adding a new lead is a few lines in one method.
- **Wordlist export.** Dump all discovered parameter names as a wordlist for
  fuzzing tools like ffuf/Arjun.
- **Scope filtering.** Skip out-of-scope hosts before they ever hit
  `EndpointGroupIndex` (Montoya exposes a `Scope` API for this).
