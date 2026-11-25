![nightcrawl banner](assets/banner.svg)

# nightcrawl

A recon checklist planner for authorized security testing — pick a target and profile, get a phased OWASP-style checklist, track progress, and export it to Markdown.

## Features

- **Three profiles** — Quick recon, Full web assessment, and API focus, each generating a different phased plan.
- **Phased OWASP-style checklist** — Scope & authorization, Passive recon, DNS & subdomain discovery, Fingerprinting, Crawling & content discovery, Authentication testing, Authorization/IDOR, Input validation (XSS/SQLi/SSRF classes), Session management, Business logic, and Reporting.
- **Rich items** — every checklist item carries a short description, a suggested tool/technique note, and a severity-relevance tag.
- **Progress tracking** — per-phase and overall progress bars, persisted in `localStorage` per domain + profile, with a notes field per phase.
- **Export** — download the checklist as Markdown (with checkbox states and notes), copy it to the clipboard, or print a clean view.
- **Domain validation** — target domains are normalized and validated before a plan is generated.
- **Zero dependencies** — plain HTML, CSS, and JavaScript; everything runs locally in your browser.

## Usage

Open `index.html` in a browser (or serve the folder with any static file server):

```sh
python3 -m http.server 8000
# then visit http://localhost:8000
```

1. Enter a target domain, e.g. `example.com`.
2. Pick a profile: **Quick recon**, **Full web assessment**, or **API focus**.
3. Click **Generate checklist**.
4. Work through the phases, ticking items off and adding notes as you go — progress is saved automatically for that domain + profile.
5. Export with **Download Markdown** or **Copy Markdown** when you need the plan (or the record of what was done) outside the browser.

## How it works

The checklist logic lives in `app.js` as pure, exported functions, so it can be tested without a browser:

- `validateDomain(input)` — normalizes (scheme, case, path, port) and validates a target domain, returning `{ ok, domain, error }`.
- `buildChecklist(domain, profile)` — builds the phased checklist for the `quick`, `full`, or `api` profile; profiles differ in which phases and items they include, and the API profile swaps in API-specific items.
- `progressSummary(checklist, checked)` — computes overall and per-phase completion from a list, `Set`, or map of checked item IDs.
- `toMarkdown(checklist, state)` — renders the checklist as Markdown with `- [x]` / `- [ ]` states, progress, and per-phase notes.

The browser UI (guarded by `typeof document !== "undefined"`) renders the plan, wires the checkboxes and notes fields, persists state to `localStorage` under a per-domain-plus-profile key, and handles the Markdown download, clipboard copy, print, and reset actions.

## Tests

Requires Node.js 20+ (the package is an ES module):

```sh
node --check app.js
node --test
```

The suite in `tests/checklist.test.mjs` covers domain validation (valid, normalized, and invalid inputs), checklist generation per profile (phase/item counts, API-specific items, item shape), progress math, and Markdown export checkbox states.

## Authorized use

nightcrawl is a planning tool for **authorized security testing only**. Only test systems you own or have explicit written permission to test. That is why the first phase of every generated checklist is confirming written authorization and scope — never skip it, and stay inside the agreed rules of engagement.

## License

MIT — see [LICENSE](LICENSE). Copyright © Lavish Gangwar.
