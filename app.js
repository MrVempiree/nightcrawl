// nightcrawl — recon checklist planner for authorized security testing.
// Pure logic (validateDomain, buildChecklist, progressSummary, toMarkdown)
// is exported for tests; the browser UI is guarded below.

export const PROFILES = {
  quick: {
    id: "quick",
    label: "Quick recon",
    description: "A fast, low-noise pass: scope, passive recon, DNS, fingerprinting, light crawling, and a short report.",
  },
  full: {
    id: "full",
    label: "Full web assessment",
    description: "The complete phased assessment, from authorization through business logic to reporting.",
  },
  api: {
    id: "api",
    label: "API focus",
    description: "An API-centred plan: discovery, authentication, object-level authorization, and API input validation.",
  },
};

// Each item: [id-suffix, title, description, tool/technique note, severity relevance]
const PHASES = {
  scope: {
    id: "scope",
    title: "Scope & authorization",
    description: "Confirm you are allowed to test before you touch anything.",
    items: [
      ["written-auth", "Confirm written authorization", "Hold a signed authorization / rules-of-engagement document naming the target, owner, and testing window.", "Engagement letter / bug-bounty scope page", "critical"],
      ["scope-boundaries", "Define in-scope and out-of-scope assets", "List included domains, subdomains, IPs, and apps; explicitly note exclusions (third parties, production data, DoS).", "Scope checklist, asset inventory", "high"],
      ["rules-of-engagement", "Agree rules of engagement", "Testing hours, rate limits, prohibited techniques, data-handling rules, and emergency contacts.", "RoE document", "high"],
      ["test-accounts", "Provision test accounts", "Create dedicated tester accounts at each privilege level; never use real customer accounts.", "Target's own signup / client-provided accounts", "medium"],
      ["stop-conditions", "Agree stop conditions", "Decide what halts testing immediately (outage, sensitive data exposure, scope drift) and who to notify.", "RoE escalation path", "high"],
    ],
  },
  passive: {
    id: "passive-recon",
    title: "Passive recon",
    description: "Learn what the target exposes publicly — without sending it a single packet.",
    items: [
      ["search-engines", "Search-engine footprinting", "Indexed pages, exposed documents, login portals, and error messages visible in search results.", "Search operators (site:, inurl:, filetype:)", "low"],
      ["cert-transparency", "Certificate Transparency lookup", "Certificates issued for the domain reveal subdomains and naming patterns.", "crt.sh, certspotter", "low"],
      ["public-code", "Public code & leak check", "Public repositories and paste sites referencing the domain, keys, or internal hostnames (report, never use leaked secrets).", "GitHub code search, public leak indexes", "high"],
      ["wayback", "Archive review", "Historical URLs, old endpoints, and retired features that may still be live.", "Wayback Machine", "low"],
      ["tech-signals", "Public technology signals", "Job ads, headers in public scans, and vendor case studies hinting at the stack.", "Public scan databases, job boards", "info"],
    ],
  },
  dns: {
    id: "dns-discovery",
    title: "DNS & subdomain discovery",
    description: "Map the target's DNS surface and every hostname that answers.",
    items: [
      ["dns-records", "Enumerate DNS records", "A/AAAA, CNAME, MX, TXT, NS, and SOA records; note mail and verification records.", "dig, dnsx", "info"],
      ["subdomain-passive", "Passive subdomain discovery", "Aggregate subdomains from CT logs and passive DNS before any brute force.", "subfinder, amass (passive)", "low"],
      ["subdomain-active", "Active subdomain enumeration", "Wordlist-based resolution against in-scope zones only; stay within rate limits.", "puredns, shuffledns", "medium"],
      ["takeover-check", "Subdomain takeover check", "Dangling CNAMEs pointing at unclaimed third-party services.", "dnsx + fingerprint checks, subzy", "high"],
      ["zone-transfer", "Zone-transfer & DNS hygiene check", "AXFR refusal, DNSSEC posture, SPF/DKIM/DMARC configuration for the domain.", "dig axfr, mail-tester style checks", "medium"],
    ],
  },
  fingerprint: {
    id: "fingerprinting",
    title: "Fingerprinting",
    description: "Identify technologies, versions, and security headers on live hosts.",
    items: [
      ["live-hosts", "Probe live hosts", "Which discovered hosts answer HTTP/HTTPS, and on which ports.", "httpx", "info"],
      ["tech-detection", "Technology detection", "Framework, CMS, server, and CDN fingerprints; map versions to known advisories (verify, don't assume).", "httpx -tech-detect, Wappalyzer", "medium"],
      ["tls-posture", "TLS posture review", "Protocol versions, cipher strength, certificate validity and expiry.", "testssl.sh, sslyze", "medium"],
      ["security-headers", "Security headers review", "HSTS, CSP, X-Content-Type-Options, frame protection, and cookie flags on key responses.", "Browser devtools, header scanners", "medium"],
      ["waf-cdn", "WAF / CDN identification", "Detect edge protection so later testing accounts for filtering and rate limits.", "httpx, wafw00f", "low"],
    ],
  },
  crawl: {
    id: "crawling",
    title: "Crawling & content discovery",
    description: "Walk the application the way a user would, then look for what isn't linked.",
    items: [
      ["manual-crawl", "Manual crawl with proxy", "Browse every workflow through an intercepting proxy, mapping pages, forms, and parameters.", "Burp Suite / Caido proxy + site map", "medium"],
      ["content-discovery", "Content discovery", "Unlinked directories, backup files, admin panels, and debug endpoints via wordlists (in scope, rate-limited).", "ffuf, dirsearch", "medium"],
      ["js-analysis", "JavaScript analysis", "Endpoints, API routes, and keys embedded in client-side bundles.", "LinkFinder, jsluice, devtools", "medium"],
      ["param-discovery", "Parameter discovery", "Hidden query/body parameters that change application behaviour.", "Arjun, param-miner", "medium"],
      ["error-handling", "Error & debug surface review", "Verbose errors, stack traces, and debug modes leaking internals.", "Manual probing, proxy history review", "low"],
    ],
  },
  authn: {
    id: "authentication",
    title: "Authentication testing",
    description: "Test how identity is established — and how it can be broken.",
    items: [
      ["credential-policy", "Password & credential policy", "Length/complexity rules, breached-password checks, and default credentials on in-scope services.", "Manual testing with test accounts", "medium"],
      ["bruteforce-controls", "Brute-force & rate-limit controls", "Lockout, throttling, and CAPTCHA behaviour on login and OTP endpoints (low volume, agreed limits).", "Manual + proxy, agreed rate only", "high"],
      ["reset-flow", "Password-reset flow", "Token entropy, expiry, reuse, host-header poisoning, and account-enumeration leaks in reset responses.", "Manual flow analysis", "high"],
      ["mfa", "MFA enforcement", "Whether MFA can be skipped, replayed, or bypassed via alternate flows (API, remember-me, backup codes).", "Manual testing, test accounts", "high"],
      ["enumeration", "Account enumeration", "Different responses/timing for existing vs non-existing accounts on login, signup, and reset.", "Manual response comparison", "low"],
    ],
  },
  authz: {
    id: "authorization",
    title: "Authorization / IDOR",
    description: "Check that users can only reach what belongs to them.",
    items: [
      ["horizontal-idor", "Horizontal IDOR / BOLA", "Swap object IDs between two same-role test accounts and confirm access is denied.", "Two test accounts + proxy (Autorize-style)", "high"],
      ["vertical-priv", "Vertical privilege escalation", "Low-privilege accounts attempting admin-only actions and endpoints.", "Role-matrix testing", "critical"],
      ["function-level", "Function-level authorization", "Admin functions reachable by direct URL/API call without the UI exposing them.", "Forced browsing with test accounts", "high"],
      ["mass-assignment", "Mass assignment", "Extra fields in requests (role, isAdmin, balance) that the server should ignore.", "Proxy request editing", "high"],
      ["tenant-isolation", "Tenant / workspace isolation", "Cross-tenant object access in multi-tenant features (files, exports, invites).", "Two workspaces, cross-access attempts", "critical"],
    ],
  },
  input: {
    id: "input-validation",
    title: "Input validation",
    description: "Probe how the application handles hostile input — XSS, SQLi, SSRF classes and friends.",
    items: [
      ["xss", "Cross-site scripting (XSS)", "Reflected, stored, and DOM XSS in every input reflected back to a browser, including file uploads and rich text.", "Manual payloads, DOM invader-style tooling", "high"],
      ["sqli", "SQL / NoSQL injection", "Injection points in search, filters, and IDs; confirm with safe boolean/time probes, never extract real data.", "Manual probes, sqlmap (safe settings)", "critical"],
      ["ssrf", "Server-side request forgery (SSRF)", "URL-fetching features (imports, webhooks, previews) reaching internal or metadata endpoints.", "Out-of-band collaborator, manual probes", "critical"],
      ["upload", "File-upload validation", "Extension/MIME bypasses, path traversal in filenames, and stored-file execution or XSS.", "Manual upload matrix with test files", "high"],
      ["injection-misc", "Command / template / XXE injection", "OS command, SSTI, and XML external entity classes where the stack suggests them.", "Manual class-specific probes", "critical"],
      ["open-redirect", "Open redirect & header injection", "Redirect parameters and response-splitting opportunities usable for phishing chains.", "Manual parameter review", "low"],
    ],
  },
  session: {
    id: "session",
    title: "Session management",
    description: "Sessions should be unpredictable, scoped, and revocable.",
    items: [
      ["cookie-flags", "Cookie security flags", "Secure, HttpOnly, and SameSite attributes on session and sensitive cookies.", "Devtools / proxy inspection", "medium"],
      ["token-entropy", "Session token quality", "Length, entropy, and predictability of session identifiers; fixation after login.", "Token analysis, sequencer-style checks", "high"],
      ["logout-invalidation", "Logout & timeout invalidation", "Server-side invalidation on logout, password change, and idle/absolute timeouts.", "Manual replay of old tokens", "medium"],
      ["jwt-review", "JWT review (if used)", "Algorithm confusion, weak secrets, missing expiry, and unverified signatures.", "jwt_tool-style manual review", "high"],
      ["csrf", "CSRF protection", "State-changing requests require unpredictable tokens or SameSite enforcement; test token removal/reuse.", "Manual PoC form against test account", "medium"],
    ],
  },
  business: {
    id: "business-logic",
    title: "Business logic",
    description: "Abuse the rules of the application, not just its code.",
    items: [
      ["workflow-bypass", "Workflow step bypass", "Skipping checkout, verification, or approval steps by calling later steps directly.", "Manual workflow mapping + proxy", "high"],
      ["race-conditions", "Race conditions", "Parallel requests on coupons, balances, votes, or one-time actions (small bursts, agreed limits).", "Proxy parallel-request tooling", "high"],
      ["price-quantity", "Price / quantity manipulation", "Negative quantities, tampered prices, and currency/rounding abuse in test transactions.", "Manual request editing", "high"],
      ["limit-abuse", "Limit & quota abuse", "Free-tier, invite, referral, and rate limits that can be reset or multiplied.", "Manual abuse-case walkthroughs", "medium"],
      ["state-transitions", "State-transition abuse", "Replaying or reversing completed states (refunds, cancellations, approvals) out of order.", "Manual state-machine review", "medium"],
    ],
  },
  reporting: {
    id: "reporting",
    title: "Reporting",
    description: "Turn notes into findings the owner can act on.",
    items: [
      ["evidence", "Collect clean evidence", "Minimal, reproducible proof for each finding using test accounts only — no real user data.", "Screenshots, request/response pairs (redacted)", "medium"],
      ["severity", "Rate severity honestly", "CVSS-style scoring with business context; no inflation, no duplicates.", "CVSS calculator + context notes", "medium"],
      ["remediation", "Write remediation guidance", "Concrete fix per finding: what to change, where, and how to verify the fix.", "OWASP Cheat Sheets as reference", "low"],
      ["retest", "Plan retest", "Agree how fixes will be verified and how retest results are reported.", "Retest checklist derived from findings", "low"],
      ["cleanup", "Clean up test artifacts", "Remove test accounts, uploaded files, and test data; confirm nothing tester-owned remains.", "Cleanup checklist with the owner", "medium"],
    ],
  },
};

// API-flavoured swaps/additions for the API profile.
const API_OVERRIDES = {
  fingerprinting: [
    ["api-discovery", "API surface discovery", "OpenAPI/Swagger documents, GraphQL introspection, and versioned base paths exposed by the target.", "Manual doc hunting, kiterunner", "medium"],
    ["api-versioning", "API versioning review", "Old API versions still reachable with weaker controls than the current one.", "Manual version probing", "medium"],
  ],
  crawling: [
    ["endpoint-inventory", "Endpoint inventory", "Build a full route/method inventory from docs, JS bundles, and proxy history.", "Proxy history, OpenAPI parsing", "medium"],
    ["graphql-review", "GraphQL review (if present)", "Introspection, batching, depth limits, and field-level authorization.", "GraphQL Voyager-style mapping, manual queries", "medium"],
  ],
  authentication: [
    ["api-keys", "API key & token handling", "Key scope, rotation, leakage in URLs/logs, and tokens accepted over plain HTTP.", "Manual token review", "high"],
    ["oauth-flow", "OAuth / OIDC flow review", "Redirect URI validation, state/PKCE enforcement, and token audience checks.", "Manual flow analysis", "high"],
  ],
  "input-validation": [
    ["api-injection", "API injection classes", "Injection via JSON bodies, filters, and sort/order parameters (SQLi, NoSQLi, command).", "Manual probes, safe automated checks", "critical"],
    ["rate-limiting", "Rate limiting & resource limits", "Per-token throttling, pagination caps, and payload-size limits on expensive endpoints.", "Low-volume manual checks", "medium"],
  ],
};

// Which phases each profile includes, and how many items per phase (Infinity = all).
const PROFILE_PLAN = {
  quick: [
    ["scope", 3],
    ["passive", 3],
    ["dns", 3],
    ["fingerprint", 3],
    ["crawl", 3],
    ["reporting", 3],
  ],
  full: [
    ["scope", Infinity],
    ["passive", Infinity],
    ["dns", Infinity],
    ["fingerprint", Infinity],
    ["crawl", Infinity],
    ["authn", Infinity],
    ["authz", Infinity],
    ["input", Infinity],
    ["session", Infinity],
    ["business", Infinity],
    ["reporting", Infinity],
  ],
  api: [
    ["scope", Infinity],
    ["passive", 2],
    ["dns", 3],
    ["fingerprint", Infinity],
    ["crawl", Infinity],
    ["authn", Infinity],
    ["authz", Infinity],
    ["input", Infinity],
    ["session", 3],
    ["business", 2],
    ["reporting", Infinity],
  ],
};

export function validateDomain(input) {
  if (typeof input !== "string" || input.trim() === "") {
    return { ok: false, domain: null, error: "Enter a target domain, e.g. example.com." };
  }
  let value = input.trim().toLowerCase();
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, ""); // strip scheme
  value = value.split("/")[0].split("?")[0].split("#")[0]; // strip path/query/fragment
  value = value.split("@").pop(); // strip userinfo
  value = value.replace(/:\d+$/, ""); // strip port
  value = value.replace(/\.$/, ""); // strip trailing dot

  if (value.length === 0 || value.length > 253) {
    return { ok: false, domain: null, error: "Domain is empty or too long." };
  }
  if (/\s/.test(value) || value.includes("_")) {
    return { ok: false, domain: null, error: "Domains cannot contain spaces or underscores." };
  }
  const labels = value.split(".");
  if (labels.length < 2) {
    return { ok: false, domain: null, error: "Enter a full domain with a TLD, e.g. example.com." };
  }
  for (const label of labels) {
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) {
      return { ok: false, domain: null, error: `Invalid label "${label}" — use letters, digits, and hyphens only.` };
    }
  }
  const tld = labels[labels.length - 1];
  if (!/^[a-z]{2,}$/.test(tld)) {
    return { ok: false, domain: null, error: "The top-level domain looks invalid." };
  }
  return { ok: true, domain: value, error: null };
}

function toItem(phaseId, tuple) {
  const [suffix, title, description, tool, severity] = tuple;
  return { id: `${phaseId}:${suffix}`, title, description, tool, severity };
}

export function buildChecklist(domainInput, profileId = "full") {
  const validation = validateDomain(domainInput);
  if (!validation.ok) {
    throw new Error(validation.error);
  }
  const profile = PROFILES[profileId];
  if (!profile) {
    throw new Error(`Unknown profile "${profileId}". Use one of: ${Object.keys(PROFILES).join(", ")}.`);
  }
  const plan = PROFILE_PLAN[profileId];
  const phases = plan.map(([phaseKey, limit]) => {
    const base = PHASES[phaseKey];
    let tuples = base.items;
    if (profileId === "api" && API_OVERRIDES[base.id]) {
      tuples = [...API_OVERRIDES[base.id], ...base.items];
    }
    const items = tuples.slice(0, limit).map((t) => toItem(base.id, t));
    return { id: base.id, title: base.title, description: base.description, items };
  });
  return {
    domain: validation.domain,
    profile: profile.id,
    profileLabel: profile.label,
    phases,
    totalItems: phases.reduce((sum, p) => sum + p.items.length, 0),
  };
}

function checkedSet(checked) {
  if (!checked) return new Set();
  if (checked instanceof Set) return checked;
  if (Array.isArray(checked)) return new Set(checked);
  if (typeof checked === "object") {
    return new Set(Object.keys(checked).filter((k) => checked[k]));
  }
  return new Set();
}

export function progressSummary(checklist, checked) {
  const done = checkedSet(checked);
  const perPhase = checklist.phases.map((phase) => {
    const total = phase.items.length;
    const phaseDone = phase.items.filter((item) => done.has(item.id)).length;
    return {
      phaseId: phase.id,
      title: phase.title,
      total,
      done: phaseDone,
      percent: total === 0 ? 100 : Math.round((phaseDone / total) * 100),
    };
  });
  const total = perPhase.reduce((s, p) => s + p.total, 0);
  const doneCount = perPhase.reduce((s, p) => s + p.done, 0);
  return {
    total,
    done: doneCount,
    remaining: total - doneCount,
    percent: total === 0 ? 100 : Math.round((doneCount / total) * 100),
    perPhase,
  };
}

export function toMarkdown(checklist, state = {}) {
  const done = checkedSet(state.checked);
  const notes = state.notes || {};
  const summary = progressSummary(checklist, done);
  const lines = [
    `# nightcrawl checklist — ${checklist.domain}`,
    "",
    `- **Profile:** ${checklist.profileLabel}`,
    `- **Progress:** ${summary.done}/${summary.total} (${summary.percent}%)`,
    `- **Scope note:** Authorized testing only. Confirm written authorization and scope before testing.`,
    "",
  ];
  for (const phase of checklist.phases) {
    const phaseSummary = summary.perPhase.find((p) => p.phaseId === phase.id);
    lines.push(`## ${phase.title} (${phaseSummary.done}/${phaseSummary.total})`, "");
    lines.push(`_${phase.description}_`, "");
    for (const item of phase.items) {
      const box = done.has(item.id) ? "x" : " ";
      lines.push(`- [${box}] **${item.title}** [${item.severity}] — ${item.description} _Tool/technique: ${item.tool}._`);
    }
    lines.push("");
    if (notes[phase.id] && notes[phase.id].trim() !== "") {
      lines.push(`> Notes: ${notes[phase.id].trim()}`, "");
    }
  }
  lines.push("---", "Generated with nightcrawl — a recon checklist planner for authorized security testing.");
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Browser UI (guarded: skipped under Node / tests)
// ---------------------------------------------------------------------------
if (typeof document !== "undefined") {
  const $ = (sel) => document.querySelector(sel);
  const storageKey = (domain, profile) => `nightcrawl:${domain}:${profile}`;

  let checklist = null;
  let state = { checked: [], notes: {} };

  function loadState() {
    try {
      const raw = localStorage.getItem(storageKey(checklist.domain, checklist.profile));
      state = raw ? JSON.parse(raw) : { checked: [], notes: {} };
      if (!Array.isArray(state.checked)) state.checked = [];
      if (!state.notes || typeof state.notes !== "object") state.notes = {};
    } catch {
      state = { checked: [], notes: {} };
    }
  }

  function saveState() {
    try {
      localStorage.setItem(storageKey(checklist.domain, checklist.profile), JSON.stringify(state));
    } catch {
      // storage unavailable (private mode etc.) — checklist still works in-memory
    }
  }

  function renderProgress() {
    const summary = progressSummary(checklist, state.checked);
    $("#overall-bar").style.width = `${summary.percent}%`;
    $("#overall-label").textContent = `${summary.done} of ${summary.total} done — ${summary.percent}%`;
    for (const p of summary.perPhase) {
      const bar = document.querySelector(`[data-phase-bar="${p.phaseId}"]`);
      const label = document.querySelector(`[data-phase-label="${p.phaseId}"]`);
      if (bar) bar.style.width = `${p.percent}%`;
      if (label) label.textContent = `${p.done}/${p.total}`;
    }
  }

  function render() {
    const container = $("#phases");
    container.innerHTML = "";
    $("#plan-title").textContent = `${checklist.domain} — ${checklist.profileLabel}`;
    $("#plan-panel").hidden = false;

    for (const phase of checklist.phases) {
      const section = document.createElement("section");
      section.className = "phase glass";
      const header = document.createElement("div");
      header.className = "phase-head";
      header.innerHTML = `<h3></h3><span class="phase-count" data-phase-label="${phase.id}"></span>`;
      header.querySelector("h3").textContent = phase.title;
      const desc = document.createElement("p");
      desc.className = "phase-desc";
      desc.textContent = phase.description;
      const track = document.createElement("div");
      track.className = "track";
      track.innerHTML = `<div class="fill" data-phase-bar="${phase.id}"></div>`;

      const list = document.createElement("ul");
      list.className = "items";
      for (const item of phase.items) {
        const li = document.createElement("li");
        li.className = "item";
        const label = document.createElement("label");
        const box = document.createElement("input");
        box.type = "checkbox";
        box.checked = state.checked.includes(item.id);
        box.addEventListener("change", () => {
          state.checked = box.checked
            ? [...new Set([...state.checked, item.id])]
            : state.checked.filter((id) => id !== item.id);
          saveState();
          renderProgress();
        });
        const body = document.createElement("span");
        body.className = "item-body";
        const title = document.createElement("strong");
        title.textContent = item.title;
        const sev = document.createElement("span");
        sev.className = `sev sev-${item.severity}`;
        sev.textContent = item.severity;
        const text = document.createElement("span");
        text.className = "item-desc";
        text.textContent = item.description;
        const tool = document.createElement("span");
        tool.className = "item-tool";
        tool.textContent = item.tool;
        body.append(title, sev, text, tool);
        label.append(box, body);
        li.append(label);
        list.append(li);
      }

      const notes = document.createElement("textarea");
      notes.className = "notes";
      notes.placeholder = `Notes for ${phase.title}…`;
      notes.value = state.notes[phase.id] || "";
      notes.addEventListener("input", () => {
        state.notes[phase.id] = notes.value;
        saveState();
      });

      section.append(header, desc, track, list, notes);
      container.append(section);
    }
    renderProgress();
  }

  function flash(message) {
    const el = $("#status");
    el.textContent = message;
    el.hidden = false;
    setTimeout(() => { el.hidden = true; }, 3000);
  }

  document.addEventListener("DOMContentLoaded", () => {
    $("#generate-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const validation = validateDomain($("#domain").value);
      const errorEl = $("#domain-error");
      if (!validation.ok) {
        errorEl.textContent = validation.error;
        errorEl.hidden = false;
        return;
      }
      errorEl.hidden = true;
      const profile = document.querySelector('input[name="profile"]:checked').value;
      checklist = buildChecklist(validation.domain, profile);
      loadState();
      render();
      flash(`Checklist ready for ${checklist.domain} (${checklist.profileLabel}).`);
    });

    $("#download").addEventListener("click", () => {
      if (!checklist) return;
      const blob = new Blob([toMarkdown(checklist, state)], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `nightcrawl-${checklist.domain}-${checklist.profile}.md`;
      a.click();
      URL.revokeObjectURL(url);
    });

    $("#copy").addEventListener("click", async () => {
      if (!checklist) return;
      try {
        await navigator.clipboard.writeText(toMarkdown(checklist, state));
        flash("Markdown copied to clipboard.");
      } catch {
        flash("Clipboard unavailable — use Download instead.");
      }
    });

    $("#print").addEventListener("click", () => window.print());

    $("#reset").addEventListener("click", () => {
      if (!checklist) return;
      state = { checked: [], notes: {} };
      saveState();
      render();
      flash("Progress reset for this domain + profile.");
    });
  });
}
