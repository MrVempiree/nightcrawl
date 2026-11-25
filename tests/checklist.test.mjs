import { test } from "node:test";
import assert from "node:assert/strict";
import { validateDomain, buildChecklist, progressSummary, toMarkdown, PROFILES } from "../app.js";

test("validateDomain accepts plain and subdomain targets", () => {
  assert.deepEqual(validateDomain("example.com"), { ok: true, domain: "example.com", error: null });
  assert.equal(validateDomain("app.example.co.uk").ok, true);
  assert.equal(validateDomain("my-site.example.com").domain, "my-site.example.com");
});

test("validateDomain normalizes scheme, case, path, and port", () => {
  assert.equal(validateDomain("HTTPS://Example.COM/login?next=/home").domain, "example.com");
  assert.equal(validateDomain("  example.com:8443  ").domain, "example.com");
  assert.equal(validateDomain("example.com.").domain, "example.com");
});

test("validateDomain rejects invalid input", () => {
  for (const bad of ["", "   ", "localhost", "not a domain.com", "exam_ple.com", "-example.com", "example-.com", "example.c", "example.123", "http://", 42, null]) {
    const result = validateDomain(bad);
    assert.equal(result.ok, false, `expected ${JSON.stringify(bad)} to be invalid`);
    assert.equal(result.domain, null);
    assert.equal(typeof result.error, "string");
  }
});

test("buildChecklist starts with scope & authorization for every profile", () => {
  for (const profile of Object.keys(PROFILES)) {
    const checklist = buildChecklist("example.com", profile);
    assert.equal(checklist.phases[0].id, "scope");
    assert.match(checklist.phases[0].items[0].title, /authorization/i);
    assert.equal(checklist.domain, "example.com");
    assert.equal(checklist.profile, profile);
  }
});

test("profiles differ in phase and item counts", () => {
  const quick = buildChecklist("example.com", "quick");
  const full = buildChecklist("example.com", "full");
  const api = buildChecklist("example.com", "api");

  assert.ok(quick.phases.length < full.phases.length, "quick should have fewer phases than full");
  assert.ok(quick.totalItems < api.totalItems, "quick should have fewer items than api");
  assert.ok(api.totalItems < full.totalItems, "api should have fewer items than full");
  assert.equal(full.phases.length, 11);
  assert.equal(quick.totalItems, quick.phases.reduce((s, p) => s + p.items.length, 0));
});

test("full profile covers the OWASP-style phases", () => {
  const titles = buildChecklist("example.com", "full").phases.map((p) => p.title);
  for (const expected of [
    "Scope & authorization",
    "Passive recon",
    "DNS & subdomain discovery",
    "Fingerprinting",
    "Crawling & content discovery",
    "Authentication testing",
    "Authorization / IDOR",
    "Input validation",
    "Session management",
    "Business logic",
    "Reporting",
  ]) {
    assert.ok(titles.includes(expected), `missing phase: ${expected}`);
  }
});

test("api profile includes API-specific items", () => {
  const api = buildChecklist("api.example.com", "api");
  const titles = api.phases.flatMap((p) => p.items.map((i) => i.title));
  assert.ok(titles.some((t) => /API surface discovery/i.test(t)));
  assert.ok(titles.some((t) => /OAuth/i.test(t)));
  assert.ok(titles.some((t) => /endpoint inventory/i.test(t)));
});

test("every item carries title, description, tool note, and severity", () => {
  const checklist = buildChecklist("example.com", "full");
  const severities = new Set(["info", "low", "medium", "high", "critical"]);
  const ids = new Set();
  for (const phase of checklist.phases) {
    assert.ok(phase.items.length > 0, `phase ${phase.id} is empty`);
    for (const item of phase.items) {
      assert.ok(item.title.length > 0);
      assert.ok(item.description.length > 0);
      assert.ok(item.tool.length > 0);
      assert.ok(severities.has(item.severity), `bad severity: ${item.severity}`);
      assert.ok(!ids.has(item.id), `duplicate item id: ${item.id}`);
      ids.add(item.id);
    }
  }
});

test("buildChecklist throws on invalid domain or profile", () => {
  assert.throws(() => buildChecklist("not a domain", "full"), /spaces|underscores/i);
  assert.throws(() => buildChecklist("example.com", "nope"), /Unknown profile/);
});

test("progressSummary computes overall and per-phase math", () => {
  const checklist = buildChecklist("example.com", "quick");
  const firstPhase = checklist.phases[0];
  const checked = firstPhase.items.map((i) => i.id);

  const summary = progressSummary(checklist, checked);
  assert.equal(summary.total, checklist.totalItems);
  assert.equal(summary.done, firstPhase.items.length);
  assert.equal(summary.remaining, summary.total - summary.done);
  assert.equal(summary.percent, Math.round((summary.done / summary.total) * 100));
  assert.equal(summary.perPhase[0].percent, 100);
  assert.equal(summary.perPhase[1].percent, 0);

  const empty = progressSummary(checklist, []);
  assert.equal(empty.done, 0);
  assert.equal(empty.percent, 0);

  const all = progressSummary(checklist, checklist.phases.flatMap((p) => p.items.map((i) => i.id)));
  assert.equal(all.percent, 100);
  assert.equal(all.remaining, 0);
});

test("progressSummary accepts arrays, Sets, and id->bool maps", () => {
  const checklist = buildChecklist("example.com", "quick");
  const id = checklist.phases[0].items[0].id;
  assert.equal(progressSummary(checklist, [id]).done, 1);
  assert.equal(progressSummary(checklist, new Set([id])).done, 1);
  assert.equal(progressSummary(checklist, { [id]: true, "bogus:id": false }).done, 1);
  assert.equal(progressSummary(checklist).done, 0);
});

test("toMarkdown renders checkbox states, progress, and notes", () => {
  const checklist = buildChecklist("example.com", "quick");
  const checkedId = checklist.phases[0].items[0].id;
  const md = toMarkdown(checklist, {
    checked: [checkedId],
    notes: { scope: "Authorization letter signed 2026-01-01." },
  });

  assert.match(md, /^# nightcrawl checklist — example\.com/);
  assert.match(md, /- \*\*Profile:\*\* Quick recon/);
  assert.match(md, new RegExp(`- \\*\\*Progress:\\*\\* 1/${checklist.totalItems}`));
  assert.match(md, /- \[x\] \*\*Confirm written authorization\*\*/);
  assert.match(md, /- \[ \] \*\*/);
  assert.match(md, /> Notes: Authorization letter signed 2026-01-01\./);
  assert.match(md, /Authorized testing only/);
  assert.match(md, /## Scope & authorization \(1\/3\)/);
});

test("toMarkdown with no state renders everything unchecked", () => {
  const checklist = buildChecklist("example.com", "full");
  const md = toMarkdown(checklist);
  assert.ok(!md.includes("- [x]"));
  assert.equal((md.match(/- \[ \]/g) || []).length, checklist.totalItems);
});
