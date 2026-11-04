/**
 * Comparison logic checks against the running backend's existing assessments
 * (read-only GET requests). Variants are in-memory copies of real API data and
 * are never persisted.
 *
 * Run from frontend/:  node src/lib/assessmentComparison.test.ts
 * Optional:            ASSESSMENT_API=http://host:port/api/v1/assessments
 */
import type {
  AssessmentDetail,
  AssessmentFinding,
  AssessmentSummary,
} from "../api/types.ts";
import {
  compareAssessments,
  compareFindings,
  findingKey,
  lookupCoverage,
  readCoverage,
  type AssessmentComparisonResult,
} from "./assessmentComparison.ts";

declare const process: { env: Record<string, string | undefined> } | undefined;

const API =
  (typeof process !== "undefined" && process.env.ASSESSMENT_API) ||
  "http://127.0.0.1:8000/api/v1/assessments";

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${message}`);
}

async function getJson<T>(url: string): Promise<T> {
  const response = await fetch(url);
  check(response.status === 200, `${url} returned ${response.status}`);
  return (await response.json()) as T;
}

const results: string[] = [];
function pass(name: string, note = "") {
  results.push(`PASS ${name}${note ? ` — ${note}` : ""}`);
}
const blocking = (c: AssessmentComparisonResult) =>
  c.issues.filter((i) => i.level === "blocking").map((i) => i.message);
const warnings = (c: AssessmentComparisonResult) =>
  c.issues.filter((i) => i.level === "warning").map((i) => i.message);
const clone = (detail: AssessmentDetail): AssessmentDetail => structuredClone(detail);
const sameJson = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

function expectBlockedWithoutResults(c: AssessmentComparisonResult, message: string) {
  check(!c.comparable, `${message}: comparison should be blocked`);
  check(c.findings === null, `${message}: findings must not be presented`);
  check(c.evidence === null, `${message}: evidence must not be presented`);
}

const list = await getJson<AssessmentSummary[]>(API);
const details = await Promise.all(
  list.map((item) => getJson<AssessmentDetail>(`${API}/${item.id}`)),
);
// The real-data cases below are about runs recorded before coverage existed;
// newer runs record coverage and are covered by the in-memory variants.
const complete = details
  .filter((d) => d.status === "COMPLETE" && !readCoverage(d).recorded && d.target !== "AUTHORIZED_IOT")
  .sort((a, b) => Date.parse(b.started_at) - Date.parse(a.started_at));
const incomplete = details.find((d) => d.status !== "COMPLETE");
check(complete.length >= 2, "need two COMPLETE runs without recorded coverage");

for (const summary of list) {
  const detail = details.find((d) => d.id === summary.id);
  check(detail, `detail missing for ${summary.id}`);
  check(detail.finding_count === detail.findings.length, "finding_count mismatch");
  check(detail.highest_risk === summary.highest_risk, "highest_risk mismatch");
}

const [after0, before0] = complete; // newest first: before0 started earlier
const NEW_META = {
  admin_service_ports: [22],
  mqtt_broker_port: 1883,
  mqtt_tls_port: 8883,
  check_catalog_version: "IoT-CHECKS-v1",
};

// Scope compatibility check: single-device vs environment is blocked.
{
  const envDetail = clone(before0);
  envDetail.target = "AUTHORIZED_IOT";
  envDetail.assessment_type = "ENVIRONMENT";
  const c = compareAssessments(before0, envDetail);
  expectBlockedWithoutResults(c, "single-device vs environment scope mismatch");
  check(
    blocking(c).some((m) => m.includes("assessment scopes differ")),
    "scope mismatch message",
  );
  pass("scope compatibility: single-device vs environment blocked");
}

// Normal chronological comparison (real data) — CASE A, H, J, D.
{
  const c = compareAssessments(before0, after0);
  check(c.comparable, "real chronological pair should be comparable");
  check(c.findings && c.evidence, "results should be presented");
  check(blocking(c).length === 0, "no blocking issues expected");
  check(c.findings.remaining.length === before0.findings.length, "all findings remaining");
  check(c.findings.added.length === 0, "no new findings");
  check(c.findings.resolved.length === 0, "no resolved findings");
  check(!c.beforeCoverage.recorded && !c.afterCoverage.recorded, "legacy coverage");
  check(
    warnings(c).some((m) =>
      m.startsWith("Resolution status is unavailable because AFTER coverage was not recorded"),
    ),
    "AFTER coverage limitation shown",
  );
  check(
    !warnings(c).some((m) => m.includes("started after")),
    "no chronology issue for a chronological pair",
  );
  check(c.risk.before && c.risk.after, "both overall snapshots present");
  check(c.risk.delta === c.risk.after.score - c.risk.before.score, "overall delta");
  for (const r of c.findings.remaining) {
    if (r.risk.before && r.risk.after) {
      check(r.risk.delta === r.risk.after.score - r.risk.before.score, "per-finding delta");
    } else {
      check(r.risk.delta === null, "per-finding delta null when a side is missing");
    }
  }
  pass("A normal chronological comparison", `${before0.id.slice(0, 8)} -> ${after0.id.slice(0, 8)}, ${c.findings.remaining.length} remaining`);
  pass("H remaining (real)");
  pass("J overall delta (real)", `${c.risk.before.score} -> ${c.risk.after.score}, delta ${c.risk.delta}`);
  pass("D legacy coverage = not recorded, no resolved claims");
}

// FIX 2 — BEFORE started after AFTER: blocked.
{
  const c = compareAssessments(after0, before0);
  expectBlockedWithoutResults(c, "reversed chronology");
  check(
    blocking(c).includes(
      "Cannot compare: the BEFORE assessment started after the AFTER assessment.",
    ),
    "chronology blocking message",
  );
  pass("BEFORE started after AFTER -> blocked (real data, reversed)");
}
{
  // Instants are compared, not strings: 15:00+05:30 (09:30Z) is before 10:00Z.
  const before = clone(before0);
  const after = clone(after0);
  before.started_at = "2026-01-01T15:00:00+05:30";
  after.started_at = "2026-01-01T10:00:00Z";
  check(compareAssessments(before, after).comparable, "offset-aware order should be comparable");
  before.started_at = "2026-01-01T10:30:00Z";
  after.started_at = "2026-01-01T15:30:00+05:30"; // 10:00Z
  check(!compareAssessments(before, after).comparable, "offset-aware reversed order blocked");
  pass("chronology compares instants across UTC offsets");
}
{
  const before = clone(before0);
  before.started_at = after0.started_at;
  const c = compareAssessments(before, after0);
  check(c.comparable, "equal start times are not blocked");
  check(
    warnings(c).some((m) => m.includes("same recorded start time")),
    "equal start time warning",
  );
  before.started_at = "not a timestamp";
  expectBlockedWithoutResults(compareAssessments(before, after0), "unreadable start time");
  pass("equal start time -> warning; unreadable start time -> blocked");
}

// FIX 1 — duplicate finding keys: blocked.
{
  const after = clone(after0);
  const original = after.findings[0];
  const duplicate: AssessmentFinding = {
    ...original,
    id: "00000000-0000-0000-0000-00000000d001",
  };
  after.findings.push(duplicate);
  const c = compareAssessments(before0, after);
  expectBlockedWithoutResults(c, "AFTER duplicate key");
  const expected = `(${original.finding_id}, ${original.target}, ${original.port ?? "no port"}) × 2`;
  check(
    blocking(c).some(
      (m) =>
        m.startsWith("Cannot compare: the AFTER assessment contains duplicate finding keys") &&
        m.includes(expected),
    ),
    `duplicate message should identify ${expected}`,
  );
  let threw = false;
  try {
    compareFindings(before0, after);
  } catch {
    threw = true;
  }
  check(threw, "compareFindings must refuse duplicate keys");
  pass("duplicate finding key in AFTER -> blocked", expected);
}
{
  const before = clone(before0);
  const nullPort = { ...before.findings[0], id: "00000000-0000-0000-0000-00000000d002", port: null };
  before.findings.push(nullPort, { ...nullPort, id: "00000000-0000-0000-0000-00000000d003" });
  const c = compareAssessments(before, after0);
  expectBlockedWithoutResults(c, "BEFORE duplicate key");
  check(
    blocking(c).some(
      (m) =>
        m.startsWith("Cannot compare: the BEFORE assessment contains duplicate finding keys") &&
        m.includes(`(${nullPort.finding_id}, ${nullPort.target}, no port) × 2`),
    ),
    "BEFORE duplicate with null port identified",
  );
  pass("duplicate finding key in BEFORE (null port) -> blocked");
}

// Existing gate checks.
if (incomplete) {
  const c = compareAssessments(incomplete, after0);
  expectBlockedWithoutResults(c, "INCOMPLETE run");
  check(blocking(c).some((m) => m.includes("BEFORE assessment status is")), "status reason");
  pass("real INCOMPLETE run blocked", `${blocking(c).length} blocking reasons`);
}
check(
  blocking(compareAssessments(after0, after0)).some((m) => m.includes("same assessment")),
  "same assessment blocked",
);
pass("same assessment blocked");
{
  const after = clone(after0);
  after.target = "198.51.100.7";
  check(
    blocking(compareAssessments(before0, after)).some((m) => m.startsWith("Cannot compare: targets differ")),
    "targets differ",
  );
  pass("B different targets blocked");
}
{
  const after = clone(after0);
  (after as { assessment_type: string }).assessment_type = "OTHER_TYPE";
  check(
    blocking(compareAssessments(before0, after)).some((m) =>
      m.startsWith("Cannot compare: assessment types differ"),
    ),
    "types differ",
  );
  pass("C different assessment types blocked");
}
{
  const before = clone(before0);
  Object.assign(before.metadata, NEW_META);
  const after = clone(after0);
  Object.assign(after.metadata, NEW_META, { check_catalog_version: "IoT-CHECKS-v2" });
  check(
    blocking(compareAssessments(before, after)).some((m) =>
      m.startsWith("Cannot compare: check catalog versions differ"),
    ),
    "catalog differs",
  );
  const after2 = clone(after0);
  Object.assign(after2.metadata, NEW_META, { admin_service_ports: [22, 2323] });
  check(
    blocking(compareAssessments(before, after2)).some((m) => m.includes("admin_service_ports")),
    "config differs",
  );
  const after3 = clone(after0);
  Object.assign(after3.metadata, NEW_META);
  after3.metadata.ports = [...(after3.metadata.ports as number[])].reverse();
  check(blocking(compareAssessments(before, after3)).length === 0, "port order ignored");
  pass("catalog/config differences blocked; port order ignored");
}

// Coverage and resolution.
const mqtt01 = after0.findings.find((f) => f.finding_id === "IOT-MQTT-01");
const net06 = after0.findings.find((f) => f.finding_id === "NET-06");
check(mqtt01 && net06, "expected real IOT-MQTT-01 and NET-06 findings");

function afterWith(coverage: unknown[] | undefined, removed: AssessmentFinding[]) {
  const after = clone(after0);
  const ids = new Set(removed.map((f) => f.id));
  after.findings = after.findings.filter((f) => !ids.has(f.id));
  after.risk_snapshots = after.risk_snapshots.filter(
    (s) => s.finding_ref === null || !ids.has(s.finding_ref),
  );
  Object.assign(after.metadata, NEW_META);
  if (coverage) after.metadata.checks_evaluated = coverage;
  return after;
}
function unconfirmedReasonFor(c: AssessmentComparisonResult, findingId: string) {
  return c.findings?.unconfirmed.find((u) => u.before.finding_id === findingId)?.reason;
}

{
  const c = compareAssessments(
    before0,
    afterWith(
      [
        { check_id: "IOT-MQTT-01", port: mqtt01.port, status: "EVALUATED" },
        { check_id: "NET-06", port: null, status: "EVALUATED" },
      ],
      [mqtt01, net06],
    ),
  );
  check(c.findings, "comparable");
  const resolved = c.findings.resolved.map((r) => findingKey(r.before));
  check(resolved.includes(findingKey(mqtt01)), "IOT-MQTT-01 resolved");
  check(resolved.includes(findingKey(net06)), "NET-06 resolved");
  const net = c.findings.resolved.find((r) => r.before.finding_id === "NET-06");
  check(net?.coverage.kind === "entry" && net.coverage.scope === "scan_wide", "scan-wide scope");
  pass("E resolved when AFTER coverage EVALUATED", resolved.join(" "));
}
{
  const index = readCoverage({
    metadata: {
      ports: [1883],
      checks_evaluated: [{ check_id: "NET-06", port: null, status: "EVALUATED" }],
    },
  } as unknown as AssessmentDetail);
  check(lookupCoverage(index, "NET-06", 445).kind === "no_entry", "outside scanned ports");
  check(lookupCoverage(index, "NET-06", null).kind === "entry", "null port exact");
  pass("scan-wide entry limited to scanned ports; null port matched exactly");
}
check(
  unconfirmedReasonFor(
    compareAssessments(before0, afterWith([{ check_id: "IOT-MQTT-01", port: 8883, status: "EVALUATED" }], [mqtt01])),
    "IOT-MQTT-01",
  ) === "NO_COVERAGE_ENTRY",
  "other-port coverage not used",
);
pass("coverage for another port is not used");
check(
  unconfirmedReasonFor(
    compareAssessments(before0, afterWith([{ check_id: "IOT-MQTT-01", port: mqtt01.port, status: "NOT_EVALUATED" }], [mqtt01])),
    "IOT-MQTT-01",
  ) === "NOT_EVALUATED",
  "NOT_EVALUATED",
);
pass("F NOT_EVALUATED -> not confirmed");
check(
  unconfirmedReasonFor(
    compareAssessments(before0, afterWith([{ check_id: "IOT-MQTT-01", port: mqtt01.port, status: "NOT_APPLICABLE" }], [mqtt01])),
    "IOT-MQTT-01",
  ) === "NOT_APPLICABLE",
  "NOT_APPLICABLE",
);
pass("NOT_APPLICABLE -> not resolved");
check(
  unconfirmedReasonFor(
    compareAssessments(
      before0,
      afterWith(
        [
          { check_id: "IOT-MQTT-01", port: mqtt01.port, status: "EVALUATED" },
          { check_id: "IOT-MQTT-01", port: mqtt01.port, status: "NOT_EVALUATED" },
        ],
        [mqtt01],
      ),
    ),
    "IOT-MQTT-01",
  ) === "NOT_EVALUATED",
  "weakest wins",
);
pass("duplicate coverage entries use backend weakest-wins rule");
{
  const c = compareAssessments(before0, afterWith(undefined, [mqtt01]));
  check(c.findings?.resolved.length === 0, "no resolved without coverage");
  check(unconfirmedReasonFor(c, "IOT-MQTT-01") === "COVERAGE_NOT_RECORDED", "coverage missing");
  pass("G coverage missing -> coverage not recorded");
}
{
  const after = clone(after0);
  after.findings.push({ ...mqtt01, id: "00000000-0000-0000-0000-00000000aaaa", port: 8883 });
  const c = compareAssessments(before0, after);
  check(c.findings?.added.length === 1 && c.findings.added[0].after.port === 8883, "new finding");
  check(c.findings.added[0].risk === null, "no invented risk for new finding");
  check(
    c.findings.remaining.some((r) => r.after.finding_id === "IOT-MQTT-01" && r.after.port === mqtt01.port),
    "original port still remaining",
  );
  check(findingKey({ ...mqtt01, port: null }) !== findingKey({ ...mqtt01, port: 0 }), "null port distinct");
  pass("I new finding; same finding_id on another port not merged; null port distinct");
}
{
  const after = clone(after0);
  after.risk_snapshots = after.risk_snapshots.filter((s) => s.finding_ref !== null);
  const c = compareAssessments(before0, after);
  check(c.risk.after === null && c.risk.delta === null && c.risk.unavailableReason === "missing", "missing risk");
  pass("K missing overall risk -> no delta, no zero");
}
{
  const after = clone(after0);
  for (const s of after.risk_snapshots) s.score_version = "IoT-RISK-v2";
  const c = compareAssessments(before0, after);
  check(c.risk.delta === null && c.risk.unavailableReason === "version_mismatch", "version mismatch");
  check(warnings(c).includes("Cannot compare risk scores: risk score versions differ."), "risk warning");
  check(c.findings?.remaining.every((r) => r.risk.delta === null), "no per-finding delta");
  pass("L different score versions -> no numeric delta");
}
{
  const after = clone(after0);
  const item = after.evidence.find((e) => e.check_type === "MQTT_ANONYMOUS_CONNECT");
  check(item, "MQTT evidence present");
  item.observation = { ...item.observation, reason_code: 5 };
  const row = compareAssessments(before0, after).evidence?.find(
    (r) => r.checkType === "MQTT_ANONYMOUS_CONNECT",
  );
  check(row && row.before.length === 1 && row.after.length === 1, "both sides present");
  check(!sameJson(row.before[0].observation, row.after[0].observation), "observations differ");
  check(
    sameJson(Object.keys(row).sort(), ["after", "before", "checkType", "key", "port", "target"]),
    "no verdict field",
  );
  pass("M differing observations shown side by side");
}

console.log(`runs fetched: ${details.length} (${complete.length} COMPLETE)`);
for (const line of results) console.log(line);
console.log(`${results.length} checks passed`);
