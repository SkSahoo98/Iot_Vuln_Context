/**
 * UX-3D: evidence/risk traceability, AI provenance, before/after evaluation and
 * the evaluation summary. Real .tsx components are rendered through Vite's SSR
 * loader. Fixtures are test-only API-shaped objects and are never persisted.
 *
 * Run from frontend/:  node src/lib/traceability.test.ts
 * Optional real-data check (GET only): ASSESSMENT_API=http://host:port/api/v1/assessments
 */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type {
  AssessmentDetail,
  AssessmentEvidence,
  AssessmentFinding,
  AssessmentSummary,
  RiskSnapshot,
  RiskTrace,
} from "../api/types.ts";

declare const process: { cwd(): string; env: Record<string, string | undefined> };

type ViteServer = {
  ssrLoadModule(url: string): Promise<Record<string, unknown>>;
  close(): Promise<void>;
};
type NodeFs = { readFileSync(path: string, encoding: "utf8"): string };
type TraceModule = typeof import("./traceability.ts");
type ComparisonModule = typeof import("./assessmentComparison.ts");
type ConversationModule = typeof import("./assistant/conversation.ts");
type TraceViewModule = typeof import("../components/assessments/AssessmentTrace.tsx");
type SummaryModule = typeof import("../components/assessments/EvaluationSummary.tsx");
type VerificationModule = typeof import("../components/assessments/VerificationEvaluation.tsx");
type AssistantPageModule = typeof import("../components/assistant/AssistantPage.tsx");

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${message}`);
}

const results: string[] = [];
const pass = (name: string, note = "") => results.push(`PASS ${name}${note ? ` — ${note}` : ""}`);

const fsModuleName = "node:fs";
const fs = (await import(fsModuleName)) as NodeFs;
const source = (path: string) => fs.readFileSync(`${process.cwd()}/${path}`, "utf8");

// Real backend data first (GET only), before fetch is instrumented.
const API = process.env.ASSESSMENT_API || "http://127.0.0.1:8000/api/v1/assessments";
let realList: AssessmentSummary[] | null = null;
let realLatest: AssessmentDetail | null = null;
let realBaseline: AssessmentDetail | null = null;
try {
  realList = (await (await fetch(API)).json()) as AssessmentSummary[];
  const latest = realList
    .filter((item) => item.status === "COMPLETE" && item.target !== "AUTHORIZED_IOT")
    .sort((a, b) => b.started_at.localeCompare(a.started_at))[0];
  if (latest) realLatest = (await (await fetch(`${API}/${latest.id}`)).json()) as AssessmentDetail;
} catch {
  realList = null;
}

const viteModuleName = "vite";
const vite = (await import(viteModuleName)) as {
  createServer(config: Record<string, unknown>): Promise<ViteServer>;
};
const server = await vite.createServer({
  root: process.cwd(),
  configFile: false,
  logLevel: "error",
  appType: "custom",
  server: { middlewareMode: true, hmr: false },
  esbuild: { jsx: "automatic" },
  optimizeDeps: { noDiscovery: true, include: [] },
});

const requests: string[] = [];
const realFetch = globalThis.fetch;

// ------------------------------------------------------------------ fixtures
const RUN = "a0000000-0000-4000-8000-0000000000a1";
const TARGET = "192.0.2.10";
const T0 = "2026-10-14T09:00:00Z";

const CONTRIBUTIONS = {
  network_exposure: { weight: 0.2, normalized_value: 0.6, contribution_to_100: 6 },
  firmware_security: { weight: 0.1, normalized_value: 0.5, contribution_to_100: 2.5 },
  protocol_security: { weight: 0.2, normalized_value: 1, contribution_to_100: 10 },
  device_criticality: { weight: 0.3, normalized_value: 0.3, contribution_to_100: 4.5 },
  authentication_security: { weight: 0.2, normalized_value: 1, contribution_to_100: 10 },
};
const INPUTS = {
  device_criticality: { value: 0.3, source: "CONFIGURATION", limitation: "Configured fixture input." },
  network_exposure: { value: 0.6, source: "NMAP", derivation: "min(open_ports=3 / threshold=5, 1.0)" },
  authentication_security: { value: 1, source: "MQTT_PROBE" },
  protocol_security: { value: 1, source: "ACTIVE_PROBE" },
  firmware_security: { value: 0.5, source: "CONFIGURATION" },
  model_limitations: ["The current model can double-count a finding in context."],
};

let seq = 0;
const uid = (prefix: string) => `${prefix}0000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`;

function ev(check_type: string, result: string, port: number | null, evidence_source: string, run = RUN): AssessmentEvidence {
  return { id: uid("e"), assessment_id: run, target: TARGET, port, check_type, result, evidence_source, observation: {}, observed_at: T0 };
}

function fd(finding_id: string, finding_type: string, severity: AssessmentFinding["severity"], port: number | null, ref: AssessmentEvidence | null, title: string, run = RUN): AssessmentFinding {
  return {
    id: uid("f"), assessment_id: run, finding_id, finding_type, category: "X", title, severity,
    confidence: 0.9, description: null, target: TARGET, port, evidence_reference: ref?.id ?? null,
    remediation: "Recorded remediation.", status: "OPEN", created_at: T0,
  };
}

function snap(ref: AssessmentFinding | null, score: number, risk_level: RiskSnapshot["risk_level"], run = RUN, created_at = T0): RiskSnapshot {
  return {
    id: uid("s"), assessment_id: run, finding_ref: ref?.id ?? null, score, risk_level,
    score_version: "IoT-RISK-v1", base_severity: ref?.severity ?? "HIGH", context_score: 0.66,
    factor_contributions: CONTRIBUTIONS, context_inputs: INPUTS, created_at,
  };
}

const METADATA = {
  ports: [139, 445, 1883],
  nmap_arguments: "-sT",
  open_service_threshold: 5,
  admin_service_ports: [139, 445],
  mqtt_broker_port: 1883,
  mqtt_tls_port: 8883,
  check_catalog_version: "fixture-1",
};

function coverage(entries: [string, number | null][]) {
  return entries.map(([check_id, port]) => ({ check_id, port, status: "EVALUATED" }));
}

function buildRun(options: { id?: string; started?: string; anonymous?: boolean; status?: AssessmentDetail["status"]; withRisk?: boolean } = {}) {
  const id = options.id ?? RUN;
  const anonEv = ev("MQTT_ANONYMOUS_CONNECT", "ACCEPTED", 1883, "MQTT_PROBE", id);
  const plainEv = ev("MQTT_TRANSPORT_COMPARISON", "PLAINTEXT_NO_TLS", 1883, "MQTT_PROBE", id);
  const portEv = ev("NMAP_PORT", "OPEN", 445, "NMAP", id);
  const anon = fd("IOT-MQTT-01", "MQTT_ANONYMOUS_ACCESS", "HIGH", 1883, anonEv, "MQTT broker accepted an anonymous connection", id);
  const plain = fd("IOT-MQTT-02", "MQTT_WITHOUT_TLS", "MEDIUM", 1883, plainEv, "MQTT accepted over plaintext", id);
  const net = fd("NET-01", "OPEN_TCP_SERVICE", "INFO", 445, portEv, "Open TCP service observed", id);
  const findings = options.anonymous === false ? [plain, net] : [anon, plain, net];
  const snapshots = options.withRisk === false ? [] : options.anonymous === false
    ? [snap(plain, 48.0, "MEDIUM", id), snap(null, 48.0, "MEDIUM", id)]
    : [snap(anon, 70.5, "HIGH", id), snap(plain, 58.0, "MEDIUM", id), snap(null, 70.5, "HIGH", id)];
  const trace: RiskTrace | null = snapshots.length ? {
    score_version: "IoT-RISK-v1",
    overall_rule: "HIGHEST_FINDING_RISK",
    overall_finding_refs: [snapshots[0].finding_ref!],
    factors: [
      { factor: "authentication_security", rule: "FINDING_TYPE", finding_refs: options.anonymous === false ? [] : [anon.id], evidence_refs: options.anonymous === false ? [] : [anonEv.id] },
      { factor: "protocol_security", rule: "FINDING_TYPE", finding_refs: [plain.id], evidence_refs: [plainEv.id] },
      { factor: "network_exposure", rule: "OPEN_PORT_EVIDENCE", finding_refs: [net.id], evidence_refs: [portEv.id] },
      { factor: "device_criticality", rule: "CONFIGURATION", finding_refs: [], evidence_refs: [] },
      { factor: "firmware_security", rule: "CONFIGURATION", finding_refs: [], evidence_refs: [] },
    ],
  } : null;
  const status = options.status ?? "COMPLETE";
  const detail: AssessmentDetail = {
    id, target: TARGET, assessment_type: "MULTI_LAYER", status,
    started_at: options.started ?? T0, completed_at: status === "RUNNING" ? null : options.started ?? T0,
    error_summary: null,
    metadata: {
      ...METADATA,
      checks_evaluated: coverage([["IOT-MQTT-01", 1883], ["IOT-MQTT-02", 1883], ["NET-01", null], ["IOT-TLS-01", 8883]]),
    },
    created_at: options.started ?? T0,
    evidence_count: 3, finding_count: findings.length,
    highest_risk: snapshots.length ? snapshots[snapshots.length - 1].score : null,
    highest_risk_level: snapshots.length ? snapshots[snapshots.length - 1].risk_level : null,
    evidence: [anonEv, plainEv, portEv], findings, risk_snapshots: snapshots, risk_trace: trace,
  };
  return { detail, anon, plain, net, anonEv, plainEv, portEv };
}

const summaryOf = (detail: AssessmentDetail): AssessmentSummary => {
  const { evidence: _e, findings: _f, risk_snapshots: _r, risk_trace: _t, ...rest } = detail;
  return rest;
};

const NEW_FILES = [
  "src/lib/traceability.ts",
  "src/components/assessments/AssessmentTrace.tsx",
  "src/components/assessments/EvaluationSummary.tsx",
  "src/components/assessments/VerificationEvaluation.tsx",
];

try {
  globalThis.fetch = ((input: Parameters<typeof fetch>[0]) => {
    requests.push(String(input));
    return Promise.reject(new Error("offline in tests"));
  }) as typeof fetch;

  const trace = (await server.ssrLoadModule("/src/lib/traceability.ts")) as unknown as TraceModule;
  const comparison = (await server.ssrLoadModule("/src/lib/assessmentComparison.ts")) as unknown as ComparisonModule;
  const conversation = (await server.ssrLoadModule("/src/lib/assistant/conversation.ts")) as unknown as ConversationModule;
  const { AssessmentTrace } = (await server.ssrLoadModule("/src/components/assessments/AssessmentTrace.tsx")) as unknown as TraceViewModule;
  const { EvaluationSummary } = (await server.ssrLoadModule("/src/components/assessments/EvaluationSummary.tsx")) as unknown as SummaryModule;
  const verificationModule = (await server.ssrLoadModule("/src/components/assessments/VerificationEvaluation.tsx")) as unknown as VerificationModule;
  const { VerificationEvaluation, useVerification } = verificationModule;
  const { ExplanationProvenance, AI_DOES_NOT } = (await server.ssrLoadModule("/src/components/assistant/AssistantPage.tsx")) as unknown as AssistantPageModule;

  const renderTrace = (detail: AssessmentDetail) => renderToStaticMarkup(createElement(AssessmentTrace, { detail }));
  const renderVerification = (detail: AssessmentDetail, history: AssessmentSummary[] | null) =>
    renderToStaticMarkup(createElement(function Harness() {
      const v = useVerification(detail, history);
      return createElement(VerificationEvaluation, { detail, state: v.state, onRetry() {}, onRunVerification() {} });
    }));
  const renderReady = (before: AssessmentDetail, after: AssessmentDetail) =>
    renderToStaticMarkup(createElement(VerificationEvaluation, {
      detail: after,
      state: { kind: "ready", baseline: summaryOf(before), view: trace.verificationView(comparison.compareAssessments(before, after)) },
      onRetry() {},
      onRunVerification() {},
      onOpenComparison() {},
    }));
  const renderSummary = (detail: AssessmentDetail) =>
    renderToStaticMarkup(createElement(EvaluationSummary, { detail, verification: { kind: "no_baseline" } }));

  // 1. Traceability uses recorded evidence.
  {
    const run = buildRun();
    const built = trace.buildAssessmentTrace(run.detail);
    const anon = built.findings.find((item) => item.finding.id === run.anon.id)!;
    check(anon.evidence.kind === "linked" && anon.evidence.record === run.anonEv, "IOT-MQTT-01 uses its recorded evidence object");
    const html = renderTrace(run.detail);
    check(html.includes(`data-trace-evidence="${run.anonEv.id}"`) && html.includes("MQTT_ANONYMOUS_CONNECT") && html.includes("MQTT_PROBE"), "recorded evidence rendered");
    check(built.findings[0].finding.id === run.anon.id, "important finding first");
    pass("B1 traceability uses recorded evidence (finding.evidence_reference -> evidence.id)");
  }

  // 2. Frontend does not synthesize evidence.
  {
    const run = buildRun();
    const orphan = { ...run.anon, id: uid("f"), evidence_reference: null };
    const dangling = { ...run.plain, id: uid("f"), evidence_reference: uid("e") };
    const detail = { ...run.detail, findings: [orphan, dangling] };
    const built = trace.buildAssessmentTrace(detail);
    check(built.findings.every((item) => item.evidence.kind === "not_available"), "no evidence without a resolvable reference");
    const html = renderTrace(detail);
    check((html.match(/Evidence not available for this finding\./g) ?? []).length === 2, "exact unavailable text");
    check(!html.includes("MQTT_ANONYMOUS_CONNECT") && !html.includes("ACCEPTED"), "same-port evidence is not borrowed by title or port");
    for (const file of NEW_FILES) {
      check(!/check_type\s*:|evidence_source\s*:|observed_at\s*:|finding_id\s*:|risk_level\s*:/.test(source(file)), `${file} constructs records`);
    }
    pass("B2 frontend does not synthesize evidence; exact 'Evidence not available' text");
  }

  // 3. Frontend does not calculate risk.
  {
    const run = buildRun();
    const odd = { weight: 0.2, normalized_value: 1, contribution_to_100: 7.77 };
    const overall = { ...run.detail.risk_snapshots[2], score: 12.345, factor_contributions: { ...CONTRIBUTIONS, authentication_security: odd } };
    const own = { ...run.detail.risk_snapshots[0], score: 99.9, factor_contributions: { ...CONTRIBUTIONS, authentication_security: odd } };
    const detail = { ...run.detail, risk_snapshots: [own, run.detail.risk_snapshots[1], overall] };
    const html = renderTrace(detail);
    check(html.includes("+7.77 points") && html.includes("12.345") && html.includes("99.9"), "recorded values shown verbatim even when inconsistent");
    check(!html.includes("+4 points") && !html.includes("+20 points"), "no recomputed contribution");
    for (const file of NEW_FILES) {
      check(
        !/\.score\s*[-+*/]|[-+*/]\s*[\w.]*\.score\b|weight\s*\*|\*\s*[\w.]*weight|normalized_?[vV]alue\s*\*|\*\s*[\w.]*normalized|contribution_to_100\s*[-+*/]|Math\.|toFixed|risk_rules|CONTEXT_WEIGHT/.test(source(file)),
        `${file} computes risk`,
      );
    }
    pass("B3 frontend does not calculate risk (values verbatim; no arithmetic on scores/weights)");
  }

  // 4. Frontend does not calculate comparison results.
  {
    const before = buildRun({ id: uid("a"), started: "2026-10-14T08:00:00Z" }).detail;
    const after = buildRun({ id: uid("a"), started: "2026-10-14T09:00:00Z", anonymous: false }).detail;
    const result = comparison.compareAssessments(before, after);
    const view = trace.verificationView(result);
    check(view.kind === "compared", "comparable fixtures");
    check(
      view.resolved.length === result.findings!.resolved.length &&
        view.added.length === result.findings!.added.length &&
        view.unchanged.length === result.findings!.remaining.length &&
        view.notConfirmed.length === result.findings!.unconfirmed.length &&
        view.riskDelta === result.risk.delta,
      "view mirrors compareAssessments output",
    );
    const fnText = source("src/lib/traceability.ts").split("export function verificationView")[1];
    check(!/lookupCoverage|readCoverage|findingKey|COVERAGE_|compareRisk|\.score/.test(fnText), "verificationView only maps engine output");
    check(!/lookupCoverage|readCoverage|findingKey|COVERAGE_|compareRisk|checkComparability/.test(source("src/components/assessments/VerificationEvaluation.tsx")), "component has no comparison logic");
    pass("B4 frontend renders compareAssessments output only", `resolved ${view.resolved.length}, delta ${view.riskDelta}`);
  }

  // 5-8. AI cannot alter risk, findings, evidence or remediation: provenance is labels only.
  {
    const reply = conversation.explanationReply({
      status: "COMPLETE",
      answer: "Your current risk is rated HIGH.",
      source: "AI",
      basis: ["FINDINGS", "EVIDENCE", "SCAN", "RISK_RESULT"] as never,
      score: 12, findings: [{ title: "Invented" }], remediation: "Invented fix",
    } as never);
    check(JSON.stringify(reply.basis) === '["RISK_RESULT","FINDINGS"]', `unknown basis dropped (${JSON.stringify(reply.basis)})`);
    check(!("score" in reply) && !("findings" in reply) && !("remediation" in reply), "no data fields carried");
    const html = renderToStaticMarkup(createElement(ExplanationProvenance, { source: "AI", basis: reply.basis }));
    check(html.includes("Based on your latest security check.") && html.includes("Current risk result") && html.includes("Recorded findings"), "labels for recorded sections");
    check(!html.includes("Remediation from the assessment engine") && !html.includes("EVIDENCE") && !html.includes("Invented"), "nothing beyond the backend basis");
    for (const item of AI_DOES_NOT) check(html.includes(item), `AI does not: ${item}`);
    const fallback = renderToStaticMarkup(createElement(ExplanationProvenance, { source: "DETERMINISTIC_FALLBACK", basis: ["RISK_RESULT"] }));
    check(fallback.includes("Rule-based explanation") && !fallback.includes("AI explanation:"), "fallback labelled rule-based");
    const ai = renderToStaticMarkup(createElement(ExplanationProvenance, { source: "AI", basis: [] }));
    check(ai.includes("AI explanation:") && ai.includes("Recorded results of your latest completed security check."), "AI label; generic basis when none recorded");
    pass("B5-B8 AI cannot alter risk/findings/evidence/remediation: provenance lists backend basis labels only");
  }

  // 9-10. AI cannot execute assessments or call security tools.
  {
    const files = [...NEW_FILES, "src/components/assistant/AssistantPage.tsx", "src/lib/assistant/conversation.ts"];
    for (const file of files) {
      const text = source(file);
      check(!/AI (scanned|detected|verified|found|calculated|ran)/i.test(text), `${file} claims AI performed a check`);
    }
    for (const file of NEW_FILES) {
      check(!/createAssessment|apiPost|setInterval|setTimeout|\.confirm\(/.test(source(file)), `${file} can start work by itself`);
    }
    const panel = source("src/components/assessments/ReassessmentPanel.tsx");
    check(/if \(requestToken > 0\) flow\.request\(\);/.test(panel) && !/requestToken[^\n]*confirm/.test(panel), "verification button only opens the confirmation step");
    pass("B9-B10 no assessment or security tool can be started by the AI or by the new views");
  }

  // 11. Browser cannot access Ollama.
  {
    for (const file of NEW_FILES) {
      check(!/ollama|11434|qwen|llama|\/api\/chat|\/api\/generate/i.test(source(file)), `${file} references the model service`);
    }
    pass("B11 no model service reference in UX-3D files");
  }

  // 12. No new autonomous AI capability: only GET reads in new views.
  {
    const imports = NEW_FILES.flatMap((file) => [...source(file).matchAll(/import \{([^}]*)\} from "\.\.\/(?:\.\.\/)?api\/(\w+)"/g)].map((m) => `${m[2]}:${m[1].trim()}`));
    check(imports.sort().join(",") === "assessments:fetchAssessment,security:fetchExperiments", `API use: ${imports.join(", ")}`);
    check(!/\/ai\/|\/chat\b|\/trace\b/.test(source("src/api/assistant.ts") + source("src/api/assessments.ts")), "no new AI endpoints");
    pass("B12 no new autonomous capability (new views use GET /assessments/{id} and GET /experiments only)");
  }

  // Data integrity: assessment status.
  {
    for (const status of ["COMPLETE", "INCOMPLETE", "FAILED", "RUNNING"] as const) {
      const detail = buildRun({ status, withRisk: status === "COMPLETE" }).detail;
      const verification = renderVerification(detail, [summaryOf(detail)]);
      const summary = renderSummary(detail);
      check(summary.includes(status), `${status} shown in summary`);
      if (status === "COMPLETE") {
        check(verification.includes("No verification comparison is available yet.") && verification.includes("Run verification check"), "COMPLETE without baseline offers explicit run");
      } else {
        check(verification.includes('data-verification="not_complete"') && !verification.includes("Run verification check"), `${status} not comparable, no run button`);
        check(summary.includes("No risk result was recorded for this check."), `${status} without risk`);
      }
    }
    pass("D1 statuses COMPLETE/INCOMPLETE/FAILED/RUNNING");
  }

  // Data integrity: findings, evidence, risk snapshot.
  {
    const empty = { ...buildRun().detail, findings: [], evidence: [], risk_snapshots: [], risk_trace: null };
    check(renderTrace(empty).includes("No findings recorded"), "no findings");
    const s = trace.buildEvaluationSummary(empty);
    check(s.findings.important === 0 && s.findingCount === 0 && s.risk === null, "empty counts");
    const run = buildRun();
    const s2 = trace.buildEvaluationSummary(run.detail);
    check(s2.findings.important === 2 && s2.findings.informational === 1 && s2.coverage.recorded && s2.coverage.evaluated === 4, "important findings and coverage counted from records");
    const noTrace = renderTrace({ ...run.detail, risk_trace: null });
    check(noTrace.includes("Risk factor links are not recorded for this check."), "trace unavailable state");
    const noRisk = renderTrace({ ...run.detail, risk_snapshots: [], risk_trace: null });
    check(noRisk.includes("No overall risk was recorded for this check.") && noRisk.includes("No risk snapshot is recorded for this finding."), "snapshot unavailable");
    const withRisk = renderTrace(run.detail);
    check(withRisk.includes("+10 points") && withRisk.includes("70.5") && withRisk.includes("Observed evidence") && withRisk.includes("This finding&#x27;s risk is the overall risk"), "snapshot available: contribution, basis, overall");
    pass("D2 findings none/important; evidence linked/missing; risk snapshot available/unavailable; trace unavailable");
  }

  // Data integrity: comparison available / unavailable / incompatible.
  {
    const before = buildRun({ id: uid("a"), started: "2026-10-14T08:00:00Z" }).detail;
    const after = buildRun({ id: uid("a"), started: "2026-10-14T09:00:00Z", anonymous: false }).detail;
    const ready = renderReady(before, after);
    check(ready.includes('data-verification="compared"') && ready.includes("Baseline") && ready.includes("Verification") && ready.includes("Change"), "compared layout");
    check(ready.includes('data-outcome="Resolved"') && ready.includes("-22.5 points"), "resolved finding and engine delta shown");
    const none = renderVerification(after, [summaryOf(after)]);
    check(none.includes("No verification comparison is available yet.") && none.includes("Run a new security check after remediation to compare the results."), "no comparison texts");
    const other = { ...before, metadata: { ...before.metadata, check_catalog_version: "fixture-2" } };
    const incompatible = renderReady(other, after);
    check(incompatible.includes('data-verification="none"') && incompatible.includes("check catalog versions differ"), "incompatible shows reason, no outcomes");
    check(!incompatible.includes("data-outcome"), "no outcomes for incompatible runs");
    pass("D3 comparison available/unavailable/incompatible");
  }

  // Data integrity: AI source labels.
  {
    for (const source of ["AI", "DETERMINISTIC_FALLBACK", "DETERMINISTIC"] as const) {
      const html = renderToStaticMarkup(createElement(ExplanationProvenance, { source, basis: ["FINDINGS"] }));
      check(html.includes(`data-provenance="${source}"`), `${source} provenance`);
      check(!/model|prompt|token|chain|reasoning|qwen|ollama/i.test(html), `${source} exposes internals`);
    }
    pass("D4 AI source AI / deterministic fallback / deterministic");
  }

  // No fake metrics.
  {
    const html = renderSummary(buildRun().detail);
    check(html.includes("Ground-truth evaluation dataset is not configured."), "ground truth text");
    check(!/(precision|recall|accuracy|F1)\s*[:=]?\s*\d|\d+(\.\d+)?\s*%|true positive|false positive|true negative|false negative/i.test(html), "no fabricated metric values");
    pass("D5 no fake precision/recall/F1/accuracy; ground truth not configured");
  }

  check(requests.every((url) => url.endsWith("/api/v1/experiments") || url.includes("/api/v1/assessments/")), `unexpected requests: ${requests.join(", ")}`);
  check(!requests.some((url) => /11434|ollama/i.test(url)), "no model requests");

  // Real data (GET only): latest COMPLETE assessment.
  if (realLatest && realList) {
    globalThis.fetch = realFetch;
    const built = trace.buildAssessmentTrace(realLatest);
    const ids = new Set(realLatest.evidence.map((e) => e.id));
    for (const item of built.findings) {
      if (item.evidence.kind === "linked") check(ids.has(item.evidence.record.id), "real evidence is recorded");
      else check(!item.finding.evidence_reference || !ids.has(item.finding.evidence_reference), "real missing evidence is really missing");
    }
    const anon = built.findings.find((item) => item.finding.finding_id === "IOT-MQTT-01");
    let note = `${realLatest.id.slice(0, 8)}: ${built.findings.length} findings`;
    if (anon && realLatest.risk_trace) {
      check(anon.evidence.kind === "linked" && anon.evidence.record.evidence_source === "MQTT_PROBE", "IOT-MQTT-01 evidence MQTT_PROBE");
      const auth = anon.linkedFactors.find((f) => f.factor === "authentication_security");
      check(auth && auth.contribution !== null && auth.provenance?.label === "Observed evidence", "IOT-MQTT-01 -> authentication_security, observed");
      note += `; IOT-MQTT-01 -> auth +${auth!.contribution}, overall ${built.overall?.score} ${built.overall?.risk_level}, sets overall ${anon.setsOverall}`;
    }
    const baselineSummary = trace.selectBaseline(realList, realLatest);
    if (baselineSummary) {
      realBaseline = (await (await realFetch(`${API}/${baselineSummary.id}`)).json()) as AssessmentDetail;
      const view = trace.verificationView(comparison.compareAssessments(realBaseline, realLatest));
      note += view.kind === "compared"
        ? `; vs ${baselineSummary.id.slice(0, 8)}: delta ${view.riskDelta}, resolved ${view.resolved.length}, new ${view.added.length}, unchanged ${view.unchanged.length}`
        : `; vs ${baselineSummary.id.slice(0, 8)}: not comparable`;
    }
    pass("real data: trace joins recorded IDs only", note);
  } else {
    results.push("SKIP real-data check — backend not reachable or no COMPLETE assessment");
  }
} finally {
  globalThis.fetch = realFetch;
  await server.close();
}

for (const line of results) console.log(line);
console.log(`${results.filter((line) => line.startsWith("PASS")).length} checks passed`);
