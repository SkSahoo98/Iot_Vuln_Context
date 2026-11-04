/**
 * Render checks for the assessment finding cards (Phase 3E traceability and
 * Phase 3G-A remediation guidance). The real .tsx component is loaded through
 * Vite's SSR loader and rendered with react-dom/server; no dependency is added.
 *
 * Run from frontend/:  node src/components/assessments/AssessmentFindingList.test.ts
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
} from "../../api/types.ts";

declare const process: { cwd(): string; env: Record<string, string | undefined> };

type ViteServer = {
  ssrLoadModule(url: string): Promise<Record<string, unknown>>;
  close(): Promise<void>;
};
type FindingListModule = typeof import("./AssessmentFindingList.tsx");

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${message}`);
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const results: string[] = [];
const pass = (name: string, note = "") =>
  results.push(`PASS ${name}${note ? ` — ${note}` : ""}`);

// Real backend data is read first (GET only), before fetch is instrumented.
const API = process.env.ASSESSMENT_API || "http://127.0.0.1:8000/api/v1/assessments";
let realDetail: AssessmentDetail | null = null;
try {
  const list = (await (await fetch(API)).json()) as AssessmentSummary[];
  const candidate = list.find((item) => item.status === "COMPLETE" && item.finding_count > 0);
  if (candidate) {
    realDetail = (await (await fetch(`${API}/${candidate.id}`)).json()) as AssessmentDetail;
  }
} catch {
  realDetail = null;
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

let fetchCalls = 0;
const realFetch = globalThis.fetch;
globalThis.fetch = ((...args: Parameters<typeof fetch>) => {
  fetchCalls += 1;
  return realFetch(...args);
}) as typeof fetch;

try {
  const { AssessmentFindingList } = (await server.ssrLoadModule(
    "/src/components/assessments/AssessmentFindingList.tsx",
  )) as unknown as FindingListModule;

  const render = (
    findings: AssessmentFinding[],
    evidence: AssessmentEvidence[],
    snapshots: RiskSnapshot[],
  ) => renderToStaticMarkup(createElement(AssessmentFindingList, { findings, evidence, snapshots }));

  // Test-only fixtures in the API response shape; never persisted.
  const evidence: AssessmentEvidence = {
    id: "e0000000-0000-4000-8000-000000000001",
    assessment_id: "a0000000-0000-4000-8000-000000000001",
    target: "192.0.2.10",
    port: 1883,
    check_type: "MQTT_ANONYMOUS_CONNECT",
    result: "ACCEPTED",
    evidence_source: "MQTT_PROBE",
    observation: { reason_code: 0 },
    observed_at: "2026-10-13T10:00:00Z",
  };
  const base: AssessmentFinding = {
    id: "f0000000-0000-4000-8000-000000000001",
    assessment_id: evidence.assessment_id,
    finding_id: "CHECK-A",
    finding_type: "TYPE_A",
    category: "IOT_PROTOCOL",
    title: "Fixture finding",
    severity: "HIGH",
    confidence: 0.99,
    description: "Fixture description.",
    target: evidence.target,
    port: evidence.port,
    evidence_reference: evidence.id,
    remediation: null,
    status: "OPEN",
    created_at: "2026-10-13T10:00:01Z",
  };
  const snapshot: RiskSnapshot = {
    id: "r0000000-0000-4000-8000-000000000001",
    assessment_id: evidence.assessment_id,
    finding_ref: base.id,
    score: 70.5,
    risk_level: "HIGH",
    score_version: "IoT-RISK-v1",
    base_severity: "HIGH",
    context_score: 0.5,
    factor_contributions: {},
    context_inputs: {},
    created_at: "2026-10-13T10:00:02Z",
  };

  // 1. Remediation shown verbatim, including line breaks and repeated spaces.
  {
    const text = "Set allow_anonymous false.\n2. Use a password_file  &  topic ACLs <per client>.";
    const html = render([{ ...base, remediation: text }], [evidence], [snapshot]);
    check(html.includes("Recommended Remediation"), "remediation heading");
    const pattern = new RegExp(
      `<p class="[^"]*whitespace-pre-wrap[^"]*">${escapeRegExp(escapeHtml(text))}</p>`,
    );
    check(pattern.test(html), "remediation text rendered verbatim in a pre-wrap paragraph");
    check(!html.includes("No remediation recorded."), "no empty-state when text exists");
    pass("1 remediation displayed verbatim (line breaks and spacing preserved)");
  }

  // 2. Null, empty and whitespace-only remediation.
  for (const [label, value] of [
    ["null", null],
    ["empty", ""],
    ["whitespace", "   \n "],
  ] as const) {
    const html = render([{ ...base, remediation: value }], [evidence], [snapshot]);
    check(html.includes("No remediation recorded."), `${label}: empty-state text`);
    check(!html.includes("Local checklist"), `${label}: no checklist without guidance`);
  }
  pass("2 null/empty/whitespace remediation -> \"No remediation recorded.\"");

  // Local checklist: unchecked, labelled, makes no completion claim.
  {
    const html = render([{ ...base, remediation: "Do X." }], [evidence], [snapshot]);
    check(html.includes("Local checklist — not recorded or verified"), "checklist label");
    check(/<input[^>]*type="checkbox"(?![^>]*checked)[^>]*>/.test(html), "checkbox unchecked");
    check(!/remediated|completed|resolved|fixed/i.test(html), "no completion claim");
    pass("local checklist labelled, unchecked, no completion claim");
  }

  // 3. Evidence linkage (resolved / unresolved / absent reference).
  {
    const linked = render([{ ...base, remediation: "Do X." }], [evidence], [snapshot]);
    check(linked.includes("Evidence supporting this finding"), "trace heading");
    check(linked.includes(evidence.check_type), "linked evidence check type");
    check(linked.includes("Locate in evidence list"), "locate button");
    const missing = render([{ ...base }], [], [snapshot]);
    check(missing.includes("Referenced evidence could not be resolved."), "unresolved reference");
    const none = render([{ ...base, evidence_reference: null }], [evidence], [snapshot]);
    check(none.includes("Evidence reference not available."), "no reference");
    pass("3 finding -> evidence linkage unchanged");
  }

  // 4. Risk impact via finding_ref.
  {
    const withRisk = render([{ ...base }], [evidence], [snapshot]);
    check(withRisk.includes("70.5"), "risk score shown");
    check(withRisk.includes("IoT-RISK-v1"), "score version shown");
    const withoutRisk = render([{ ...base }], [evidence], [{ ...snapshot, finding_ref: "other" }]);
    check(withoutRisk.includes("Risk impact not available for this finding."), "no snapshot");
    pass("4 risk impact unchanged");
  }

  // 5. HIGH/CRITICAL evidence open by default; lower severities collapsed.
  {
    for (const severity of ["HIGH", "CRITICAL"] as const) {
      const html = render([{ ...base, severity }], [evidence], [snapshot]);
      check(html.includes('aria-expanded="true"') && html.includes("Hide evidence"), `${severity} open`);
    }
    for (const severity of ["MEDIUM", "LOW", "INFO"] as const) {
      const html = render([{ ...base, severity }], [evidence], [snapshot]);
      check(html.includes('aria-expanded="false"') && html.includes("View evidence"), `${severity} collapsed`);
    }
    pass("5 HIGH/CRITICAL evidence open by default; others collapsed");
  }

  // 6 + 7. Same props contract; rendering makes no backend request.
  check(fetchCalls === 0, `rendering issued ${fetchCalls} fetch call(s)`);
  pass("6/7 unchanged props contract; no backend requests during render");

  // Real backend data: every remediation is shown verbatim.
  if (realDetail) {
    const html = render(realDetail.findings, realDetail.evidence, realDetail.risk_snapshots);
    for (const finding of realDetail.findings) {
      check(finding.remediation, `real finding ${finding.finding_id} has remediation`);
      check(html.includes(escapeHtml(finding.remediation)), `real remediation for ${finding.finding_id}`);
    }
    check(fetchCalls === 0, "no backend requests while rendering real data");
    pass(
      "real data: remediation verbatim",
      `${realDetail.findings.length} findings from ${realDetail.id.slice(0, 8)}`,
    );
  } else {
    results.push("SKIP real-data check — backend not reachable or no COMPLETE assessment");
  }
} finally {
  globalThis.fetch = realFetch;
  await server.close();
}

for (const line of results) console.log(line);
console.log(`${results.filter((line) => line.startsWith("PASS")).length} checks passed`);
