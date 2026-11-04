/**
 * Checks for the assessment-driven security home (Phase UX-1). All API calls
 * go through the real api/assessments.ts with globalThis.fetch replaced by a
 * stub that never reaches the network. Components are loaded through Vite's
 * SSR loader and rendered with react-dom/server; no dependency is added.
 *
 * Run from frontend/:  node src/components/overview/SecurityHome.test.ts
 */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type {
  AssessmentDetail,
  AssessmentFinding,
  AssessmentStatus,
  AssessmentSummary,
  RiskSnapshot,
} from "../../api/types.ts";

declare const process: { cwd(): string };

type ViteServer = {
  ssrLoadModule(url: string): Promise<Record<string, unknown>>;
  close(): Promise<void>;
};
type HomeLib = typeof import("../../lib/securityHome.ts");
type ViewModule = typeof import("./SecurityHomeView.tsx");
type PageModule = typeof import("./OverviewPage.tsx");
type ApiModule = typeof import("../../api/assessments.ts");

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${message}`);
}

const results: string[] = [];
const pass = (name: string, note = "") =>
  results.push(`PASS ${name}${note ? ` — ${note}` : ""}`);

// ---- fetch stub -----------------------------------------------------------
const LEGACY_SENTINEL = "LEGACY_FINDING_SENTINEL";
let routes: Record<string, () => Response> = {};
const requested: string[] = [];
const json = (status: number, payload: unknown) =>
  new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL) => {
  const path = new URL(String(input)).pathname;
  requested.push(path);
  if (path === "/api/v1/findings") {
    return json(200, [{ finding_type: "X", title: LEGACY_SENTINEL, severity: "HIGH" }]);
  }
  if (path === "/api/v1/risk") return json(200, { highest_score: 99.99, items: [] });
  const route = routes[path];
  if (!route) throw new Error(`unexpected request ${path}`);
  return route();
}) as typeof fetch;

// ---- fixtures (test-only, API response shape, never persisted) -----------
const T1 = "192.0.2.44";
const T2 = "198.51.100.7";
let seq = 0;
const uuid = (prefix: string) =>
  `${prefix}0000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`;

function summary(
  status: AssessmentStatus,
  startedAt: string,
  extra: Partial<AssessmentSummary> = {},
): AssessmentSummary {
  return {
    id: uuid("a"),
    target: T1,
    assessment_type: "MULTI_LAYER",
    status,
    started_at: startedAt,
    completed_at: status === "RUNNING" ? null : startedAt.replace(":00Z", ":40Z"),
    error_summary: null,
    metadata: {} as AssessmentSummary["metadata"],
    created_at: startedAt,
    evidence_count: 6,
    finding_count: 5,
    highest_risk: null,
    highest_risk_level: null,
    ...extra,
  };
}

function finding(
  assessmentId: string,
  findingId: string,
  severity: AssessmentFinding["severity"],
  title: string,
  remediation: string | null,
  port: number | null,
): AssessmentFinding {
  return {
    id: uuid("f"),
    assessment_id: assessmentId,
    finding_id: findingId,
    finding_type: `TYPE_${findingId}`,
    category: "IOT_PROTOCOL",
    title,
    severity,
    confidence: 0.97,
    description: `Observed detail on ${T1}:${port} for ${findingId}.`,
    target: T1,
    port,
    evidence_reference: uuid("e"),
    remediation,
    status: "OPEN",
    created_at: "2026-10-13T10:00:05Z",
  };
}

function snapshot(
  assessmentId: string,
  findingRef: string | null,
  score: number,
  level: RiskSnapshot["risk_level"],
): RiskSnapshot {
  return {
    id: uuid("r"),
    assessment_id: assessmentId,
    finding_ref: findingRef,
    score,
    risk_level: level,
    score_version: "IoT-RISK-v1",
    base_severity: null,
    context_score: 0.5,
    factor_contributions: {},
    context_inputs: {},
    created_at: "2026-10-13T10:00:06Z",
  };
}

const older = summary("COMPLETE", "2026-10-11T08:00:00Z", {
  highest_risk: 12.5,
  highest_risk_level: "LOW",
});
const latest = summary("COMPLETE", "2026-10-13T19:58:00Z", {
  highest_risk: 63.25,
  highest_risk_level: "HIGH",
});
const middle = summary("INCOMPLETE", "2026-10-12T09:00:00Z", {
  highest_risk: 88.8,
  highest_risk_level: "CRITICAL",
});

const REMEDIATION_A = "Fixture remediation A:\n  set allow_anonymous false.";
const anonymous = finding(latest.id, "IOT-MQTT-01", "HIGH", "Backend title A", REMEDIATION_A, 1883);
const plaintextA = finding(latest.id, "IOT-MQTT-02", "MEDIUM", "Backend title B", "Fixture remediation B.", 1883);
const plaintextB = finding(latest.id, "IOT-MQTT-02", "MEDIUM", "Backend title B", "Fixture remediation B.", 8883);
const unknownCheck = finding(latest.id, "ZZ-99", "MEDIUM", "Backend-only fixture title", null, null);
const headers = finding(latest.id, "WEB-02", "LOW", "Backend title C", "Fixture remediation C.", 80);
const infoTitle = "INFO fixture backend title";
const info = finding(latest.id, "NET-01", "INFO", infoTitle, "Fixture remediation INFO.", 22);

const latestDetail: AssessmentDetail = {
  ...latest,
  evidence: [],
  findings: [info, headers, plaintextA, anonymous, unknownCheck, plaintextB],
  risk_snapshots: [
    snapshot(latest.id, null, 63.25, "HIGH"),
    snapshot(latest.id, anonymous.id, 57.93, "HIGH"),
    snapshot(latest.id, plaintextA.id, 41.17, "MEDIUM"),
  ],
};

// ---- loader ---------------------------------------------------------------
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

try {
  const lib = (await server.ssrLoadModule("/src/lib/securityHome.ts")) as unknown as HomeLib;
  const { SecurityHomeView } = (await server.ssrLoadModule(
    "/src/components/overview/SecurityHomeView.tsx",
  )) as unknown as ViewModule;
  const { OverviewPage } = (await server.ssrLoadModule(
    "/src/components/overview/OverviewPage.tsx",
  )) as unknown as PageModule;
  const api = (await server.ssrLoadModule("/src/api/assessments.ts")) as unknown as ApiModule;

  const noop = () => {};
  const actions = { deviceContext: null, onCheckSecurity: noop, onShowDetails: noop };
  const renderPage = (assessments: AssessmentSummary[] | null, error: string | null = null) =>
    renderToStaticMarkup(
      createElement(OverviewPage, {
        assessments,
        assessmentsError: error,
        onRetryAssessments: noop,
        ...actions,
      }),
    );

  /** Same data path as the app: list -> latest -> detail, all via the API module. */
  async function loadHome(list: AssessmentSummary[], details: AssessmentDetail[] = []) {
    routes = { "/api/v1/assessments": () => json(200, list) };
    for (const detail of details) {
      routes[`/api/v1/assessments/${detail.id}`] = () => json(200, detail);
    }
    const fetched = await api.fetchAssessments();
    const state = lib.securityHomeState(fetched);
    if (state.kind !== "complete") {
      return { state, html: renderToStaticMarkup(createElement(SecurityHomeView, { state, issues: null, ...actions })) };
    }
    const detail = await api.fetchAssessment(state.latest.id);
    const summaryData = lib.summarizeIssues(detail);
    const html = renderToStaticMarkup(
      createElement(SecurityHomeView, {
        state,
        issues: { status: "ready", summary: summaryData },
        ...actions,
      }),
    );
    return { state, html, summaryData };
  }

  const completeList = [older, latest];

  // 1. No assessments -> empty state, no risk.
  {
    const { state, html } = await loadHome([]);
    check(state.kind === "empty", "empty state");
    check(html.includes("Your network hasn&#x27;t been checked yet."), "empty headline");
    check(html.includes(">Check security<"), "Check security action");
    check(!/risk score|\/ 100|Show technical details/i.test(html), "no fake risk or details");
    check(renderPage([]).includes("hasn&#x27;t been checked yet"), "OverviewPage empty");
    pass("1 no assessments -> \"Your network hasn't been checked yet.\" + Check security");
  }

  // 2 + 3. COMPLETE latest -> real risk and real findings.
  let completeHtml = "";
  {
    const { state, html, summaryData } = await loadHome(completeList, [latestDetail]);
    completeHtml = html;
    check(state.kind === "complete" && state.latest.id === latest.id, "latest COMPLETE chosen");
    check(requested.includes(`/api/v1/assessments/${latest.id}`), "detail fetched by selected ID");
    check(html.includes(">HIGH</span> risk."), "risk level from backend");
    check(html.includes(">63.25</span>"), "risk score from backend");
    check(html.includes(T1), "target from backend");
    check(html.includes("Last checked"), "timestamp shown");
    check(html.includes("3 important issues"), "important issue count");
    check(html.includes("Based on the checks configured for this authorized target only."), "scope note");
    check(html.includes(">Check again<") && html.includes(">Show technical details<"), "actions");
    pass("2 COMPLETE -> backend risk level, score, target, time and counts shown");

    check(summaryData, "summary");
    const titles = summaryData.important.map((issue) => issue.title);
    check(
      titles.join("|") ===
        "MQTT broker accepts connections without a password|MQTT traffic is not encrypted|Backend-only fixture title",
      `important order by severity then recorded score (${titles.join("|")})`,
    );
    check(html.includes("The broker accepted a connection that supplied no username or password."), "plain summary");
    check(html.includes("Backend-only fixture title"), "unknown check falls back to backend title");
    check(html.includes("Found on 2 services"), "same check on two services shown once");
    check(html.includes("Fixture remediation A:\n  set allow_anonymous false."), "remediation verbatim");
    check(html.includes("No remediation recorded."), "missing remediation stated");
    check(html.includes("Show 1 minor issue") && html.includes("Web security headers are missing"), "minor collapsed");
    pass("3 COMPLETE -> real findings as simple issues with backend remediation");
  }

  // 4. INCOMPLETE latest -> no current risk.
  {
    const partial = summary("INCOMPLETE", "2026-10-14T07:00:00Z", {
      highest_risk: 88.8,
      highest_risk_level: "CRITICAL",
      error_summary: "TLS check on target returned TIMEOUT.",
    });
    const { state, html } = await loadHome([older, partial, latest, middle]);
    check(state.kind === "incomplete", "incomplete state");
    check(html.includes("I could only partially check your authorized target."), "headline");
    check(html.includes("TLS check on target returned TIMEOUT."), "error_summary shown");
    check(html.includes(">Run another check<"), "Run another check");
    check(!html.includes("88.8") && !html.includes("CRITICAL"), "incomplete run's risk not shown");
    check(!/Risk score|at <span/.test(html), "no risk statement");
    check(html.includes("No current risk level is shown"), "explains missing risk");
    pass("4 INCOMPLETE -> partial-check message, error_summary, no current risk");
  }

  // 5. FAILED latest -> no current risk.
  {
    const failed = summary("FAILED", "2026-10-15T07:00:00Z", {
      highest_risk: 77.7,
      highest_risk_level: "HIGH",
      error_summary: "RuntimeError: probe crashed",
    });
    const { state, html } = await loadHome([latest, failed]);
    check(state.kind === "failed", "failed state");
    check(html.includes("The security check failed."), "headline");
    check(html.includes("RuntimeError: probe crashed"), "error_summary shown");
    check(!html.includes("77.7") && !html.includes(">HIGH<"), "failed run's risk not shown");
    check(!html.includes("63.25"), "older run's risk not presented as current");
    pass("5 FAILED -> failure message, error_summary, no current risk");
  }

  // 6. INFO findings are never important issues.
  {
    const summaryData = lib.summarizeIssues(latestDetail);
    const all = [...summaryData.important, ...summaryData.minor];
    check(all.every((issue) => issue.severity !== "INFO"), "no INFO issue cards");
    check(summaryData.observationCount === 1, "INFO counted as observation");
    check(!completeHtml.includes(infoTitle) && !completeHtml.includes("Open network service found"), "INFO title not shown");
    check(completeHtml.includes("1 informational observation recorded"), "observation count line");
    check(lib.issueGroup("CRITICAL") === "important" && lib.issueGroup("MEDIUM") === "important", "important group");
    check(lib.issueGroup("LOW") === "minor" && lib.issueGroup("INFO") === "observation", "minor/observation");
    pass("6 INFO findings shown only as an observation count");
  }

  // 7. Simple layer shows no IDs, ports, UUIDs, evidence or confidence.
  {
    for (const forbidden of [
      "IOT-MQTT-01", "IOT-MQTT-02", "WEB-02", "NET-01", "ZZ-99",
      "1883", "8883", "Observed detail", "IoT-RISK-v1", "97%", "0.97",
    ]) {
      check(!completeHtml.includes(forbidden), `simple layer leaks "${forbidden}"`);
    }
    for (const item of latestDetail.findings) {
      check(!completeHtml.includes(item.id), "finding UUID shown");
      check(!completeHtml.includes(item.evidence_reference ?? "-"), "evidence UUID shown");
    }
    check(!completeHtml.includes(latest.id), "assessment UUID shown");
    pass("7 no finding IDs, ports, UUIDs, evidence or confidence in the simple layer");
  }

  // 8. Legacy /findings and /risk are never requested or shown.
  {
    const html = renderToStaticMarkup(
      createElement(OverviewPage, {
        assessments: completeList,
        assessmentsError: null,
        onRetryAssessments: noop,
        ...actions,
        // Legacy-shaped props must have no effect on the security home.
        ...({ findings: [{ title: LEGACY_SENTINEL }], risk: { highest_score: 99.99 } } as object),
      } as Parameters<typeof OverviewPage>[0]),
    );
    check(!html.includes(LEGACY_SENTINEL) && !html.includes("99.99"), "legacy data not rendered");
    check(html.includes(">63.25</span>"), "assessment summary rendered");
    const legacy = requested.filter((path) =>
      ["/api/v1/findings", "/api/v1/risk"].includes(path) || path.startsWith("/api/v1/explanations"),
    );
    check(requested.length > 0, "requests were recorded");
    check(legacy.length === 0, `legacy endpoints requested: ${legacy.join(", ")}`);
    check(!/Security Findings|Top findings|Security pipeline|Context-Aware Risk/.test(html), "legacy widgets gone");
    pass("8 Overview uses only /assessments; legacy endpoints never requested");
  }

  // 9. Risk is passed through, never calculated.
  {
    check(!completeHtml.includes("57.93") && !completeHtml.includes("41.17"), "per-finding scores not shown");
    check(!completeHtml.includes("99.1"), "no summed score");
    const altered: AssessmentSummary = {
      ...latest,
      highest_risk: 12.345,
      highest_risk_level: "MODERATE",
    };
    const html = renderPage([older, altered]);
    check(html.includes(">12.345</span>") && html.includes(">MODERATE</span>"), "displays backend value as-is");
    const noRisk = renderPage([{ ...latest, highest_risk: null, highest_risk_level: null }]);
    check(noRisk.includes("without an overall risk level") && !noRisk.includes("Risk score"), "null risk not invented");
    pass("9 risk shown exactly as recorded; null stays unknown");
  }

  // 10. No hardcoded target.
  {
    const html = renderPage([{ ...latest, target: T2 }]);
    check(html.includes(T2) && !html.includes(T1), "target follows data");
    check(!completeHtml.includes("10.188.244.85"), "no hardcoded lab target");
    pass("10 target comes from the assessment record");
  }

  // 11. No hardcoded ID; selection by timestamp, not array position.
  {
    const orders = [
      [older, latest, middle],
      [middle, older, latest],
      [latest, middle, older],
    ];
    for (const order of orders) {
      check(lib.selectLatestAssessment(order)?.id === latest.id, "order-independent selection");
    }
    const newer = summary("COMPLETE", "2026-10-20T00:00:00Z");
    check(lib.selectLatestAssessment([newer, latest])?.id === newer.id, "newest start wins");
    const offset = summary("COMPLETE", "2026-10-14T01:00:00+05:30");
    check(lib.selectLatestAssessment([offset, latest])?.id === latest.id, "instants compared across offsets");
    const sameStartA = summary("COMPLETE", "2026-10-13T19:58:00Z", { completed_at: "2026-10-13T20:01:00Z" });
    check(lib.selectLatestAssessment([latest, sameStartA])?.id === sameStartA.id, "completion breaks ties");
    const unreadable = summary("COMPLETE", "not-a-date", { created_at: "also-bad", completed_at: null });
    check(lib.selectLatestAssessment([unreadable, older])?.id === older.id, "unreadable timestamp never wins");
    check(lib.selectLatestAssessment([]) === null, "empty -> null");
    pass("11 latest chosen by timestamp; detail fetched with that ID");
  }

  // 12. API failure handling.
  {
    routes = {
      "/api/v1/assessments": () => json(500, { detail: "database unavailable" }),
    };
    let message = "";
    try {
      await api.fetchAssessments();
    } catch (error) {
      message = error instanceof Error ? error.message : "";
    }
    check(message === "database unavailable", "API client message");
    const html = renderPage(null, message);
    check(html.includes("Couldn&#x27;t load your latest security assessment. database unavailable"), "error text");
    check(html.includes(">Retry<"), "retry offered");
    check(!/Risk score| risk\.|Check again/.test(html), "no risk on error");
    const loading = renderPage(null);
    check(loading.includes("Loading your latest security assessment…"), "loading text");
    const issueError = renderToStaticMarkup(
      createElement(SecurityHomeView, {
        state: { kind: "complete", latest },
        issues: { status: "error", message: "Assessment not found", onRetry: noop },
        ...actions,
      }),
    );
    check(issueError.includes("Couldn&#x27;t load the issues from your latest assessment. Assessment not found"), "detail error");
    pass("12 list and detail API failures show the API message with Retry");
  }

  // Safety wording: never claims the network is safe.
  {
    const clean: AssessmentDetail = { ...latestDetail, findings: [info], risk_snapshots: [] };
    const html = renderToStaticMarkup(
      createElement(SecurityHomeView, {
        state: { kind: "complete", latest: { ...latest, highest_risk_level: "LOW", highest_risk: 10 } },
        issues: { status: "ready", summary: lib.summarizeIssues(clean) },
        ...actions,
      }),
    );
    check(html.includes("No important issues were reported in the latest check."), "neutral wording");
    check(!/\bsafe\b|\bsecure\b|no vulnerabilities/i.test(html), "no safety claim");
    pass("no 'safe'/'secure' claims when no important issues are reported");
  }
} finally {
  globalThis.fetch = realFetch;
  await server.close();
}

for (const line of results) console.log(line);
console.log(`${results.filter((line) => line.startsWith("PASS")).length} checks passed`);
