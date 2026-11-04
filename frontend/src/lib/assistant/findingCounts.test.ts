/**
 * Checks that the assistant separates important issues from the other recorded
 * findings: counts by severity group, the result card, the count questions
 * ("What did you find?", "Are there only two vulnerabilities?", "Show me
 * everything", "How many issues?"), View all findings, and that guided fix,
 * verification and comparison keep their explicit, existing behaviour.
 * globalThis.fetch is a recorder that answers only POST /api/v1/assistant/explain,
 * POST /api/v1/assessments and GET /api/v1/assessments/{id} from fixtures and
 * fails on anything else. Fixtures are test-only and never persisted.
 *
 * Run from frontend/:  node src/lib/assistant/findingCounts.test.ts
 */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { AssistantExplainResponse } from "../../api/assistant.ts";
import type {
  AssessmentDetail,
  AssessmentEvidence,
  AssessmentFinding,
  AssessmentStatus,
  AssessmentSummary,
  RiskSnapshot,
} from "../../api/types.ts";
import type { AssistantMessage, RequestOutcome } from "./conversation.ts";
import type { AssistantWorkflowState } from "./workflow.ts";

declare const process: { cwd(): string };

type ViteServer = {
  ssrLoadModule(url: string): Promise<Record<string, unknown>>;
  close(): Promise<void>;
};
type ConversationLib = typeof import("./conversation.ts");
type ContextLib = typeof import("./context.ts");
type IntentsLib = typeof import("./intents.ts");
type WorkflowLib = typeof import("./workflow.ts");
type HomeLib = typeof import("../securityHome.ts");
type ComparisonLib = typeof import("../assessmentComparison.ts");
type AssistantApi = typeof import("../../api/assistant.ts");
type AssessmentsApi = typeof import("../../api/assessments.ts");
type PageModule = typeof import("../../components/assistant/AssistantPage.tsx");
type FsModule = { readFileSync(path: string, encoding: "utf8"): string };
type Context = ReturnType<ContextLib["buildAssistantContext"]>;

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${message}`);
}
const results: string[] = [];
const pass = (name: string, note = "") => results.push(`PASS ${name}${note ? ` — ${note}` : ""}`);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

// ---- fixtures (shaped like the recorded lab check) ----------------------------------
const TARGET = "192.0.2.44";
let seq = 0;
const uuid = (prefix: string) => `${prefix}0000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`;
const COVERAGE = [
  { check_id: "IOT-MQTT-01", port: 1883, status: "EVALUATED" },
  { check_id: "IOT-MQTT-02", port: 1883, status: "EVALUATED" },
  { check_id: "NET-01", port: 139, status: "EVALUATED" },
  { check_id: "NET-01", port: 445, status: "EVALUATED" },
  { check_id: "NET-01", port: 1883, status: "EVALUATED" },
  { check_id: "NET-06", port: 139, status: "EVALUATED" },
  { check_id: "NET-06", port: 445, status: "EVALUATED" },
];
const FIX: Record<string, string> = {
  "IOT-MQTT-01": "Set allow_anonymous false, configure a password_file, and enforce topic ACLs for each client.",
  "IOT-MQTT-02": "Enable an MQTT TLS listener (port 8883) with a valid certificate and move clients to it.",
  "NET-01": "Confirm the service is required; close or firewall it otherwise.",
  "NET-06": "Verify the administrative service is required and restrict it to management hosts.",
};

function summary(status: AssessmentStatus, startedAt: string, extra: Partial<AssessmentSummary> = {}): AssessmentSummary {
  return {
    id: uuid("a"),
    target: TARGET,
    assessment_type: "MULTI_LAYER",
    status,
    started_at: startedAt,
    completed_at: status === "RUNNING" ? null : startedAt.replace(":00Z", ":40Z"),
    error_summary: null,
    metadata: { check_catalog_version: "1", ports: [139, 445, 1883, 8883], checks_evaluated: COVERAGE } as AssessmentSummary["metadata"],
    created_at: startedAt,
    evidence_count: 1,
    finding_count: 7,
    highest_risk: null,
    highest_risk_level: null,
    ...extra,
  };
}
function evidence(assessmentId: string): AssessmentEvidence {
  return {
    id: uuid("e"),
    assessment_id: assessmentId,
    target: TARGET,
    port: 1883,
    check_type: "NMAP_PORT",
    result: "OPEN",
    evidence_source: "NMAP",
    observation: { port: 1883, state: "open", reason: "syn-ack", protocol: "tcp", service_name: "mosquitto version 2.1.2", product: null, version: null },
    observed_at: "2026-10-13T19:58:20Z",
  };
}
function finding(assessmentId: string, findingId: string, severity: AssessmentFinding["severity"], title: string, port: number): AssessmentFinding {
  return {
    id: uuid("f"),
    assessment_id: assessmentId,
    finding_id: findingId,
    finding_type: `TYPE_${findingId}`,
    category: "IOT_PROTOCOL",
    title,
    severity,
    confidence: 0.9,
    description: null,
    target: TARGET,
    port,
    evidence_reference: null,
    remediation: FIX[findingId] ?? null,
    status: "OPEN",
    created_at: "2026-10-13T19:58:30Z",
  };
}
function snapshot(assessmentId: string, score: number, level: RiskSnapshot["risk_level"]): RiskSnapshot {
  return {
    id: uuid("r"),
    assessment_id: assessmentId,
    finding_ref: null,
    score,
    risk_level: level,
    score_version: "IoT-RISK-v1",
    base_severity: null,
    context_score: null,
    factor_contributions: {},
    context_inputs: {},
    created_at: "2026-10-13T19:58:40Z",
  };
}
function detail(s: AssessmentSummary, findings: AssessmentFinding[], score: number, level: RiskSnapshot["risk_level"]): AssessmentDetail {
  return { ...s, evidence: [evidence(s.id)], findings, risk_snapshots: [snapshot(s.id, score, level)] };
}
/** The lower-severity findings of the lab check: 2 LOW, 3 INFO. */
const lowerFindings = (assessmentId: string) => [
  finding(assessmentId, "NET-06", "LOW", "Administrative service exposed", 139),
  finding(assessmentId, "NET-06", "LOW", "Administrative service exposed", 445),
  finding(assessmentId, "NET-01", "INFO", "Open network service", 139),
  finding(assessmentId, "NET-01", "INFO", "Open network service", 445),
  finding(assessmentId, "NET-01", "INFO", "Open network service", 1883),
];
const importantFindings = (assessmentId: string) => [
  finding(assessmentId, "IOT-MQTT-01", "HIGH", "Anonymous MQTT access", 1883),
  finding(assessmentId, "IOT-MQTT-02", "MEDIUM", "MQTT without TLS", 1883),
];

const older = summary("COMPLETE", "2026-10-12T08:00:00Z", { highest_risk: 41.2, highest_risk_level: "MEDIUM" });
const latest = summary("COMPLETE", "2026-10-13T19:58:00Z", { highest_risk: 70.5, highest_risk_level: "HIGH" });
const latestDetail = detail(latest, [...importantFindings(latest.id), ...lowerFindings(latest.id)], 70.5, "HIGH");
const olderDetail = detail(older, importantFindings(older.id), 41.2, "MEDIUM");

const onlyImportant = summary("COMPLETE", "2026-10-13T19:58:00Z", { highest_risk: 70.5, highest_risk_level: "HIGH" });
const onlyImportantDetail = detail(onlyImportant, importantFindings(onlyImportant.id), 70.5, "HIGH");
const onlyLower = summary("COMPLETE", "2026-10-13T19:58:00Z", { highest_risk: 12.0, highest_risk_level: "LOW" });
const onlyLowerDetail = detail(onlyLower, lowerFindings(onlyLower.id), 12.0, "LOW");
const critical = summary("COMPLETE", "2026-10-13T19:58:00Z", { highest_risk: 92.0, highest_risk_level: "CRITICAL" });
const criticalDetail = detail(
  critical,
  [finding(critical.id, "NET-03", "CRITICAL", "Telnet exposed", 23), ...importantFindings(critical.id), ...lowerFindings(critical.id).slice(0, 1)],
  92.0,
  "CRITICAL",
);

/** A verification check run when nothing was changed on the broker. */
function afterUnchanged(): AssessmentDetail {
  const s = summary("COMPLETE", "2026-10-14T09:00:00Z", { highest_risk: 70.5, highest_risk_level: "HIGH" });
  return detail(s, [...importantFindings(s.id), ...lowerFindings(s.id)], 70.5, "HIGH");
}
/** A verification check where anonymous access was no longer observed. */
function afterFixed(): AssessmentDetail {
  const s = summary("COMPLETE", "2026-10-14T09:00:00Z", { highest_risk: 55.0, highest_risk_level: "MEDIUM" });
  return detail(s, [finding(s.id, "IOT-MQTT-02", "MEDIUM", "MQTT without TLS", 1883), ...lowerFindings(s.id)], 55.0, "MEDIUM");
}

// ---- fetch recorder -----------------------------------------------------------------
type Recorded = { url: string; method: string; body: string };
const recorded: Recorded[] = [];
const unexpected: string[] = [];
const explainResponse: AssistantExplainResponse = { status: "COMPLETE", answer: "Model text for the test.", source: "AI" };
let createResponse: { status: number; body: unknown } = { status: 201, body: afterUnchanged() };
const details = new Map<string, AssessmentDetail>();
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  const method = init?.method ?? "GET";
  recorded.push({ url, method, body: String(init?.body ?? "") });
  if (method === "POST" && url.endsWith("/api/v1/assistant/explain")) return json(explainResponse);
  if (method === "POST" && url.endsWith("/api/v1/assessments")) {
    const body = createResponse.body as AssessmentDetail;
    if (createResponse.status < 300) details.set(body.id, body);
    return json(createResponse.body, createResponse.status);
  }
  const detailMatch = /\/api\/v1\/assessments\/([^/]+)$/.exec(url);
  if (method === "GET" && detailMatch) {
    const found = details.get(decodeURIComponent(detailMatch[1]));
    return found ? json(found) : json({ detail: "Not found" }, 404);
  }
  unexpected.push(`${method} ${url}`);
  throw new Error(`unexpected request ${method} ${url}`);
}) as typeof fetch;

const assessmentPosts = (from = 0) =>
  recorded.slice(from).filter((call) => call.method === "POST" && call.url.endsWith("/api/v1/assessments"));
const explainCalls = (from = 0) =>
  recorded.slice(from).filter((call) => call.method === "POST" && call.url.endsWith("/api/v1/assistant/explain"));

// ---- loader -------------------------------------------------------------------------
const viteModuleName = "vite";
const fsModuleName = "node:fs";
const vite = (await import(viteModuleName)) as { createServer(config: Record<string, unknown>): Promise<ViteServer> };
const fs = (await import(fsModuleName)) as FsModule;
const source = (path: string) => fs.readFileSync(`${process.cwd()}/${path}`, "utf8");
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
  const load = async <T>(url: string) => (await server.ssrLoadModule(url)) as unknown as T;
  const conv = await load<ConversationLib>("/src/lib/assistant/conversation.ts");
  const ctx = await load<ContextLib>("/src/lib/assistant/context.ts");
  const intents = await load<IntentsLib>("/src/lib/assistant/intents.ts");
  const wf = await load<WorkflowLib>("/src/lib/assistant/workflow.ts");
  const home = await load<HomeLib>("/src/lib/securityHome.ts");
  const cmp = await load<ComparisonLib>("/src/lib/assessmentComparison.ts");
  const assistantApi = await load<AssistantApi>("/src/api/assistant.ts");
  const assessmentsApi = await load<AssessmentsApi>("/src/api/assessments.ts");
  const { AssistantView } = await load<PageModule>("/src/components/assistant/AssistantPage.tsx");

  for (const d of [latestDetail, olderDetail, onlyImportantDetail, onlyLowerDetail, criticalDetail]) details.set(d.id, d);
  const contextFor = (summaries: AssessmentSummary[], d: AssessmentDetail) =>
    ctx.buildAssistantContext(summaries, { status: "ready", detail: d });
  const contextComplete = contextFor([latest, older], latestDetail);
  const contextOnlyImportant = contextFor([onlyImportant, older], onlyImportantDetail);
  const contextOnlyLower = contextFor([onlyLower, older], onlyLowerDetail);
  const contextCritical = contextFor([critical, older], criticalDetail);
  const detailFor = new Map<string, AssessmentDetail>([...details.entries()]);

  function harness(initial: Context, workflow: Partial<AssistantWorkflowState> = {}) {
    const context: Context = initial;
    let state: AssistantWorkflowState = { ...wf.INITIAL_WORKFLOW_STATE, ...workflow };
    const messages: AssistantMessage[] = [];
    const navigations: unknown[] = [];
    let id = 0;
    const conversation = conv.createAssistantConversation({
      getContext: () => context,
      getLatestDetail: () => detailFor.get(context.latestAssessment?.id ?? "") ?? null,
      navigate: (request) => navigations.push(request),
      addMessage: (message) => messages.push(message),
      setStatus: () => {},
      explain: assistantApi.explainWithAssistant,
      workflow: {
        get: () => state,
        update: (patch) => {
          state = { ...state, ...patch };
        },
        runAssessment: assessmentsApi.createAssessment,
        loadAssessment: assessmentsApi.fetchAssessment,
      },
      wait: () => Promise.resolve(),
      now: () => 1_700_000_000_000,
      nextId: () => `m${++id}`,
    });
    return {
      ...conversation,
      messages,
      navigations,
      state: () => state,
      last: () => messages.filter((m) => m.role === "assistant").at(-1)!,
    };
  }
  type Harness = ReturnType<typeof harness>;

  /** Asks and requires a deterministic answer: no request, no navigation, no check. */
  async function askQuiet(h: Harness, text: string) {
    const before = recorded.length;
    const outcome = await h.handleAssistantRequest(text);
    check(outcome.status === "answered", `${text}: answered`);
    const reply = h.last();
    check(reply.text !== conv.UNKNOWN_REPLY, `${text}: generic reply`);
    check(recorded.length === before, `${text}: made ${recorded.length - before} request(s)`);
    check(h.navigations.length === 0, `${text}: navigated`);
    check(h.state().running === null, `${text}: started a check`);
    return reply;
  }
  const actionIds = (m: AssistantMessage) => (m.actions ?? []).map((a) => `${a.id}:${a.label}`);
  const assistantMessage = (id: string, text: string, card: AssistantMessage["card"]): AssistantMessage => ({
    id,
    role: "assistant",
    text,
    timestamp: 1_700_000_000_000,
    card,
  });
  const renderView = (context: Context, messages: AssistantMessage[]) =>
    renderToStaticMarkup(
      createElement(AssistantView, {
        context,
        assessmentsError: null,
        onRetryAssessments: () => {},
        messages,
        status: null,
        onRequest: (): Promise<RequestOutcome> => Promise.resolve({ status: "rejected", reason: "empty" }),
        onOpenAction: () => {},
        running: null,
        onRunCheck: () => {},
        onSelectIssue: () => {},
        onGuidedFix: () => {},
        onNotYet: () => {},
        onWorkflowNavigate: () => {},
      }),
    );
  const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
  const simpleLayer = (html: string) => html.replace(/<details data-technical=""[\s\S]*?<\/details>/g, "");
  const RAW_ID = /IOT-MQTT-0\d|NET-0\d|[0-9a-f]{7}0-0000-4000-8000|IoT-RISK|confidence|evidence_reference/;
  const SECURITY_CLAIM = /you are secure|you're secure|network is secure|completely secure|fully secure|everything else is safe|no other vulnerabilities|only 2 vulnerabilities/i;
  const LOWER_AS_VULNERABILITY = /\b(LOW|INFO|informational|lower-severity|additional)\b[^.\n]*\bvulnerabilit/i;
  const counts = contextComplete.findingCounts!;

  // 1. 2 important + 5 additional findings.
  {
    check(
      same(counts, { critical: 0, high: 1, medium: 1, low: 2, info: 3, important: 2, additional: 5, total: 7 }),
      `counts of the lab check: ${JSON.stringify(counts)}`,
    );
    check(same(home.countFindings(latestDetail.findings), counts), "context counts are countFindings of the recorded findings");
    const html = renderView(contextComplete, [assistantMessage("r1", "Security check complete.", wf.contextResultCard(contextComplete))]);
    const important = /<[^>]*data-result-group="important"[\s\S]*?<\/section>/.exec(html)?.[0] ?? "";
    const additional = /<[^>]*data-result-group="additional"[\s\S]*?<\/section>/.exec(html)?.[0] ?? "";
    check(text(important).startsWith("2 Important Issues"), `important group: ${text(important)}`);
    check(text(additional).startsWith("5 Additional Findings"), `additional group: ${text(additional)}`);
    const chip = (label: string) => text(new RegExp(`<li[^>]*data-severity-count="${label}"[^>]*>[\\s\\S]*?</li>`).exec(additional)?.[0] ?? "");
    check(chip("LOW") === "2 LOW" && chip("INFO") === "3 INFO", `chips: ${chip("LOW")} / ${chip("INFO")}`);
    check(html.indexOf('data-result-group="important"') < html.indexOf('data-result-group="additional"'), "important issues first");
    check(!html.includes("Important issues: <span"), "the old single count is gone");
    pass("1 the lab check shows 2 important issues and 5 additional findings");
  }

  // 2. Every finding is counted once.
  {
    for (const d of [latestDetail, onlyImportantDetail, onlyLowerDetail, criticalDetail]) {
      const c = home.countFindings(d.findings);
      check(c.total === d.findings.length && c.important + c.additional === c.total, `total = important + additional (${JSON.stringify(c)})`);
      check(c.critical + c.high + c.medium === c.important && c.low + c.info === c.additional, "groups add up by severity");
    }
    check(same(home.countFindings([]), { critical: 0, high: 0, medium: 0, low: 0, info: 0, important: 0, additional: 0, total: 0 }), "no findings");
    pass("2 all recorded findings are counted correctly");
  }

  // 3. CRITICAL, HIGH and MEDIUM are important.
  {
    const c = contextCritical.findingCounts!;
    check(c.critical === 1 && c.high === 1 && c.medium === 1 && c.important === 3, `critical check: ${JSON.stringify(c)}`);
    for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "high"]) check(home.issueGroup(severity) === "important", `${severity} is important`);
    check(wf.severityBreakdown(c, "important") === "1 CRITICAL, 1 HIGH and 1 MEDIUM", wf.severityBreakdown(c, "important"));
    pass("3 HIGH/MEDIUM/CRITICAL are important");
  }

  // 4. LOW and INFO are additional.
  {
    check(home.issueGroup("LOW") !== "important" && home.issueGroup("INFO") !== "important", "LOW and INFO are not important");
    check(wf.severityBreakdown(counts, "additional") === "2 LOW and 3 INFO", wf.severityBreakdown(counts, "additional"));
    check(wf.lowerSeverityKinds(counts) === "LOW or informational", "both lower kinds named");
    pass("4 LOW/INFO are additional");
  }

  // 5. Zero additional findings.
  {
    const c = contextOnlyImportant.findingCounts!;
    check(c.important === 2 && c.additional === 0 && c.total === 2, JSON.stringify(c));
    const overview = wf.findingsOverviewText(c, 2);
    check(overview === "I found 2 findings in your latest check: 2 important issues. No additional lower-severity findings.", overview);
    const html = renderView(contextOnlyImportant, [assistantMessage("r1", "Security check complete.", wf.contextResultCard(contextOnlyImportant))]);
    check(/data-result-group="additional"[\s\S]*?No additional lower-severity findings\./.test(html) && !html.includes("data-severity-count"), "no chips");
    const reply = await askQuiet(harness(contextOnlyImportant), "Are there only two vulnerabilities?");
    check(reply.text.startsWith("Yes. Your check produced 2 findings."), reply.text);
    check(reply.text.includes("No additional lower-severity findings."), reply.text);
    pass("5 zero additional findings");
  }

  // 6. Zero important findings.
  {
    const c = contextOnlyLower.findingCounts!;
    check(c.important === 0 && c.additional === 5, JSON.stringify(c));
    const html = renderView(contextOnlyLower, [assistantMessage("r1", "Security check complete.", wf.contextResultCard(contextOnlyLower))]);
    check(/data-result-group="important"[\s\S]*?No high-priority issues were found\./.test(html), "no high-priority issues");
    check(text(/<[^>]*data-result-group="additional"[\s\S]*?<\/section>/.exec(html)?.[0] ?? "").startsWith("5 Additional Findings"), "lower findings still shown");
    const found = await askQuiet(harness(contextOnlyLower), "What did you find?");
    check(found.text.startsWith("I found 5 findings in your latest check. No high-priority issues were found"), found.text);
    check(!SECURITY_CLAIM.test(found.text) && !SECURITY_CLAIM.test(text(html)), "never claims the network is secure");
    pass("6 zero important findings");
  }

  // 7. "What did you find?"
  {
    const r = intents.classifyAssistantIntent("What did you find?");
    check(r.intent === "TECHNICAL" && r.subject === "FINDINGS", `classified ${r.intent}/${r.subject}`);
    const reply = await askQuiet(harness(contextComplete), "What did you find?");
    check(
      reply.text.split("\n")[0] === "I found 7 findings in your latest check: 2 important issues and 5 additional lower-severity findings.",
      reply.text,
    );
    check(reply.card?.kind === "ISSUES" && reply.card.issues.length === 2 && reply.card.additionalFindings === 5, "important issues to choose from");
    check(actionIds(reply).includes("technical-details:View all findings"), `actions: ${actionIds(reply)}`);
    check(!SECURITY_CLAIM.test(reply.text) && !LOWER_AS_VULNERABILITY.test(reply.text), reply.text);
    pass("7 \"What did you find?\"");
  }

  // 8. "Are there only two vulnerabilities?" and "How many issues?"
  {
    const reply = await askQuiet(harness(contextComplete), "Are there only two vulnerabilities?");
    check(
      reply.text ===
        "No. Your check produced 7 findings.\n2 are important security issues (HIGH/MEDIUM), while the other 5 are LOW or informational findings.",
      reply.text,
    );
    check(!LOWER_AS_VULNERABILITY.test(reply.text) && !SECURITY_CLAIM.test(reply.text), "LOW/INFO are not called vulnerabilities");
    check(actionIds(reply)[0] === "technical-details:View all findings", `actions: ${actionIds(reply)}`);
    for (const question of ["Are there only 2 issues?", "Is that all you found?"]) {
      const r = await askQuiet(harness(contextComplete), question);
      check(/Your check produced 7 findings|7 findings in total/.test(r.text), `${question}: ${r.text}`);
    }
    const many = await askQuiet(harness(contextComplete), "How many issues?");
    check(
      many.text ===
        [
          "Your latest check produced 7 findings in total:",
          "• 2 important issues (1 HIGH and 1 MEDIUM)",
          "• 5 additional lower-severity findings (2 LOW and 3 INFO)",
        ].join("\n"),
      many.text,
    );
    check(!LOWER_AS_VULNERABILITY.test(many.text), "count lines never call LOW/INFO vulnerabilities");
    pass("8 \"Are there only two vulnerabilities?\" and \"How many issues?\" distinguish important, additional and total");
  }

  // 9. "Show me everything".
  {
    const reply = await askQuiet(harness(contextComplete), "Show me everything");
    const lines = reply.text.split("\n");
    check(lines[0] === "I found 7 findings in your latest check: 2 important issues and 5 additional lower-severity findings.", reply.text);
    const titleOf = (findingId: string) => home.findingDisplayTitle(latestDetail.findings.find((f) => f.finding_id === findingId)!);
    check(lines.includes(`• ${titleOf("NET-06")} — LOW (2 findings)`), `LOW group with the recorded title: ${reply.text}`);
    check(lines.includes(`• ${titleOf("NET-01")} — INFO (3 findings)`), `INFO group with the recorded title: ${reply.text}`);
    for (const issue of contextComplete.importantIssues!) check(reply.text.includes(issue.title), `important issue listed: ${issue.title}`);
    check(lines.indexOf(`• ${titleOf("NET-06")} — LOW (2 findings)`) < lines.indexOf(`• ${titleOf("NET-01")} — INFO (3 findings)`), "LOW before INFO");
    check(reply.actions?.[0]?.id === "technical-details" && reply.actions[0].primary === true, "View all findings is the main action");
    check(!RAW_ID.test(reply.text), `no raw IDs: ${reply.text}`);
    const all = await askQuiet(harness(contextComplete), "Show all findings");
    check(all.text === reply.text, "Show all findings = Show me everything");
    pass("9 \"Show me everything\" lists every recorded finding and offers the full list");
  }

  // 10. View all findings opens the existing technical findings view.
  {
    const h = harness(contextComplete);
    await askQuiet(h, "Show me everything");
    const before = recorded.length;
    h.openWorkflowAction("technical-details");
    check(
      same(h.navigations.at(-1), { section: "security", securityTechnical: true, anchor: { id: "assessment-findings" } }),
      `destination: ${JSON.stringify(h.navigations.at(-1))}`,
    );
    check(recorded.length === before, "navigation makes no request");
    const card = wf.contextResultCard(contextComplete);
    const stale = { ...card, assessmentId: older.id } as typeof card;
    const html = renderView(contextComplete, [assistantMessage("r1", "Security check complete.", stale), assistantMessage("r2", "Security check complete.", card)]);
    check((html.match(/data-view-all-findings=""/g) ?? []).length === 1, "View all findings only on the latest check's card");
    check(/<button[^>]*data-view-all-findings=""[^>]*>View all findings<\/button>/.test(html), "rendered as a button");
    check(!RAW_ID.test(simpleLayer(html)), `no raw IDs in the result card: ${RAW_ID.exec(simpleLayer(html))?.[0]}`);
    check(!/\b1883\b|evidence|confidence/i.test(text(simpleLayer(html))), "no ports, evidence or confidence in the simple summary");
    const page = source("src/components/assistant/AssistantPage.tsx");
    check(!/Anonymous MQTT access|Open network service|Administrative service/.test(page), "no hardcoded finding titles in the component");
    pass("10 View all findings navigates to the technical findings list");
  }

  // 11. Counting never asks the model.
  {
    const from = recorded.length;
    const h = harness(contextComplete);
    for (const question of ["What did you find?", "How many issues?", "How many findings?", "Are there only two vulnerabilities?", "Show me everything", "Total findings"]) {
      await askQuiet(h, question);
    }
    check(explainCalls(from).length === 0, "no explanation request");
    check(!recorded.some((call) => /11434|ollama|qwen/i.test(`${call.url} ${call.body}`)), "no model-service request");
    for (const file of ["src/lib/assistant/replies.ts", "src/lib/assistant/workflow.ts", "src/lib/securityHome.ts"]) {
      check(!/\bfetch\(|explainWithAssistant|\.explain\(|ollama|qwen|11434/i.test(source(file)), `${file}: no request or model reference`);
    }
    pass("11 no AI request for counting");
  }

  // 12. Questions never start a check.
  {
    const from = recorded.length;
    const h = harness(contextComplete);
    for (const question of ["What did you find?", "Show me everything", "How many vulnerabilities?", "Are there more findings?"]) await askQuiet(h, question);
    const seen = new Set<string>();
    for (let i = 0; i < h.messages.length && i < 100; i++) {
      for (const action of h.messages[i].role === "assistant" ? (h.messages[i].actions ?? []) : []) {
        if (action.id === "ask" && !seen.has(action.label)) {
          seen.add(action.label);
          await h.handleAssistantRequest(action.label);
        }
      }
    }
    check(assessmentPosts(from).length === 0, `questions POSTed ${assessmentPosts(from).length} time(s)`);
    check(h.state().running === null, "no check running");
    pass("12 no assessment POST from conversational questions", `${seen.size} follow-ups clicked`);
  }

  // 13. Guided fix still needs an explicit request.
  {
    const h = harness(contextComplete);
    for (const question of ["What did you find?", "How many issues?", "Show me everything"]) await askQuiet(h, question);
    check(!h.messages.some((m) => m.card?.kind === "GUIDED_FIX"), "counting never opens a guided fix");
    h.startGuidedFix("IOT-MQTT-01");
    check(h.last().card?.kind === "GUIDED_FIX", "the guide opens on the explicit Start guided fix");
    const guide = await askQuiet(harness(contextComplete), "How do I fix the more serious one?");
    check(guide.card?.kind === "GUIDED_FIX" && guide.card.guide.checkId === "IOT-MQTT-01", "asking for the fix still opens it");
    pass("13 guided fix still requires explicit user action");
  }

  // 14. Verification still needs the Run verification click; nothing resolved = still present.
  {
    createResponse = { status: 201, body: afterUnchanged() };
    const h = harness(contextComplete);
    h.startGuidedFix("IOT-MQTT-01");
    const ready = await askQuiet(h, "I've completed the fix");
    check(same(actionIds(ready), ["run-verification:Run verification check", "not-yet:Not yet"]), `buttons: ${actionIds(ready)}`);
    check(assessmentPosts().length === 0, "nothing before the click");
    const from = recorded.length;
    await h.runCheck("VERIFY");
    const posts = assessmentPosts(from);
    check(posts.length === 1 && same(JSON.parse(posts[0].body), { target: TARGET }), `one POST to the authorized target: ${posts.map((p) => p.body)}`);
    check(h.last().text === "This issue is still present.", h.last().text);
    check(!/appears to be fixed|has been fixed|you are secure/i.test(h.last().text), "no success claim without evidence");
    pass("14 verification still requires explicit user action");
  }

  // 15. Comparison uses the existing engine, with both groups counted.
  {
    const after = afterFixed();
    const expected = cmp.compareAssessments(latestDetail, after);
    const summaryResult = wf.comparisonSummary(latestDetail, after);
    check(summaryResult.comparable && summaryResult.card.kind === "COMPARISON", "comparable checks");
    const card = summaryResult.card as Extract<typeof summaryResult.card, { kind: "COMPARISON" }>;
    check(card.delta === expected.risk.delta && card.before?.score === 70.5 && card.after?.score === 55, "risk from compareAssessments");
    check(same(card.resolved.map((i) => i.checkId), ["IOT-MQTT-01"]), "resolved from the comparison engine");
    check(same(card.counts.before, counts) && same(card.counts.after, home.countFindings(after.findings)), "before/after counts from the recorded findings");
    check(card.counts.after.important === 1 && card.counts.after.additional === 5, JSON.stringify(card.counts.after));
    const html = renderView(contextComplete, [assistantMessage("c1", summaryResult.text, card)]);
    const grid = text(/<[^>]*data-comparison-counts=""[\s\S]*?<\/dl>/.exec(html)?.[0] ?? "");
    check(/Before After Important 2 1 Additional 5 5/.test(grid), `rendered counts: ${grid}`);
    check(grid.includes("-15.5") || grid.includes("−15.5"), `risk change: ${grid}`);
    const unchanged = wf.comparisonSummary(latestDetail, afterUnchanged());
    check(unchanged.comparable && unchanged.card.kind === "COMPARISON" && unchanged.card.resolved.length === 0, "nothing resolved when nothing changed");
    check(!/went down|fixed|resolved/i.test(unchanged.text), `no success claim: ${unchanged.text}`);
    pass("15 comparison uses the existing engine");
  }

  check(unexpected.length === 0, `unexpected requests: ${unexpected.join(", ")}`);
  for (const line of results) console.log(line);
  console.log(`${results.length} checks passed`);
} finally {
  globalThis.fetch = realFetch;
  await server.close();
}
