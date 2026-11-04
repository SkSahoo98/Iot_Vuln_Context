/**
 * Checks for the assistant security workflow (Phase UX-3C). The real API
 * clients are used; globalThis.fetch is a recorder that answers only
 * POST /api/v1/assistant/explain, POST /api/v1/assessments and
 * GET /api/v1/assessments/{id} from fixtures and fails on anything else, so
 * the run needs no backend and no model.
 *
 * Run from frontend/:  node src/lib/assistant/workflow.test.ts
 */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { AssistantExplainResponse } from "../../api/assistant.ts";
import type {
  AssessmentDetail,
  AssessmentFinding,
  AssessmentStatus,
  AssessmentSummary,
  RiskSnapshot,
} from "../../api/types.ts";
import type { NavRequest } from "../navigation.ts";
import type { AssistantMessage, RequestOutcome } from "./conversation.ts";
import type { AssistantWorkflowState } from "./workflow.ts";

declare const process: { cwd(): string };

type ViteServer = {
  ssrLoadModule(url: string): Promise<Record<string, unknown>>;
  close(): Promise<void>;
};
type ConversationLib = typeof import("./conversation.ts");
type ContextLib = typeof import("./context.ts");
type WorkflowLib = typeof import("./workflow.ts");
type ComparisonLib = typeof import("../assessmentComparison.ts");
type AssistantApi = typeof import("../../api/assistant.ts");
type AssessmentsApi = typeof import("../../api/assessments.ts");
type PageModule = typeof import("../../components/assistant/AssistantPage.tsx");
type FsModule = {
  readFileSync(path: string, encoding: "utf8"): string;
  readdirSync(path: string): string[];
};
type Context = ReturnType<ContextLib["buildAssistantContext"]>;

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${message}`);
}
const results: string[] = [];
const pass = (name: string, note = "") => results.push(`PASS ${name}${note ? ` — ${note}` : ""}`);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

// ---- fixtures -------------------------------------------------------------------
const TARGET = "192.0.2.44";
let seq = 0;
const uuid = (prefix: string) => `${prefix}0000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`;
const COVERAGE = [
  { check_id: "IOT-MQTT-01", port: 1883, status: "EVALUATED" },
  { check_id: "IOT-HTTP-02", port: 80, status: "EVALUATED" },
];

function summary(status: AssessmentStatus, startedAt: string, extra: Partial<AssessmentSummary> = {}): AssessmentSummary {
  return {
    id: uuid("a"),
    target: TARGET,
    assessment_type: "MULTI_LAYER",
    status,
    started_at: startedAt,
    completed_at: status === "RUNNING" ? null : startedAt.replace(":00Z", ":40Z"),
    error_summary: null,
    metadata: { check_catalog_version: "1", ports: [80, 1883], checks_evaluated: COVERAGE } as AssessmentSummary["metadata"],
    created_at: startedAt,
    evidence_count: 4,
    finding_count: 2,
    highest_risk: null,
    highest_risk_level: null,
    ...extra,
  };
}
function finding(assessmentId: string, findingId: string, severity: AssessmentFinding["severity"], title: string, port: number, remediation: string): AssessmentFinding {
  return {
    id: uuid("f"),
    assessment_id: assessmentId,
    finding_id: findingId,
    finding_type: `TYPE_${findingId}`,
    category: "IOT_PROTOCOL",
    title,
    severity,
    confidence: 0.9,
    description: `Recorded on port ${port}.`,
    target: TARGET,
    port,
    evidence_reference: "evidence-ref-0001",
    remediation,
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
    score_version: "iot-risk-v1",
    base_severity: null,
    context_score: null,
    factor_contributions: {},
    context_inputs: {},
    created_at: "2026-10-13T19:58:40Z",
  };
}
const detailOf = (s: AssessmentSummary, findings: AssessmentFinding[], snapshots: RiskSnapshot[]): AssessmentDetail => ({
  ...s,
  evidence: [],
  findings,
  risk_snapshots: snapshots,
});

const MQTT_FIX = "Require a username and password on the MQTT broker.";
const HTTP_FIX = "Turn off the unauthenticated web admin page.";
const older = summary("COMPLETE", "2026-10-12T08:00:00Z", { highest_risk: 41.2, highest_risk_level: "MEDIUM" });
const latest = summary("COMPLETE", "2026-10-13T19:58:00Z", { highest_risk: 70.5, highest_risk_level: "HIGH" });
const mqtt = finding(latest.id, "IOT-MQTT-01", "HIGH", "MQTT broker accepted an anonymous connection", 1883, MQTT_FIX);
const http = finding(latest.id, "IOT-HTTP-02", "MEDIUM", "Web admin page without authentication", 80, HTTP_FIX);
const latestDetail = detailOf(latest, [mqtt, http], [snapshot(latest.id, 70.5, "HIGH")]);

/** What the backend returns for a check run after the MQTT issue was fixed. */
function afterCheck(status: AssessmentStatus = "COMPLETE"): AssessmentDetail {
  const s = summary(status, "2026-10-14T09:00:00Z", { highest_risk: 40.0, highest_risk_level: "MEDIUM" });
  const remaining = { ...finding(s.id, "IOT-HTTP-02", "MEDIUM", "Web admin page without authentication", 80, HTTP_FIX) };
  return detailOf(s, status === "COMPLETE" ? [remaining] : [], status === "COMPLETE" ? [snapshot(s.id, 40.0, "MEDIUM")] : []);
}

// ---- fetch recorder -----------------------------------------------------------------
type Recorded = { url: string; method: string; body: string };
const recorded: Recorded[] = [];
const unexpected: string[] = [];
let explainResponse: AssistantExplainResponse = { status: "ERROR" };
let createResponse: { status: number; body: unknown } | Error = { status: 201, body: afterCheck() };
let createGate: Promise<void> | null = null;
const details = new Map<string, AssessmentDetail>();
let detailFailure = false;
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  const method = init?.method ?? "GET";
  recorded.push({ url, method, body: String(init?.body ?? "") });
  if (method === "POST" && url.endsWith("/api/v1/assistant/explain")) return json(explainResponse);
  if (method === "POST" && url.endsWith("/api/v1/assessments")) {
    if (createGate) await createGate;
    if (createResponse instanceof Error) throw createResponse;
    const body = createResponse.body as AssessmentDetail;
    if (createResponse.status < 300) details.set(body.id, body);
    return json(createResponse.body, createResponse.status);
  }
  const detailMatch = /\/api\/v1\/assessments\/([^/]+)$/.exec(url);
  if (method === "GET" && detailMatch) {
    const found = details.get(decodeURIComponent(detailMatch[1]));
    if (detailFailure || !found) return json({ detail: "Internal error: database unavailable" }, 500);
    return json(found);
  }
  unexpected.push(`${method} ${url}`);
  throw new Error(`unexpected request ${method} ${url}`);
}) as typeof fetch;

const posts = (path: string, from = 0) =>
  recorded.slice(from).filter((call) => call.method === "POST" && call.url.endsWith(path));

// ---- loader ---------------------------------------------------------------------
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
  const wf = await load<WorkflowLib>("/src/lib/assistant/workflow.ts");
  const cmp = await load<ComparisonLib>("/src/lib/assessmentComparison.ts");
  const assistantApi = await load<AssistantApi>("/src/api/assistant.ts");
  const assessmentsApi = await load<AssessmentsApi>("/src/api/assessments.ts");
  const { AssistantView } = await load<PageModule>("/src/components/assistant/AssistantPage.tsx");

  details.set(latest.id, latestDetail);
  const contextComplete = ctx.buildAssistantContext([latest, older], { status: "ready", detail: latestDetail });
  const singleDetail = detailOf(latest, [mqtt], [snapshot(latest.id, 70.5, "HIGH")]);
  const contextSingle = ctx.buildAssistantContext([latest, older], { status: "ready", detail: singleDetail });
  const contextPartial = ctx.buildAssistantContext([summary("INCOMPLETE", "2026-10-14T06:00:00Z", { highest_risk: 88.8, highest_risk_level: "CRITICAL" }), latest, older]);
  const contextFailed = ctx.buildAssistantContext([summary("FAILED", "2026-10-14T07:00:00Z", { error_summary: "RuntimeError: probe crashed" }), latest, older]);
  const contextNone = ctx.buildAssistantContext([]);
  const mqttTitle = contextComplete.importantIssues!.find((issue) => issue.checkId === "IOT-MQTT-01")!.title;

  /** Controller with the real API clients, the fetch recorder and in-memory workflow state. */
  function harness(initial: Context | null, workflow: Partial<AssistantWorkflowState> = {}) {
    let context = initial;
    let state: AssistantWorkflowState = { ...wf.INITIAL_WORKFLOW_STATE, ...workflow };
    const messages: AssistantMessage[] = [];
    const navigations: NavRequest[] = [];
    const statuses: (string | null)[] = [];
    const created: AssessmentDetail[] = [];
    const runningSeen: AssistantWorkflowState["running"][] = [];
    let id = 0;
    const conversation = conv.createAssistantConversation({
      getContext: () => context,
      navigate: (request) => navigations.push(request),
      addMessage: (message) => messages.push(message),
      setStatus: (label) => statuses.push(label),
      explain: assistantApi.explainWithAssistant,
      workflow: {
        get: () => state,
        update: (patch) => {
          state = { ...state, ...patch };
          runningSeen.push(state.running);
        },
        runAssessment: assessmentsApi.createAssessment,
        loadAssessment: assessmentsApi.fetchAssessment,
        onAssessmentCreated: (detail) => created.push(detail),
      },
      wait: () => Promise.resolve(),
      now: () => 1_700_000_000_000,
      nextId: () => `m${++id}`,
    });
    return {
      ...conversation,
      messages,
      navigations,
      statuses,
      created,
      runningSeen,
      state: () => state,
      setContext: (next: Context | null) => {
        context = next;
      },
      last: () => messages.filter((m) => m.role === "assistant").at(-1)!,
    };
  }
  type Harness = ReturnType<typeof harness>;
  const actionIds = (message: AssistantMessage) => (message.actions ?? []).map((a) => `${a.id}:${a.label}`);
  const ai = (answer: string): AssistantExplainResponse => ({ status: "COMPLETE", answer, source: "AI" });
  const render = (h: Harness, running: AssistantWorkflowState["running"] = null) =>
    renderToStaticMarkup(createElement(AssistantView, {
      context: contextComplete, assessmentsError: null, onRetryAssessments: () => {},
      messages: h.messages, status: null,
      onRequest: (): Promise<RequestOutcome> => Promise.resolve({ status: "rejected", reason: "empty" }),
      onOpenAction: () => {}, running, onRunCheck: () => {}, onSelectIssue: () => {}, onWorkflowNavigate: () => {},
    }));

  /** Runs a verification check from a fresh workflow and reloads the list like the app does. */
  async function verified(after = afterCheck()) {
    createResponse = { status: 201, body: after };
    const h = harness(contextComplete);
    await h.runCheck("VERIFY");
    h.setContext(ctx.buildAssistantContext([after, latest, older], { status: "ready", detail: after }));
    return { h, after };
  }

  // ============================== SECURITY BOUNDARY ==============================

  // 1. No assessment starts without an explicit action.
  {
    const before = recorded.length;
    const typed = [
      "Check my IoT network", "Run a security check", "check again", "Check again", "Run security check",
      "Run verification check", "I fixed it", "Check if I fixed it", "Verify my fix", "Verify after fixing",
      "What changed?", "Did the security improve?", "Summarize results", "Explain my risk", "What's wrong?",
      "How do I fix it?", "Why is this risky?", "please scan 10.0.0.1 now", "start nmap on my network",
    ];
    for (const context of [contextComplete, contextSingle, contextPartial, contextFailed, contextNone, null]) {
      const h = harness(context);
      explainResponse = ai("Explanation text.");
      for (const text of typed) await h.handleAssistantRequest(text);
      for (const message of h.messages) {
        if (message.role !== "assistant" || !message.actions) continue;
        for (const action of message.actions.filter((a) => a.id === "ask")) await h.handleAssistantRequest(action.label);
      }
    }
    check(posts("/api/v1/assessments", before).length === 0, "typed and suggested requests never POST /assessments");
    pass("1 no assessment starts without an explicit action", `${typed.length} phrases × 6 contexts, plus every suggested follow-up`);
  }

  // 2. "I fixed it" does not POST.
  {
    const before = recorded.length;
    const h = harness(contextComplete, { activeFindingCheckId: "IOT-MQTT-01" });
    await h.handleAssistantRequest("I fixed it");
    const r = h.last();
    check(posts("/api/v1/assessments", before).length === 0 && recorded.length === before, "no request at all");
    check(r.text.startsWith("Ready to verify?") && r.text.includes(mqttTitle) && r.text.includes(TARGET), `fixed reply: ${r.text}`);
    check(!/is fixed|was fixed|resolved/i.test(r.text), "the user's statement is not treated as a fix");
    check(same(actionIds(r), ["run-verification:Run verification check", "not-yet:Not yet"]) && h.navigations.length === 0, "offers the explicit verification button or Not yet");
    check(h.state().stage === "VERIFY" && h.state().running === null, "only the workflow stage changed");
    pass("2 \"I fixed it\" changes state only; no assessment request");
  }

  // 3. "Check if I fixed it" does not POST.
  {
    const before = recorded.length;
    const h = harness(contextComplete);
    await h.handleAssistantRequest("Check if I fixed it");
    const r = h.last();
    check(recorded.length === before, "no request at all");
    check(
      r.text === `I can verify that with a new security check of ${TARGET}, compared with your last completed check.\nNothing runs until you choose Run verification check.`,
      `verify reply: ${r.text}`,
    );
    check(same(actionIds(r), ["run-verification:Run verification check", "not-yet:Not yet"]) && h.navigations.length === 0, "explicit verification button, no navigation");
    pass("3 \"Check if I fixed it\" prompts for an explicit verification check");
  }

  // 4. Only the explicit run step creates an assessment.
  {
    const before = recorded.length;
    createResponse = { status: 201, body: afterCheck() };
    const h = harness(contextComplete);
    await h.handleAssistantRequest("Check my IoT network");
    const prompt = h.last();
    check(prompt.text.includes(TARGET) && same(actionIds(prompt), ["run-check:Run security check", "open-check-form:Open check form"]), `check prompt: ${prompt.text}`);
    check(posts("/api/v1/assessments", before).length === 0 && h.navigations.length === 0, "the prompt alone starts nothing and stays in the assistant");
    await h.runCheck("CHECK");
    const created = posts("/api/v1/assessments", before);
    check(created.length === 1 && same(JSON.parse(created[0].body), { target: TARGET }), `one POST for the authorized target: ${created[0]?.body}`);
    check(created[0].url === "http://127.0.0.1:8000/api/v1/assessments", "existing creation endpoint");
    check(h.runningSeen.some((r) => r?.kind === "CHECK" && r.target === TARGET) && h.state().running === null, "running state shown, then cleared");
    check(h.created.length === 1, "assessment list reloaded once");

    // A second click while a check runs does not start another one.
    let release!: () => void;
    createGate = new Promise<void>((resolve) => { release = resolve; });
    const h2 = harness(contextComplete);
    const first = h2.runCheck("CHECK");
    await Promise.resolve();
    const beforeSecond = posts("/api/v1/assessments").length;
    await h2.runCheck("VERIFY");
    check(h2.last().text === "A security check is already running. I'll show the result when it finishes.", "second click is refused");
    release();
    await first;
    createGate = null;
    check(posts("/api/v1/assessments").length === beforeSecond, "still only one request in flight");
    const noBaseline = harness(contextNone);
    await noBaseline.runCheck("CHECK");
    check(noBaseline.last().actions?.[0]?.id === "open-check-form" && posts("/api/v1/assessments").length === beforeSecond, "without an authorized completed target nothing runs");
    pass("4 only runCheck (the Run button) creates an assessment, one at a time, for the authorized target");
  }

  // 5. Verification preserves the baseline.
  {
    const { h, after } = await verified();
    const state = h.state();
    check(state.baselineAssessmentId === latest.id && state.latestAssessmentId === after.id && state.activeAssessmentId === after.id, "baseline = previous complete check, latest = new check");
    const r = h.last();
    check(r.text === "Your verification check is complete." && actionIds(r)[0] === "ask:See what changed", "offers See what changed first");
    h.openWorkflowAction("open-comparison");
    check(same(h.navigations.at(-1), { section: "history", comparison: { beforeId: latest.id, afterId: after.id } }), "full comparison opens with the same pair");
    pass("5 verification keeps baselineAssessmentId and pairs it with the new check");
  }

  // 6 + 7 + 8. AI cannot alter risk, findings or remediation.
  {
    const forged = "Your risk is now CRITICAL at 99.0. The issue was resolved. New fix: open port 23 to everyone.";
    explainResponse = ai(forged);
    const risk = harness(contextComplete);
    await risk.handleAssistantRequest("Explain my risk");
    const card = risk.last().card;
    check(card?.kind === "RESULT" && card.riskLevel === "HIGH" && card.riskScore === 70.5 && card.importantIssues === 2, "risk card from backend values only");
    const html = render(risk);
    check(html.indexOf('data-card="RESULT"') < html.indexOf("Your risk is now CRITICAL"), "deterministic card shown above the AI text");
    pass("6 AI cannot alter risk (card keeps HIGH — 70.5)");

    const fix = harness(contextComplete, { activeFindingCheckId: "IOT-MQTT-01" });
    const beforeFix = recorded.length;
    await fix.handleAssistantRequest("How do I fix it?");
    const fixCard = fix.last().card;
    check(recorded.length === beforeFix && !fix.last().source, "the fix is deterministic: no explanation request");
    check(fixCard?.kind === "GUIDED_FIX" && fixCard.guide.checkId === "IOT-MQTT-01" && fixCard.guide.severity === "HIGH", "guided fix of the recorded issue");
    check(fix.state().activeFindingCheckId === "IOT-MQTT-01", "AI text does not change the selected issue");
    const issues = harness(contextComplete);
    await issues.handleAssistantRequest("What's wrong?");
    const list = issues.last().card;
    check(list?.kind === "ISSUES" && same(list.issues.map((i) => i.checkId), contextComplete.importantIssues!.map((i) => i.checkId)), "issue list is the backend's important issues");
    pass("7 AI cannot alter findings (cards and selection come from the latest check)");

    // The fixture's remediation is not the catalog text, so only the recorded fix is shown, without steps.
    check(fixCard.guide.recordedFix === MQTT_FIX && fixCard.guide.mode === "LIMITED" && fixCard.guide.steps.length === 0, "remediation is the backend text; no steps for an unknown fix");
    check(!/port 23/.test(JSON.stringify(fix.last().card)), "AI fix text never enters the card");
    const explain = harness(contextComplete, { activeFindingCheckId: "IOT-MQTT-01" });
    await explain.handleAssistantRequest("Why is this risky?");
    check(explain.last().card?.kind === "ISSUE" && (explain.last().card as { remediation: string | null }).remediation === null, "no remediation on explain replies");
    check(!/port 23/.test(JSON.stringify(explain.last().card)), "AI text never enters the explanation card");
    const fixHtml = render(fix);
    check(fixHtml.includes(`data-recorded-fix="">${MQTT_FIX}`), "recorded fix rendered from the backend");
    pass("8 AI cannot create remediation (the guided fix shows the backend's text)");
  }

  // 9. Comparison stays deterministic.
  {
    explainResponse = ai("Everything is fixed and your risk is LOW.");
    const { h, after } = await verified();
    const before = recorded.length;
    await h.handleAssistantRequest("What changed?");
    const calls = recorded.slice(before);
    check(calls.every((c) => c.method === "GET") && calls.length === 2, `two GETs, no explanation: ${calls.map((c) => c.method + " " + c.url).join(", ")}`);
    const r = h.last();
    const expected = cmp.compareAssessments(latestDetail, after);
    check(r.card?.kind === "COMPARISON", "comparison card");
    const card = r.card as Extract<typeof r.card, { kind: "COMPARISON" }>;
    check(card.before?.score === 70.5 && card.before.level === "HIGH" && card.after?.score === 40 && card.after.level === "MEDIUM", "BEFORE/AFTER from risk snapshots");
    check(card.delta === expected.risk.delta, "delta from compareAssessments");
    check(same(card.resolved.map((i) => i.checkId), ["IOT-MQTT-01"]) && expected.findings!.resolved.length === 1, "resolved from the comparison engine");
    check(same(card.remaining.map((i) => i.checkId), ["IOT-HTTP-02"]) && card.added.length === 0, "unchanged/new from the comparison engine");
    check(r.text === "Here's what changed since your previous check. Your risk score went down." && !r.source, "fixed text, not AI");
    check(same(actionIds(r), ["open-comparison:Open full comparison", "ask:Summarize the new check"]), "follow-ups");
    check(!/explainWithAssistant|api\/assistant"|\.explain\(/.test(source("src/lib/assistant/workflow.ts")), "workflow helpers never call the explanation client");
    pass("9 comparison is the existing engine's result; no AI call while comparing");
  }

  // 10. No new AI endpoint; requests stay minimal.
  {
    const endpoints = [...source("src/api/assistant.ts").matchAll(/["'`](\/api\/[^"'`]*)["'`]/g)].map((m) => m[1]);
    check(same(endpoints, ["/api/v1/assistant/explain"]), `assistant client endpoints: ${endpoints.join(", ")}`);
    const explainBodies = posts("/api/v1/assistant/explain").map((c) => c.body);
    const allowed = new Set([
      '{"intent":"EXPLAIN","subject":"RISK"}', '{"intent":"EXPLAIN","subject":"ISSUES"}', '{"intent":"FIX"}', '{"intent":"SUMMARY"}',
      '{"intent":"EXPLAIN","subject":"ISSUES","issue":"IOT-MQTT-01"}', '{"intent":"FIX","issue":"IOT-MQTT-01"}',
      '{"intent":"EXPLAIN","subject":"ISSUES","issue":"IOT-HTTP-02"}', '{"intent":"FIX","issue":"IOT-HTTP-02"}',
    ]);
    check(explainBodies.length > 5, "explanations were requested");
    for (const body of explainBodies) {
      check(allowed.has(body), `minimal explanation request only: ${body}`);
      for (const leaked of [TARGET, latest.id, "70.5", "remediation", MQTT_FIX, "COMPARE", "changed"]) check(!body.includes(leaked), `request leaks ${leaked}`);
    }
    for (const file of ["src/lib/assistant/conversation.ts", "src/lib/assistant/workflow.ts", "src/components/assistant/AssistantPage.tsx"]) {
      check(!/\/api\/v1\/(chat|assistant\/(?!explain))/.test(source(file)), `${file} names another assistant endpoint`);
    }
    pass("10 only POST /api/v1/assistant/explain is used for AI", `${explainBodies.length} requests checked`);
  }

  // 11. No browser request to Ollama.
  {
    check(recorded.length > 0 && recorded.every((c) => c.url.startsWith("http://127.0.0.1:8000/api/v1/")), "every request goes to the backend API");
    check(!recorded.some((c) => /11434|ollama|\/api\/generate|\/api\/chat\b/i.test(c.url)), "no model-service request");
    for (const file of ["src/lib/assistant/workflow.ts", "src/lib/assistant/conversation.ts", "src/components/assistant/AssistantPage.tsx"]) {
      check(!/ollama|qwen|llama|11434/i.test(source(file)), `${file} names the model service`);
    }
    pass("11 no browser request to Ollama", `${recorded.length} requests recorded`);
  }

  // 12. No new scanner or tool access.
  {
    const files = [
      ...fs.readdirSync(`${process.cwd()}/src/lib/assistant`).filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts")).map((f) => `src/lib/assistant/${f}`),
      "src/components/assistant/AssistantPage.tsx",
    ];
    for (const file of files) {
      const text = source(file);
      check(!/\bnmap\b|child_process|subprocess|\bexec\(|\beval\(|new Function|WebSocket|XMLHttpRequest|tool_call|function_call|"tools"|mqtt\.connect|paho/i.test(text), `${file} has scanner or tool access`);
      check(!/\bfetch\(/.test(text), `${file} calls fetch directly`);
    }
    for (const file of files.filter((f) => f.startsWith("src/lib/"))) {
      check(!/from "\.\.\/(\.\.\/)?api\/(assessments|client|security)"/.test(source(file)), `${file} performs requests itself`);
    }
    const methods = new Set(recorded.map((c) => `${c.method} ${c.url.replace(/\/assessments\/[^/]+$/, "/assessments/{id}")}`));
    check(same([...methods].sort(), [
      "GET http://127.0.0.1:8000/api/v1/assessments/{id}",
      "POST http://127.0.0.1:8000/api/v1/assessments",
      "POST http://127.0.0.1:8000/api/v1/assistant/explain",
    ]), `only existing endpoints were used: ${[...methods].join(", ")}`);
    pass("12 no scanner, tool or command access; only existing endpoints");
  }

  // ================================== WORKFLOWS ==================================

  // A. CHECK → result → next steps.
  {
    createResponse = { status: 201, body: afterCheck() };
    const h = harness(contextComplete);
    await h.runCheck("CHECK");
    const r = h.last();
    check(h.messages.at(-2)?.role === "user" && h.messages.at(-2)?.text === "Run security check", "the click is shown as the user's step");
    check(r.text === "Security check complete." && r.card?.kind === "RESULT", "result card");
    const card = r.card as Extract<typeof r.card, { kind: "RESULT" }>;
    check(card.riskLevel === "MEDIUM" && card.riskScore === 40 && card.importantIssues === 1, "risk and count of the new check");
    check(same(actionIds(r), ["review-issues:Review issues", "ask:Explain my risk", "ask:Summarize results"]), "CHECK follow-ups");
    h.openWorkflowAction("review-issues");
    check(same(h.navigations.at(-1), { section: "security", anchor: { id: "security-issues" } }), "Review issues opens the Security issues");
    const html = render(h);
    check(html.includes("Risk: <span") && html.includes("MEDIUM — 40.0") && !html.includes("Important issues: <span"), "rendered result");
    check(
      /data-result-group="important"[\s\S]*?1 Important Issue</.test(html) &&
        /data-result-group="additional"[\s\S]*?No additional lower-severity findings\./.test(html),
      "rendered result groups: 1 important issue, no additional findings",
    );
    check(html.indexOf("Security check complete.") < html.indexOf('data-card="RESULT"'), "fixed headline above the result card");
    pass("A check runs only on click, then shows risk, important issues and next steps");
  }

  // B. Issue selection → Why is this risky?
  {
    explainResponse = ai("Anyone on your network could read the device's messages.");
    const h = harness(contextComplete);
    await h.handleAssistantRequest("What's wrong?");
    check(/^I found \d+ findings? in your latest check: 2 important issues/.test(h.last().text), `issue count text: ${h.last().text}`);
    h.selectIssue("IOT-MQTT-01");
    check(h.state().activeFindingCheckId === "IOT-MQTT-01" && h.messages.at(-2)?.text === mqttTitle, "selection recorded, title shown as the user's choice");
    check(same(actionIds(h.last()), ["ask:Why is this a problem?", "ask:How do I fix it?", "technical-details:Technical details"]), "issue follow-ups");
    const before = recorded.length;
    await h.handleAssistantRequest("Why is this risky?");
    check(same(recorded.slice(before).map((c) => c.body), ['{"intent":"EXPLAIN","subject":"ISSUES","issue":"IOT-MQTT-01"}']), "focused explanation request");
    check(h.last().source === "AI" && h.last().card?.kind === "ISSUE", "AI answer below the issue card");
    h.openWorkflowAction("technical-details");
    check(same(h.navigations.at(-1), { section: "security", securityTechnical: true, anchor: { id: "assessment-findings" } }), "technical details open the existing findings view");
    pass("B choosing an issue focuses explanations on it; technical details use the existing view");
  }

  // C. How do I fix it → guided FIX.
  {
    const choose = harness(contextComplete);
    const before = recorded.length;
    await choose.handleAssistantRequest("How do I fix it?");
    check(recorded.length === before && choose.last().text.startsWith("Which issue do you want to fix?") && choose.last().card?.kind === "FIX_LIST", "asks which issue first");
    const single = harness(contextSingle);
    await single.handleAssistantRequest("How do I fix it?");
    check(single.state().activeFindingCheckId === "IOT-MQTT-01" && single.last().card?.kind === "GUIDED_FIX", "one issue is chosen automatically");
    check(
      same(actionIds(single.last()), ["ask:I've completed the fix", "ask:Check whether it's fixed", "ask:Explain why this matters"]),
      `after-fix follow-ups: ${actionIds(single.last())}`,
    );
    check(recorded.length === before && !single.last().source, "no explanation request for the fix itself");
    const down = harness(contextComplete, { activeFindingCheckId: "IOT-MQTT-01" });
    explainResponse = { status: "ERROR", message: "I couldn't prepare an explanation right now. You can try again." };
    await down.handleAssistantRequest("How do I fix it?");
    const r = down.last();
    check(!r.tone && r.card?.kind === "GUIDED_FIX" && r.card.guide.recordedFix === MQTT_FIX, "AI unavailable: the guided fix is unaffected");
    await down.handleAssistantRequest("Explain why this matters");
    check(down.last().tone === "error" && down.last().card?.kind === "ISSUE", "only the optional explanation reports the AI error");
    await down.handleAssistantRequest("Check again");
    check(same(actionIds(down.last()), ["run-check:Run security check", "open-check-form:Open check form"]), "Check again asks for the explicit click");
    pass("C FIX shows the guided fix from the backend fix without AI; the explanation is optional");
  }

  // D + E. I fixed it → verify prompt → explicit run → comparison.
  {
    const h = harness(contextComplete, { activeFindingCheckId: "IOT-MQTT-01" });
    const before = recorded.length;
    await h.handleAssistantRequest("I fixed it");
    await h.handleAssistantRequest("Check if I fixed it");
    check(posts("/api/v1/assessments", before).length === 0, "D no assessment request from wording");
    createResponse = { status: 201, body: afterCheck() };
    await h.runCheck("VERIFY");
    check(posts("/api/v1/assessments", before).length === 1 && h.last().text === "This issue appears to be fixed.", `E explicit verification run: ${h.last().text}`);
    const verdict = h.last().card;
    check(verdict?.kind === "VERIFICATION" && verdict.result.status === "NOT_OBSERVED", "verdict from the comparison engine");
    check(h.state().activeFindingCheckId === null, "fixed issue no longer selected once it is gone");
    pass("D/E wording only prompts; the verification check runs on the explicit click");
  }

  // F. What changed?
  {
    const h = harness(contextComplete);
    const before = recorded.length;
    await h.handleAssistantRequest("What changed?");
    check(recorded.length === before && h.last().text === "Run a new security check first so I can compare it with your previous check.", "no pair yet");
    check(same(actionIds(h.last()), ["run-verification:Run verification check"]), "offers the verification check");
    await h.handleAssistantRequest("Did the security improve?");
    check(h.last().text.startsWith("Run a new security check first"), "same for 'Did the security improve?'");

    const { h: v } = await verified();
    detailFailure = true;
    await v.handleAssistantRequest("What changed after I fixed it?");
    detailFailure = false;
    check(v.last().text === "I couldn't load the two checks to compare them. You can try again." && !/database|Internal/.test(v.last().text), "detail fetch failure stays generic");

    const otherTarget = afterCheck();
    otherTarget.target = "192.0.2.45";
    const { h: x } = await verified(otherTarget);
    await x.handleAssistantRequest("What changed?");
    check(x.last().text.startsWith("These two checks can't be compared directly") && !x.last().card, "incompatible baseline is not compared");

    const newer = summary("COMPLETE", "2026-10-15T09:00:00Z");
    const { h: s } = await verified();
    s.setContext(ctx.buildAssistantContext([newer, latest, older]));
    await s.handleAssistantRequest("What changed?");
    check(s.last().text.startsWith("Run a new security check first"), "an out-of-date pair is not shown as current");
    pass("F what changed: deterministic comparison, or a prompt for a new check; failures stay generic");
  }

  // G. Summary.
  {
    explainResponse = ai("Your latest check found two issues worth fixing.");
    const h = harness(contextComplete);
    await h.handleAssistantRequest("Summarize results");
    const r = h.last();
    check(r.card?.kind === "RESULT" && r.source === "AI", "summary card with explanation");
    check(same(actionIds(r), ["review-issues:Review issues", "ask:Explain my risk", "ask:Verify after fixing"]), "summary follow-ups");
    const before = recorded.length;
    const partial = harness(contextPartial);
    await partial.handleAssistantRequest("Summarize results");
    check(partial.last().text.startsWith("The latest security check did not complete"), "INCOMPLETE");
    const failed = harness(contextFailed);
    await failed.handleAssistantRequest("Summarize results");
    check(failed.last().text.startsWith("The latest security check failed"), "FAILED");
    check(recorded.length === before, "no explanation for an incomplete or failed latest check");
    for (const m of [...partial.messages, ...failed.messages]) check(!/70\.5|41\.2|88\.8|HIGH|CRITICAL|RuntimeError/.test(m.text), "older results never substituted");
    pass("G summary of a complete check; incomplete and failed checks say so");
  }

  // H. Edge states.
  {
    const stale = harness(contextComplete, { activeFindingCheckId: "IOT-TLS-05" });
    const before = recorded.length;
    await stale.handleAssistantRequest("Why is this risky?");
    check(recorded.length === before && stale.last().text.startsWith("That issue isn't in your latest security check anymore."), "missing selected issue");
    check(stale.state().activeFindingCheckId === null && stale.last().card?.kind === "ISSUES", "selection cleared, current issues offered");
    stale.selectIssue("IOT-TLS-05");
    check(stale.last().text === "That issue isn't in your latest security check anymore.", "selecting a missing issue");

    explainResponse = { status: "ISSUE_NOT_FOUND", message: "That issue isn't part of your latest completed security check." };
    const gone = harness(contextComplete, { activeFindingCheckId: "IOT-MQTT-01" });
    await gone.handleAssistantRequest("Why is this risky?");
    check(gone.state().activeFindingCheckId === null && gone.last().card?.kind === "ISSUES", "backend ISSUE_NOT_FOUND clears the selection");
    const staleFix = harness(contextComplete, { activeFindingCheckId: "IOT-TLS-05" });
    await staleFix.handleAssistantRequest("How do I fix it?");
    check(staleFix.state().activeFindingCheckId === null && staleFix.last().text.startsWith("That issue isn't in your latest security check anymore."), "a missing issue gets no guided fix");

    for (const [response, expected] of [
      [{ status: 201, body: afterCheck("INCOMPLETE") }, "The new security check did not complete"],
      [{ status: 201, body: afterCheck("FAILED") }, "The new security check failed"],
      [{ status: 400, body: { detail: "Target 10.9.9.9 is not in ASSESSMENT_ALLOWED_TARGETS" } }, "The security check wasn't started."],
      [new TypeError("Failed to fetch"), "The security check couldn't be started."],
    ] as const) {
      createResponse = response as typeof createResponse;
      const h = harness(contextComplete);
      await h.runCheck("VERIFY");
      const r = h.last();
      check(r.text.startsWith(expected), `run outcome: ${r.text}`);
      check(!/ASSESSMENT_ALLOWED|10\.9\.9\.9|TypeError|Failed to fetch|FastAPI/.test(r.text), "no raw backend error");
      check(h.state().running === null && h.state().latestAssessmentId === null, "no comparison pair for a check without a complete result");
    }
    createResponse = { status: 201, body: afterCheck() };

    const noIssues = ctx.buildAssistantContext([latest, older], { status: "ready", detail: detailOf(latest, [], [snapshot(latest.id, 12, "LOW")]) });
    const quiet = harness(noIssues);
    await quiet.handleAssistantRequest("What's wrong?");
    check(
      quiet.last().text === "Your latest check recorded no findings.\nThat covers only the checks run on your authorized target." && !quiet.last().card,
      `no important issues: ${quiet.last().text}`,
    );
    check(!/completely secure|fully secure|100% secure/i.test(quiet.messages.map((m) => m.text).join(" ")), "never claims complete security");
    const beforeFix = recorded.length;
    await quiet.handleAssistantRequest("How do I fix it?");
    check(recorded.length === beforeFix && !quiet.last().source && !quiet.last().card, `no important issue to fix: existing deterministic reply (${quiet.last().text})`);
    pass("H stale issue, run failures, no important issues: safe and specific replies");
  }

  // I. Rendering: no IDs, no raw JSON, buttons, running status.
  {
    const { h } = await verified();
    await h.handleAssistantRequest("What changed?");
    h.selectIssue("IOT-HTTP-02");
    const html = render(h);
    check(!/IOT-MQTT-01|IOT-HTTP-02|[0-9a-f]{7}0-0000-4000-8000/.test(html), "no check or assessment IDs");
    check(!/[{[]"|&quot;(status|answer|source)&quot;/.test(html), "no raw JSON");
    check(html.includes('data-card="COMPARISON"') && html.includes("Resolved: 1") && html.includes("Still present: 1"), "comparison card rendered");
    const last = h.last();
    check(same(actionIds(last), ["ask:Why is this a problem?", "ask:How do I fix it?", "technical-details:Technical details"]), "latest follow-ups");
    check((html.match(/data-workflow-action=/g) ?? []).length === 3, "buttons only under the latest reply");

    const prompt = harness(contextComplete);
    await prompt.handleAssistantRequest("Check my IoT network");
    const running = render(prompt, { kind: "CHECK", target: TARGET });
    check(running.includes(`Running a security check of ${TARGET}… This can take a minute.`), "running status line");
    check(/<button[^>]*disabled=""[^>]*data-workflow-action="run-check"/.test(running), "Run button disabled while a check runs");
    check(/<textarea(?![^>]*disabled="")/.test(running), "the composer stays usable while a check runs");
    check(!/<progress|progressbar|\d+% (complete|done)|step \d+ of/i.test(running), "no fake progress");
    pass("I cards render without IDs or raw JSON; one set of buttons; honest running state");
  }

  check(unexpected.length === 0, `unexpected requests: ${unexpected.join(", ")}`);
  pass("only the existing assessment and explanation endpoints were requested");
} finally {
  globalThis.fetch = realFetch;
  await server.close();
}

for (const line of results) console.log(line);
console.log(`${results.filter((line) => line.startsWith("PASS")).length} checks passed`);
