/**
 * Checks for the guided fix (user remediation experience): what is wrong,
 * where to fix it, numbered steps, what it may affect, how to tell it worked,
 * the explicit verification check and the before/after verdict. Findings
 * carry the backend catalog's remediation text (scanner/core/catalog.py), so
 * the step-by-step guides are exercised; changed or missing remediation must
 * fall back to the recorded fix only. globalThis.fetch is a recorder that
 * answers only POST /api/v1/assistant/explain, POST /api/v1/assessments and
 * GET /api/v1/assessments/{id} from fixtures and fails on anything else.
 *
 * Run from frontend/:  node src/lib/assistant/guidedFix.test.ts
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
import type { AssistantIssue } from "./context.ts";
import type { AssistantMessage, RequestOutcome } from "./conversation.ts";
import type { GuidedRemediation } from "./guidedFix.ts";
import type { AssistantWorkflowState } from "./workflow.ts";

declare const process: { cwd(): string };

type ViteServer = {
  ssrLoadModule(url: string): Promise<Record<string, unknown>>;
  close(): Promise<void>;
};
type ConversationLib = typeof import("./conversation.ts");
type ContextLib = typeof import("./context.ts");
type WorkflowLib = typeof import("./workflow.ts");
type GuidedFixLib = typeof import("./guidedFix.ts");
type AssistantApi = typeof import("../../api/assistant.ts");
type AssessmentsApi = typeof import("../../api/assessments.ts");
type PageModule = typeof import("../../components/assistant/AssistantPage.tsx");
type CardModule = typeof import("../../components/assistant/GuidedFix.tsx");
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
  { check_id: "NET-03", port: 23, status: "EVALUATED" },
];
/** Remediation text of the backend catalog, verbatim. */
const CATALOG_FIX: Record<string, string> = {
  "IOT-MQTT-01": "Set allow_anonymous false, configure a password_file, and enforce topic ACLs for each client.",
  "IOT-MQTT-02": "Enable an MQTT TLS listener (port 8883) with a valid certificate and move clients to it.",
  "NET-03": "Disable Telnet and use SSH with key-based authentication if remote administration is required.",
};
const ALL_CATALOG_FIXES: Record<string, string> = {
  ...CATALOG_FIX,
  "NET-01": "Confirm the service is required; close or firewall it otherwise.",
  "NET-02": "Disable services that are not required for the device's function.",
  "NET-04": "Disable FTP or replace it with SFTP/FTPS restricted to authorized hosts.",
  "NET-06": "Verify the administrative service is required and restrict it to management hosts.",
  "IOT-MQTT-03": "Restrict $SYS topic access to administrative clients via ACLs.",
  "WEB-01": "Serve the interface over HTTPS and redirect plaintext HTTP.",
  "WEB-02": "Add the missing security headers in the web server configuration.",
  "WEB-03": "Suppress version details in the Server / X-Powered-By headers.",
  "TLS-01": "No action required; certificate and protocol checks are reported separately.",
  "TLS-02": "Renew the certificate and deploy it to the service.",
  "TLS-03": "Disable TLS 1.1 and older; allow TLS 1.2 and TLS 1.3 only.",
  "TLS-04": "Use a certificate issued by a CA trusted by the clients and matching the service address.",
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
    metadata: { check_catalog_version: "1", ports: [23, 1883, 8883], checks_evaluated: COVERAGE } as AssessmentSummary["metadata"],
    created_at: startedAt,
    evidence_count: 2,
    finding_count: 2,
    highest_risk: null,
    highest_risk_level: null,
    ...extra,
  };
}
function evidence(assessmentId: string, port: number, service: string): AssessmentEvidence {
  return {
    id: uuid("e"),
    assessment_id: assessmentId,
    target: TARGET,
    port,
    check_type: "NMAP_PORT",
    result: "OPEN",
    evidence_source: "NMAP",
    observation: { port, state: "open", reason: "syn-ack", protocol: "tcp", service_name: service, product: null, version: null },
    observed_at: "2026-10-13T19:58:20Z",
  };
}
function finding(
  assessmentId: string,
  findingId: string,
  severity: AssessmentFinding["severity"],
  title: string,
  port: number,
  remediation: string | null = CATALOG_FIX[findingId] ?? null,
): AssessmentFinding {
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
    score_version: "IoT-RISK-v1",
    base_severity: null,
    context_score: null,
    factor_contributions: {},
    context_inputs: {},
    created_at: "2026-10-13T19:58:40Z",
  };
}
function detail(s: AssessmentSummary, findings: AssessmentFinding[], score: number, level: RiskSnapshot["risk_level"]): AssessmentDetail {
  return {
    ...s,
    evidence: [evidence(s.id, 1883, "mosquitto version 2.1.2"), evidence(s.id, 23, "telnet")],
    findings,
    risk_snapshots: [snapshot(s.id, score, level)],
  };
}

const older = summary("COMPLETE", "2026-10-12T08:00:00Z", { highest_risk: 41.2, highest_risk_level: "MEDIUM" });
const latest = summary("COMPLETE", "2026-10-13T19:58:00Z", { highest_risk: 70.5, highest_risk_level: "HIGH" });
const latestDetail = detail(
  latest,
  [
    finding(latest.id, "IOT-MQTT-01", "HIGH", "Anonymous MQTT access", 1883),
    finding(latest.id, "IOT-MQTT-02", "MEDIUM", "MQTT without TLS", 1883),
  ],
  70.5,
  "HIGH",
);
const single = summary("COMPLETE", "2026-10-13T19:58:00Z", { highest_risk: 70.5, highest_risk_level: "HIGH" });
const singleDetail = detail(single, [finding(single.id, "IOT-MQTT-01", "HIGH", "Anonymous MQTT access", 1883)], 70.5, "HIGH");
const tied = summary("COMPLETE", "2026-10-13T19:58:00Z", { highest_risk: 70.5, highest_risk_level: "HIGH" });
const tiedDetail = detail(
  tied,
  [finding(tied.id, "IOT-MQTT-01", "HIGH", "Anonymous MQTT access", 1883), finding(tied.id, "NET-03", "HIGH", "Telnet exposed", 23)],
  70.5,
  "HIGH",
);

/** A verification check run after the broker fix: only the encryption issue remains. */
function afterFixed(): AssessmentDetail {
  const s = summary("COMPLETE", "2026-10-14T09:00:00Z", { highest_risk: 55.0, highest_risk_level: "MEDIUM" });
  return detail(s, [finding(s.id, "IOT-MQTT-02", "MEDIUM", "MQTT without TLS", 1883)], 55.0, "MEDIUM");
}
/** A verification check run when nothing was changed. */
function afterUnchanged(): AssessmentDetail {
  const s = summary("COMPLETE", "2026-10-14T09:00:00Z", { highest_risk: 70.5, highest_risk_level: "HIGH" });
  return detail(
    s,
    [finding(s.id, "IOT-MQTT-01", "HIGH", "Anonymous MQTT access", 1883), finding(s.id, "IOT-MQTT-02", "MEDIUM", "MQTT without TLS", 1883)],
    70.5,
    "HIGH",
  );
}

// ---- fetch recorder -----------------------------------------------------------------
type Recorded = { url: string; method: string; body: string };
const recorded: Recorded[] = [];
const unexpected: string[] = [];
let explainResponse: AssistantExplainResponse = { status: "COMPLETE", answer: "Model text for the test.", source: "AI" };
let createResponse: { status: number; body: unknown } = { status: 201, body: afterFixed() };
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
  const wf = await load<WorkflowLib>("/src/lib/assistant/workflow.ts");
  const gf = await load<GuidedFixLib>("/src/lib/assistant/guidedFix.ts");
  const assistantApi = await load<AssistantApi>("/src/api/assistant.ts");
  const assessmentsApi = await load<AssessmentsApi>("/src/api/assessments.ts");
  const { AssistantView } = await load<PageModule>("/src/components/assistant/AssistantPage.tsx");
  const { GuidedFixCard } = await load<CardModule>("/src/components/assistant/GuidedFix.tsx");

  for (const d of [latestDetail, singleDetail, tiedDetail]) details.set(d.id, d);
  const contextFor = (summaries: AssessmentSummary[], d: AssessmentDetail) =>
    ctx.buildAssistantContext(summaries, { status: "ready", detail: d });
  const contextComplete = contextFor([latest, older], latestDetail);
  const contextSingle = contextFor([single, older], singleDetail);
  const contextTied = contextFor([tied, older], tiedDetail);
  const issueOf = (context: Context, checkId: string) => context.importantIssues!.find((i) => i.checkId === checkId)!;
  const MQTT_TITLE = issueOf(contextComplete, "IOT-MQTT-01").title;
  const ENC_TITLE = issueOf(contextComplete, "IOT-MQTT-02").title;
  const detailFor = new Map<string, AssessmentDetail>([
    [latest.id, latestDetail],
    [single.id, singleDetail],
    [tied.id, tiedDetail],
  ]);

  function harness(initial: Context, workflow: Partial<AssistantWorkflowState> = {}) {
    let context: Context = initial;
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
      setContext: (next: Context) => {
        context = next;
      },
      last: () => messages.filter((m) => m.role === "assistant").at(-1)!,
    };
  }
  type Harness = ReturnType<typeof harness>;

  async function ask(h: Harness, text: string) {
    const outcome = await h.handleAssistantRequest(text);
    check(outcome.status === "answered", `${text}: answered`);
    const reply = h.last();
    check(reply.text !== conv.UNKNOWN_REPLY, `${text}: generic reply`);
    check(h.navigations.length === 0, `${text}: navigated`);
    return reply;
  }
  /** Asks and requires that nothing was requested at all. */
  async function askQuiet(h: Harness, text: string) {
    const before = recorded.length;
    const reply = await ask(h, text);
    check(recorded.length === before, `${text}: made ${recorded.length - before} request(s)`);
    return reply;
  }
  const guideOf = (reply: AssistantMessage): GuidedRemediation => {
    check(reply.card?.kind === "GUIDED_FIX", `guided fix card expected, got ${reply.card?.kind ?? "none"}: ${reply.text}`);
    return reply.card.guide;
  };
  const actionIds = (m: AssistantMessage) => (m.actions ?? []).map((a) => `${a.id}:${a.label}`);
  const renderCard = (guide: GuidedRemediation) => renderToStaticMarkup(createElement(GuidedFixCard, { guide, frame: "" }));
  const renderView = (h: Harness, context: Context = contextComplete) =>
    renderToStaticMarkup(
      createElement(AssistantView, {
        context,
        assessmentsError: null,
        onRetryAssessments: () => {},
        messages: h.messages,
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
  /** The card without its collapsed technical details. */
  const simpleLayer = (html: string) => html.replace(/<details data-technical=""[\s\S]*?<\/details>/g, "");
  const RAW_ID = /IOT-MQTT-0\d|NET-0\d|WEB-0\d|TLS-0\d|[0-9a-f]{7}0-0000-4000-8000|IoT-RISK|confidence|"[a-z_]+":/;
  const SUCCESS_CLAIM = /you are secure|you're secure|completely secure|fully secure|is fixed\b|was fixed|has been fixed|appears to be fixed|resolved/i;
  const ALLOWED_ACTIONS = new Set(["ask", "run-verification", "run-check", "not-yet", "guided-fix", "technical-details", "open-check-form", "open-comparison", "review-issues", "before-after", "view-results"]);

  // ================================ GUIDED FIX ================================

  // 1. FIX with one finding: the guide opens directly, step by step.
  {
    const h = harness(contextSingle);
    const reply = await askQuiet(h, "How do I fix it?");
    const guide = guideOf(reply);
    check(reply.text === `Here's how to fix “${MQTT_TITLE}”, step by step.`, reply.text);
    check(guide.checkId === "IOT-MQTT-01" && guide.severity === "HIGH" && guide.mode === "STEPS", "STEPS guide of the only issue");
    check(guide.recordedFix === CATALOG_FIX["IOT-MQTT-01"], "the recorded fix is the backend's text");
    check(guide.steps.length >= 3 && guide.steps.at(-1)!.title === gf.RUN_CHECK_STEP.title, "numbered steps ending with a new check");
    check(guide.whatIsWrong && guide.whereToFix && guide.impact && guide.verification && guide.preparation, "every section present");
    check(h.state().activeFindingCheckId === "IOT-MQTT-01" && h.state().stage === "FIX", "issue in focus");
    check(
      same(actionIds(reply), ["ask:I've completed the fix", "ask:Check whether it's fixed", "ask:Explain why this matters"]),
      `follow-ups: ${actionIds(reply)}`,
    );
    pass("1 FIX with one finding opens the guide directly");
  }

  // 2. FIX with two findings asks which one, a separate guide each.
  {
    const h = harness(contextComplete);
    const reply = await askQuiet(h, "How do I fix it?");
    check(reply.text === "Which issue do you want to fix?\nStart with the HIGH severity issue." || reply.text === "Which issue do you want to fix? Start with the HIGH severity issue.", reply.text);
    check(reply.card?.kind === "FIX_LIST" && same(reply.card.issues.map((i) => i.checkId), ["IOT-MQTT-01", "IOT-MQTT-02"]), "both issues listed");
    check(reply.card?.kind === "FIX_LIST" && reply.card.startWith === "IOT-MQTT-01", "start with the HIGH one");
    check(h.state().activeFindingCheckId === null, "nothing chosen for the user");
    const html = renderView(h);
    check((html.match(/data-guided-fix=""/g) ?? []).length === 2 && html.includes("Start guided fix"), "one Start guided fix button per issue");
    pass("2 FIX with two findings asks which issue, one guided fix per issue");
  }

  // 3. FIX with a selected finding (chosen from the list or with the button).
  {
    const h = harness(contextComplete);
    h.selectIssue("IOT-MQTT-02");
    const reply = await askQuiet(h, "How do I fix it?");
    check(guideOf(reply).checkId === "IOT-MQTT-02" && guideOf(reply).mode === "STEPS", "the selected issue's guide");
    const b = harness(contextComplete);
    await askQuiet(b, "How do I fix it?");
    const before = recorded.length;
    b.startGuidedFix("IOT-MQTT-01");
    check(recorded.length === before && guideOf(b.last()).checkId === "IOT-MQTT-01", "Start guided fix opens that issue's guide");
    check(b.messages.at(-2)?.role === "user" && b.messages.at(-2)?.text === `Show me how to fix “${MQTT_TITLE}”`, "the click is shown as the user's request");
    b.startGuidedFix("TLS-03");
    check(b.last().card?.kind !== "GUIDED_FIX" && b.state().activeFindingCheckId === null, "an issue that isn't in the latest check gets no guide");
    pass("3 FIX with a selected finding");
  }

  // 4. "it" refers to the issue in focus.
  {
    const h = harness(contextComplete);
    await ask(h, "What are these security issues?");
    await askQuiet(h, "Why does the encryption one matter?");
    check(h.state().activeFindingCheckId === "IOT-MQTT-02", "encryption issue in focus");
    const reply = await askQuiet(h, "How do I fix it?");
    check(guideOf(reply).checkId === "IOT-MQTT-02", "it = the issue in focus");
    pass("4 FIX using \"it\"");
  }

  // 5. "this" refers to the issue in focus.
  {
    const h = harness(contextComplete);
    await ask(h, "What are these security issues?");
    await askQuiet(h, "Which one is most serious?");
    const reply = await askQuiet(h, "How do I fix this?");
    check(guideOf(reply).checkId === "IOT-MQTT-01", "this = the most serious issue just named");
    const can = await askQuiet(harness(contextSingle), "How can I fix this?");
    check(guideOf(can).checkId === "IOT-MQTT-01", "How can I fix this?");
    const show = await askQuiet(harness(contextSingle), "Show me how to fix it");
    check(guideOf(show).checkId === "IOT-MQTT-01", "Show me how to fix it");
    const what = await askQuiet(harness(contextSingle), "What should I do?");
    check(guideOf(what).checkId === "IOT-MQTT-01", "What should I do?");
    pass("5 FIX using \"this\" and other fix phrasings");
  }

  // 6. "both": separate guides, never combined instructions.
  {
    const h = harness(contextComplete);
    await ask(h, "What are these security issues?");
    const reply = await askQuiet(h, "How do I fix both?");
    check(reply.text === "Fix these 2 issues one at a time. Start with the HIGH severity issue.", reply.text);
    check(reply.card?.kind === "FIX_LIST" && reply.card.issues.length === 2 && reply.card.startWith === "IOT-MQTT-01", "two separate guides");
    check(!/allow_anonymous|8883|password_file/.test(JSON.stringify(reply)), "no combined instructions");
    pass("6 FIX using \"both\" lists one guided fix per issue");
  }

  // 7. "the more serious one" / "What should I do first?".
  {
    const h = harness(contextComplete);
    await ask(h, "What are these security issues?");
    const reply = await askQuiet(h, "How do I fix the more serious one?");
    check(guideOf(reply).checkId === "IOT-MQTT-01", "the more serious one = HIGH");
    const first = await askQuiet(harness(contextComplete), "What should I do first?");
    check(guideOf(first).checkId === "IOT-MQTT-01", "What should I do first? = the HIGH issue");
    pass("7 FIX using \"the more serious one\"");
  }

  // 8. Ambiguous references ask instead of guessing.
  {
    const h = harness(contextTied);
    const reply = await askQuiet(h, "How do I fix the more serious one?");
    check(reply.card?.kind === "FIX_LIST" && reply.card.issues.length === 2 && reply.card.startWith === null, "two HIGH issues: no guess");
    check(reply.text.startsWith("Which issue do you want to fix?") && reply.text.includes("Choose one to start with."), reply.text);
    check(h.state().activeFindingCheckId === null, "nothing selected");
    const plain = await askQuiet(harness(contextComplete), "How do I fix this?");
    check(plain.card?.kind === "FIX_LIST" && plain.text.startsWith("Which issue do you want to fix?"), "\"this\" with nothing in focus asks which");
    pass("8 ambiguous reference asks for clarification");
  }

  // 9. "Where do I fix this?"
  {
    const h = harness(contextSingle);
    const reply = await askQuiet(h, "Where do I fix this?");
    check(reply.text.startsWith(`Where to fix “${MQTT_TITLE}”:`), reply.text);
    check(reply.text.includes("On the computer that runs your MQTT broker") && reply.text.includes(TARGET), "plain-language place on the scanned target");
    check(reply.text.includes("“mosquitto version 2.1.2”"), "software only as recorded by the scan");
    check(reply.text.includes("can't safely identify the exact configuration file"), "says when the exact file is unknown");
    check(!/\/etc\/|\.conf\b|[A-Z]:\\|\/var\/|\/usr\//.test(reply.text), "no invented path");
    check(same(actionIds(reply), ["ask:Show me how to fix it", "ask:What might this affect?"]), `follow-ups: ${actionIds(reply)}`);
    const setting = await askQuiet(harness(contextSingle), "Where is this setting?");
    check(setting.text === reply.text, "Where is this setting? = where");
    pass("9 \"Where do I fix this?\" names the place from recorded data only");
  }

  // 10. "What do I change?" shows the steps with the recorded setting.
  {
    const h = harness(contextSingle);
    const guide = guideOf(await askQuiet(h, "What do I change?"));
    const examples = guide.steps.flatMap((s) => (s.example ? [s.example] : []));
    check(examples.some((e) => e.current === "allow_anonymous true" && e.change === "allow_anonymous false"), "Current → Change to for anonymous access");
    check(examples.some((e) => e.change === "password_file <PATH_TO_PASSWORD_FILE>"), "password file as a placeholder");
    check(guide.steps.some((s) => /ESP32/.test(s.detail) && s.detail.includes("<MQTT_USERNAME>") && s.detail.includes("<MQTT_PASSWORD>")), "devices need credentials (placeholders)");
    const first = simpleLayer(renderCard(guide));
    check(first.includes("Step 1 of") && !first.includes("allow_anonymous false") && first.includes("Turn off anonymous access"), "one step at a time; all titles listed");
    const anonymousStep = guide.steps.findIndex((s) => s.example?.current === "allow_anonymous true");
    const html = renderCard({ ...guide, steps: guide.steps.slice(anonymousStep) });
    check(html.includes("If you see this line") && html.includes("Change it to") && html.includes("allow_anonymous false"), "config line rendered");
    pass("10 \"What do I change?\" shows only settings named by the recorded fix");
  }

  // 11. "Will this break my devices?"
  {
    const h = harness(contextSingle);
    const reply = await askQuiet(h, "Will this break my devices?");
    check(reply.text.startsWith("What changing this might affect:"), reply.text);
    check(reply.text.includes("will be refused until you give them a login") && reply.text.includes(gf.OUTCOME_NOTE), "impact and outcome note");
    check(!/completely secure|fully secure|you are secure/i.test(reply.text), "no security promise");
    const what = await askQuiet(harness(contextSingle), "What happens if I change this?");
    check(what.text === reply.text, "What happens if I change this? = impact");
    pass("11 \"Will this break my devices?\" explains the impact");
  }

  // 12. "How do I know it's fixed?"
  {
    const h = harness(contextSingle);
    const reply = await askQuiet(h, "How do I know it's fixed?");
    check(reply.text.startsWith(`How you'll know “${MQTT_TITLE}” is fixed:`) && reply.text.includes("Only a new security check can confirm it"), reply.text);
    check(actionIds(reply)[0] === "ask:Check whether it's fixed", "offers the check, never runs it");
    pass("12 \"How do I know it's fixed?\" explains verification");
  }

  // 13. "I've completed the fix" only asks; "Not yet" starts nothing.
  {
    const h = harness(contextSingle);
    await askQuiet(h, "How do I fix it?");
    const before = recorded.length;
    const reply = await askQuiet(h, "I've completed the fix");
    check(reply.text.startsWith("Ready to verify?") && reply.text.includes(MQTT_TITLE) && reply.text.includes(TARGET), reply.text);
    check(!SUCCESS_CLAIM.test(reply.text), "no claim that it's fixed");
    check(same(actionIds(reply), ["run-verification:Run verification check", "not-yet:Not yet"]), `buttons: ${actionIds(reply)}`);
    h.declineVerification();
    check(recorded.length === before && h.last().text.startsWith("No problem — nothing was started."), "Not yet starts nothing");
    check(h.state().running === null, "no check running");
    pass("13 \"I've completed the fix\" makes no assessment request");
  }

  // 14. "Check whether it's fixed" only offers the button.
  {
    const h = harness(contextSingle);
    await askQuiet(h, "How do I fix it?");
    for (const text of ["Check whether it's fixed", "Is it fixed?", "Check if I fixed it"]) {
      const reply = await askQuiet(h, text);
      check((reply.actions ?? []).some((a) => a.id === "run-verification"), `${text}: offers the run button`);
      check(!SUCCESS_CLAIM.test(reply.text.replace(/whether .* is fixed/, "")), `${text}: no claim — ${reply.text}`);
    }
    check(assessmentPosts().length === 0, "no automatic request");
    pass("14 \"Check whether it's fixed\" makes no automatic request");
  }

  // 15–17. The Run verification button: one POST, the authorized target, the latest result.
  {
    createResponse = { status: 201, body: afterFixed() };
    const h = harness(contextComplete);
    await askQuiet(h, "What are these security issues?");
    await askQuiet(h, "How do I fix the more serious one?");
    await h.handleAssistantRequest("Check 198.51.100.7 instead");
    await askQuiet(h, "I've completed the fix");
    check(assessmentPosts().length === 0, "nothing before the click");
    const from = recorded.length;
    await h.runCheck("VERIFY");
    const posts = assessmentPosts(from);
    check(posts.length === 1, `exactly one POST (${posts.length})`);
    pass("15 the Run verification button makes exactly one POST");
    check(same(JSON.parse(posts[0].body), { target: TARGET }), `authorized target only: ${posts[0].body}`);
    check(!recorded.some((call) => call.body.includes("198.51.100.7") || call.url.includes("198.51.100.7")), "a typed address is never sent");
    pass("16 verification uses the authorized target only");
    const reply = h.last();
    check(reply.text === "This issue appears to be fixed.", reply.text);
    check(reply.card?.kind === "VERIFICATION" && reply.card.result.status === "NOT_OBSERVED", "verdict from the comparison");
    const result = reply.card.result;
    check(result.checkId === "IOT-MQTT-01" && result.previousSeverity === "HIGH", "the issue being fixed");
    check(result.beforeImportant === 2 && result.afterImportant === 1 && result.noLongerObserved === 1, `before/after counts ${JSON.stringify(result)}`);
    check(actionIds(reply)[0] === "ask:View before & after", `actions: ${actionIds(reply)}`);
    const html = renderView(h);
    check(html.includes("Not observed") && html.includes("data-before-after") && html.includes("doesn&#x27;t mean every part of your network is secure"), "before/after rendered with the limit");
    check(!/you are secure|you&#x27;re secure/i.test(html), "never \"You are secure\"");
    pass("17 a successful verification reflects the latest result");
  }

  // 18. A failed verification makes no success claim.
  {
    createResponse = { status: 201, body: afterUnchanged() };
    const h = harness(contextComplete);
    h.selectIssue("IOT-MQTT-01");
    await h.runCheck("VERIFY");
    const reply = h.last();
    check(reply.text === "This issue is still present.", reply.text);
    check(reply.card?.kind === "VERIFICATION" && reply.card.result.status === "STILL_PRESENT", "still present");
    check(!SUCCESS_CLAIM.test(reply.text), "no success claim");
    check(same(actionIds(reply), ["guided-fix:View guided fix", "ask:View before & after", "ask:See technical details"]), `actions: ${actionIds(reply)}`);
    const html = renderView(h);
    check(html.includes("Still observed") && html.includes("What to check") && !/appears to be fixed|Not observed/.test(html), "what to check, no fixed claim");
    createResponse = { status: 201, body: { ...afterFixed(), status: "FAILED", findings: [], risk_snapshots: [] } };
    const failed = harness(contextComplete, { activeFindingCheckId: "IOT-MQTT-01" });
    await failed.runCheck("VERIFY");
    check(failed.last().card?.kind !== "VERIFICATION" && !SUCCESS_CLAIM.test(failed.last().text), `failed check: ${failed.last().text}`);
    pass("18 a failed verification makes no success claim");
  }

  // 19. Missing or changed remediation is never turned into steps.
  {
    const base = issueOf(contextSingle, "IOT-MQTT-01");
    const place = gf.guidePlace(base, TARGET, singleDetail);
    const missing = gf.buildGuidedRemediation({ ...base, remediation: null }, place, singleDetail);
    check(missing.mode === "LIMITED" && missing.steps.length === 0 && missing.recordedFix === null && missing.impact === null, "no recorded fix: no steps");
    check(renderCard(missing).includes(gf.NO_RECORDED_FIX), "says no fix was recorded");
    const changed = gf.buildGuidedRemediation({ ...base, remediation: "Rotate the broker credentials." }, place, singleDetail);
    check(changed.mode === "LIMITED" && changed.steps.length === 0 && changed.recordedFix === "Rotate the broker credentials.", "changed fix: shown verbatim, no steps");
    check(!/allow_anonymous|password_file/.test(JSON.stringify({ ...changed, technical: [] })), "no steps from the old text");
    const unknown: AssistantIssue = { ...base, checkId: "IOT-NEW-99", remediation: "Do the new thing.", meaning: null };
    const limited = gf.buildGuidedRemediation(unknown, gf.guidePlace(unknown, TARGET, singleDetail), singleDetail);
    check(limited.mode === "LIMITED" && limited.locationNote === gf.NO_EXACT_STEPS, "unknown check: limited");
    const html = renderCard(limited);
    for (const heading of ["I can explain what needs to change", "What to change", "Where to look", "Why I can&#x27;t give exact steps", "Next step"]) {
      check(html.includes(heading), `limited layout: ${heading}`);
    }
    const general: string[] = [];
    for (const [checkId, fix] of Object.entries(ALL_CATALOG_FIXES)) {
      const guide = gf.buildGuidedRemediation({ ...base, checkId, remediation: fix }, place, singleDetail);
      check(guide.recordedFix === fix, `${checkId}: recorded fix verbatim`);
      if (guide.mode === "LIMITED") general.push(checkId);
    }
    check(same(general.sort(), ["NET-02", "TLS-01", "WEB-02"]), `limited catalog checks: ${general}`);
    pass("19 missing remediation is not hallucinated", `limited for ${general.join(", ")}`);

    // Placeholders and settings only where the recorded fix names them; no paths, commands or values.
    const allGuides = Object.entries(ALL_CATALOG_FIXES).map(([checkId, fix]) =>
      gf.buildGuidedRemediation({ ...base, checkId, remediation: fix }, place, singleDetail),
    );
    const examples = allGuides.flatMap((g) => g.steps.flatMap((s) => (s.example ? [s.example.current ?? "", s.example.change] : []))).filter(Boolean);
    check(same(examples.sort(), ["allow_anonymous false", "allow_anonymous true", "password_file <PATH_TO_PASSWORD_FILE>"]), `config examples: ${examples}`);
    const simple = JSON.stringify(allGuides.map((g) => ({ ...g, technical: [] })));
    check(!/\/etc\/|\/var\/|\/usr\/|[A-Z]:\\\\|\.conf\b|sudo|systemctl|mosquitto_passwd|service \w+ restart|iptables|ufw|netsh/.test(simple), "no invented path or command");
  }

  // 20. AI unavailable: the guide is unaffected.
  {
    explainResponse = { status: "ERROR", message: "I couldn't prepare an explanation right now. You can try again." };
    const h = harness(contextSingle);
    const reply = await askQuiet(h, "How do I fix it?");
    check(guideOf(reply).mode === "STEPS" && !reply.tone && !reply.source, "guide without AI");
    const from = recorded.length;
    const why = await ask(h, "Explain why this matters");
    check(explainCalls(from).length === 1 && why.tone === "error", "only the optional explanation needs AI");
    check(same(actionIds(why), ["ask:I've completed the fix", "ask:Check whether it's fixed"]), `back to the fix: ${actionIds(why)}`);
    explainResponse = { status: "COMPLETE", answer: "Model text for the test.", source: "AI" };
    const ok = harness(contextSingle);
    await askQuiet(ok, "How do I fix it?");
    const explained = await ask(ok, "Explain why this matters");
    check(explained.source === "AI" && explained.card?.kind === "ISSUE" && !JSON.stringify(explained.card).includes("Model text"), "AI text stays outside the card");
    pass("20 AI unavailable is fine");
  }

  // 21–24. Rendering: technical details closed, steps one at a time, no IDs, no credential fields.
  {
    const h = harness(contextSingle);
    const guide = guideOf(await askQuiet(h, "How do I fix it?"));
    const card = renderCard(guide);
    check(/<details data-technical=""[^>]*>/.test(card) && !/<details data-technical=""[^>]*\bopen\b/.test(card), "technical details collapsed");
    check(card.includes("Check ID: IOT-MQTT-01 (HIGH)"), "IDs only inside technical details");
    pass("21 technical details are hidden by default");

    check(card.includes(`Step 1 of ${guide.steps.length}`) && /data-step-nav="back"[^>]*/.test(card) && card.includes("Next step"), "one step at a time");
    check(/<button type="button" disabled=""[^>]*data-step-nav="back"/.test(card), "Back disabled on the first step");
    const exampleCard = renderCard({ ...guide, steps: guide.steps.filter((s) => s.example) });
    const codes = exampleCard.match(/<code [^>]*>/g) ?? [];
    check(codes.length > 0 && codes.every((tag) => /\bbreak-all\b/.test(tag) && /\bwhitespace-pre-wrap\b/.test(tag)), "config lines wrap");
    const view = source("src/components/assistant/GuidedFix.tsx");
    check(!/\bw-\[\d{3,}px\]|min-w-\[\d{3,}px\]|whitespace-nowrap/.test(view), "no fixed widths that overflow a phone");
    check(/break-all/.test(view) && /break-words/.test(view) && /min-w-0/.test(view), "long values wrap");
    pass("22 no mobile overflow (layout rules; measured in the browser run)");

    const simple = simpleLayer(card);
    check(!RAW_ID.test(simple), `technical ID in the simple layer: ${RAW_ID.exec(simple)?.[0]}`);
    for (const reply of h.messages.filter((m) => m.role === "assistant")) check(!RAW_ID.test(reply.text), `ID in reply text: ${reply.text}`);
    const page = simpleLayer(renderView(h, contextSingle));
    check(!/IOT-MQTT-0\d|NET-0\d/.test(page), "no IDs in the rendered conversation");
    pass("23 no technical IDs in the simple layer");

    check(!/<input|<textarea/.test(card) && !/type="password"/.test(renderView(h, contextSingle)), "no credential fields");
    const guideText = JSON.stringify(guide.steps);
    check(guideText.includes("<MQTT_USERNAME>") && guideText.includes("<MQTT_PASSWORD>"), "credentials only as placeholders");
    check(guide.steps.some((s) => s.warning?.startsWith("Never type a real password into this assistant.")), "warns not to type a real password");
    const secret = "Hunter2-Lab-Secret";
    const from = recorded.length;
    await h.handleAssistantRequest(`My MQTT password is ${secret}`);
    check(!h.messages.some((m) => m.role === "assistant" && m.text.includes(secret)), "a typed secret is never repeated");
    check(!recorded.slice(from).some((call) => call.body.includes(secret)), "a typed secret is never sent");
    pass("24 no credentials collected");
  }

  // 25–27. Boundaries: no model calls from the browser, no automatic remediation, no tools.
  {
    check(!recorded.some((call) => /11434|ollama|qwen/i.test(`${call.url} ${call.body}`)), "no browser-to-Ollama request");
    const files = ["src/lib/assistant/guidedFix.ts", "src/components/assistant/GuidedFix.tsx"];
    for (const file of files) check(!/ollama|qwen|llama|11434/i.test(source(file)), `${file}: model reference`);
    pass("25 no browser-to-Ollama request");

    const crawlFrom = recorded.length;
    const h = harness(contextComplete);
    await askQuiet(h, "How do I fix both?");
    h.startGuidedFix("IOT-MQTT-01");
    await askQuiet(h, "Where do I fix this?");
    await askQuiet(h, "Will this break my devices?");
    await askQuiet(h, "How do I know it's fixed?");
    await askQuiet(h, "I've completed the fix");
    const seen = new Set<string>();
    for (let i = 0; i < h.messages.length && i < 200; i++) {
      const message = h.messages[i];
      if (message.role !== "assistant") continue;
      for (const action of message.actions ?? []) {
        check(ALLOWED_ACTIONS.has(action.id), `unexpected action ${action.id}`);
        check(!/automatic|apply|fix it for me|change it for me|restart (it|the)|run command/i.test(action.label), `action label: ${action.label}`);
        if (action.id === "ask" && !seen.has(action.label)) {
          seen.add(action.label);
          await h.handleAssistantRequest(action.label);
        }
      }
    }
    check(assessmentPosts(crawlFrom).length === 0, `guided follow-ups POSTed ${assessmentPosts(crawlFrom).length} time(s)`);
    check(h.state().running === null, "no check running");
    check(!/automatic/i.test(source("src/components/assistant/GuidedFix.tsx")), "no automatic fix control");
    const lib = source("src/lib/assistant/guidedFix.ts");
    check(!/from "\.\.\/\.\.\/api\/(assessments|client|security|assistant)"/.test(lib), "the guide module calls no API");
    pass("26 no automatic remediation", `${seen.size} follow-ups clicked, no request`);

    const forbidden = /child_process|subprocess|\bexec\(|\beval\(|new Function|WebSocket|XMLHttpRequest|tool_call|function_call|"tools"|mqtt\.connect|paho|\bfetch\(|nmap/;
    for (const file of files) check(!forbidden.test(source(file)), `${file}: ${forbidden.exec(source(file))?.[0]}`);
    pass("27 no shell or tool execution");
  }

  check(unexpected.length === 0, `unexpected requests: ${unexpected.join(", ")}`);
  check(!ENC_TITLE.includes("IOT-"), "titles are plain language");
  for (const line of results) console.log(line);
  console.log(`${results.length} checks passed`);
} finally {
  globalThis.fetch = realFetch;
  await server.close();
}
