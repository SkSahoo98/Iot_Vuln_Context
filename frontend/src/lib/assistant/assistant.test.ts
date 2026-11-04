/**
 * Checks for the assistant context and intent architecture (Phase UX-3A).
 * Modules are loaded through Vite's SSR loader; globalThis.fetch is replaced
 * by a recorder so any network use fails the run. Fixtures are test-only and
 * never persisted.
 *
 * Run from frontend/:  node src/lib/assistant/assistant.test.ts
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
type IntentsLib = typeof import("./intents.ts");
type ContextLib = typeof import("./context.ts");
type ResolveLib = typeof import("./resolve.ts");
type AILib = typeof import("./aiContext.ts");
type RedactLib = typeof import("./redact.ts");
type ShortcutsLib = typeof import("../assistantActions.ts");
type HomeLib = typeof import("../securityHome.ts");
type PageModule = typeof import("../../components/assistant/AssistantPage.tsx");
type FsModule = {
  readFileSync(path: string, encoding: "utf8"): string;
  readdirSync(path: string): string[];
};

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${message}`);
}
const results: string[] = [];
const pass = (name: string, note = "") =>
  results.push(`PASS ${name}${note ? ` — ${note}` : ""}`);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

// ---- fetch recorder ---------------------------------------------------------
const requested: string[] = [];
const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL) => {
  requested.push(String(input));
  throw new Error(`unexpected request ${String(input)}`);
}) as typeof fetch;

// ---- fixtures -----------------------------------------------------------------
const TARGET = "192.0.2.44";
const SECRET = "hunter2-fixture-secret";
const JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJlLWZpeHR1cmU";
let seq = 0;
const uuid = (prefix: string) => `${prefix}0000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`;

function summary(
  status: AssessmentStatus,
  startedAt: string,
  extra: Partial<AssessmentSummary> = {},
): AssessmentSummary {
  return {
    id: uuid("a"),
    target: TARGET,
    assessment_type: "MULTI_LAYER",
    status,
    started_at: startedAt,
    completed_at: status === "RUNNING" ? null : startedAt.replace(":00Z", ":40Z"),
    error_summary: null,
    metadata: { env: { MQTT_PASSWORD: SECRET }, config_path: "C:\\srv\\backend\\.env" },
    created_at: startedAt,
    evidence_count: 4,
    finding_count: 7,
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
    description: `Observed detail on ${TARGET}:${port} for ${findingId}.`,
    target: TARGET,
    port,
    evidence_reference: uuid("e"),
    remediation,
    status: "OPEN",
    created_at: "2026-10-13T19:58:30Z",
  };
}

function snapshot(assessmentId: string, ref: string | null, score: number, level: RiskSnapshot["risk_level"]): RiskSnapshot {
  return {
    id: uuid("r"),
    assessment_id: assessmentId,
    finding_ref: ref,
    score,
    risk_level: level,
    score_version: "IoT-RISK-v1",
    base_severity: null,
    context_score: 0.66,
    factor_contributions: {},
    context_inputs: { exposure: "fixture" },
    created_at: "2026-10-13T19:58:41Z",
  };
}

const older = summary("COMPLETE", "2026-10-12T08:00:00Z", { highest_risk: 41.2, highest_risk_level: "MEDIUM" });
const latest = summary("COMPLETE", "2026-10-13T19:58:00Z", { highest_risk: 70.5, highest_risk_level: "HIGH" });
const partial = summary("INCOMPLETE", "2026-10-14T06:00:00Z", {
  highest_risk: 88.8,
  highest_risk_level: "CRITICAL",
  error_summary: `TLS probe failed at C:\\Users\\svc\\backend\\scanner\\tls_probe.py token=${SECRET} see https://internal.example/debug and /opt/iot/backend/.env`,
});
const failed = summary("FAILED", "2026-10-14T07:00:00Z", { error_summary: "RuntimeError: probe crashed" });
const running = summary("RUNNING", "2026-10-14T08:00:00Z");

const REMEDIATION_MQTT = "Set allow_anonymous false, configure a password_file, and enforce topic ACLs for each client.";
const anonymous = finding(latest.id, "IOT-MQTT-01", "HIGH", "MQTT broker accepted an anonymous connection", REMEDIATION_MQTT, 1883);
const plainA = finding(latest.id, "IOT-MQTT-02", "MEDIUM", "MQTT accepted over plaintext", "Enable an MQTT TLS listener with a valid certificate.", 8883);
const plainB = finding(latest.id, "IOT-MQTT-02", "MEDIUM", "MQTT accepted over plaintext", "Enable an MQTT TLS listener with a valid certificate.", 1883);
const unmapped = finding(latest.id, "ZZ-99", "MEDIUM", "Backend-only fixture title", null, null);
const headers = finding(latest.id, "WEB-02", "LOW", "Recommended HTTP security headers missing", "Add the missing headers.", 80);
const infoA = finding(latest.id, "NET-01", "INFO", "Open TCP service observed", "Confirm the service is required.", 22);
const infoB = finding(latest.id, "NET-01", "INFO", "Open TCP service observed", "Confirm the service is required.", 1883);

const latestDetail: AssessmentDetail = {
  ...latest,
  evidence: [{
    id: uuid("e"),
    assessment_id: latest.id,
    target: TARGET,
    port: 1883,
    check_type: "MQTT_PROBE",
    result: "SUCCESS",
    evidence_source: "mqtt_probe",
    observation: { password: SECRET, token: JWT, banner: "Mosquitto 2.0.18-fixture" },
    observed_at: "2026-10-13T19:58:20Z",
  }],
  findings: [infoA, headers, plainA, anonymous, unmapped, plainB, infoB],
  risk_snapshots: [
    snapshot(latest.id, null, 70.5, "HIGH"),
    snapshot(latest.id, anonymous.id, 57.93, "HIGH"),
    snapshot(latest.id, plainA.id, 41.17, "MEDIUM"),
  ],
};
const readyDetail = { status: "ready" as const, detail: latestDetail };

// ---- loader -------------------------------------------------------------------
const viteModuleName = "vite";
const fsModuleName = "node:fs";
const vite = (await import(viteModuleName)) as {
  createServer(config: Record<string, unknown>): Promise<ViteServer>;
};
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
  const intents = await load<IntentsLib>("/src/lib/assistant/intents.ts");
  const ctx = await load<ContextLib>("/src/lib/assistant/context.ts");
  const res = await load<ResolveLib>("/src/lib/assistant/resolve.ts");
  const ai = await load<AILib>("/src/lib/assistant/aiContext.ts");
  const redact = await load<RedactLib>("/src/lib/assistant/redact.ts");
  const shortcuts = await load<ShortcutsLib>("/src/lib/assistantActions.ts");
  const home = await load<HomeLib>("/src/lib/securityHome.ts");
  const { AssistantView } = await load<PageModule>("/src/components/assistant/AssistantPage.tsx");

  const classify = intents.classifyAssistantIntent;
  const expectIntent = (text: string, intent: string, phrase: string | null, confidence?: string) => {
    const result = classify(text);
    check(result.intent === intent, `"${text}" -> ${result.intent}, expected ${intent} (${result.reason})`);
    check(result.matchedPhrase === phrase, `"${text}" matched ${result.matchedPhrase}, expected ${phrase}`);
    if (confidence) check(result.confidence === confidence, `"${text}" confidence ${result.confidence}`);
    return result;
  };

  // ============================== INTENT CLASSIFIER ==============================
  {
    const r = expectIntent("Check my network", "CHECK", "check my network", "HIGH");
    check(r.reason === 'Request is the phrase "check my network" (CHECK).', `reason: ${r.reason}`);
    check(!r.requiresAssessment && !r.requiresComparison && r.subject === null, "CHECK flags");
    expectIntent("Please check my IoT network", "CHECK", "check my iot network", "HIGH");
    pass("1 \"check my network\" -> CHECK", r.reason);
  }
  {
    const r = expectIntent("run a security check", "CHECK", "run a security check", "HIGH");
    expectIntent("Could you run a security check on my devices?", "CHECK", "run a security check", "MEDIUM");
    expectIntent("scan my IoT network", "CHECK", "scan my iot network");
    expectIntent("check again", "CHECK", "check again");
    pass("2 \"run a security check\" -> CHECK", r.reason);
  }
  {
    const r = expectIntent("Explain my risk", "EXPLAIN", "explain my risk", "HIGH");
    check(r.subject === "RISK" && r.requiresAssessment && !r.requiresComparison, "EXPLAIN risk flags");
    expectIntent("explain the risk", "EXPLAIN", "explain the risk");
    const why = expectIntent("Why is my risk HIGH?", "TECHNICAL", "why is my risk high", "HIGH");
    check(why.subject === "RISK_FACTORS" && why.requiresAssessment && !why.requiresComparison, "risk factors flags");
    expectIntent("why is my risk so bad", "TECHNICAL", "why is my risk", "MEDIUM");
    pass("3 \"explain my risk\" -> EXPLAIN (subject RISK); \"why is my risk high\" -> TECHNICAL (RISK_FACTORS)", r.reason);
  }
  {
    const r = expectIntent("What's wrong?", "EXPLAIN", "whats wrong", "HIGH");
    check(r.subject === "ISSUES", "issues subject");
    expectIntent("what\u2019s wrong", "EXPLAIN", "whats wrong");
    expectIntent("what is wrong with my broker", "EXPLAIN", "what is wrong", "MEDIUM");
    expectIntent("why is this risky", "EXPLAIN", "why is this risky");
    expectIntent("explain this issue", "EXPLAIN", "explain this issue");
    pass("4 \"what's wrong\" -> EXPLAIN (subject ISSUES), curly apostrophe normalized", r.reason);
  }
  {
    const r = expectIntent("How do I fix this?", "FIX", "how do i fix this", "HIGH");
    check(r.requiresAssessment && !r.requiresComparison && r.subject === null, "FIX flags");
    expectIntent("how can I fix the broker", "FIX", "how can i fix", "MEDIUM");
    expectIntent("what should I do", "FIX", "what should i do");
    expectIntent("how do I remediate it", "FIX", "how do i remediate");
    pass("5 \"how do I fix this\" -> FIX", r.reason);
  }
  {
    const r = expectIntent("help me fix this", "FIX", "help me fix this", "HIGH");
    expectIntent("help me fix the MQTT issue", "FIX", "help me fix", "MEDIUM");
    pass("6 \"help me fix this\" -> FIX", r.reason);
  }
  {
    const r = expectIntent("Did I fix it?", "VERIFY", "did i fix it", "HIGH");
    check(r.requiresAssessment && r.requiresComparison, "VERIFY needs assessment + comparison");
    expectIntent("check if I fixed it", "VERIFY", "check if i fixed it");
    expectIntent("did the issue go away", "VERIFY", "did the issue go away");
    const longer = expectIntent("check again after fixing", "VERIFY", "check again after fixing", "HIGH");
    check(longer.reason.includes("check again after fixing"), "longer phrase decides over contained CHECK phrase");
    pass("7 \"did I fix it\" -> VERIFY; \"check again after fixing\" not CHECK", r.reason);
  }
  {
    const r = expectIntent("verify the fix", "VERIFY", "verify the fix", "HIGH");
    pass("8 \"verify the fix\" -> VERIFY", r.reason);
  }
  {
    const r = expectIntent("Give me a summary", "SUMMARY", "give me a summary", "HIGH");
    check(r.requiresAssessment && !r.requiresComparison, "SUMMARY flags");
    expectIntent("summarize my security", "SUMMARY", "summarize my security");
    expectIntent("security summary please", "SUMMARY", "security summary", "HIGH");
    expectIntent("what happened in my last check", "SUMMARY", "what happened in my last check");
    pass("9 \"give me a summary\" -> SUMMARY", r.reason);
  }
  {
    for (const text of ["what's the weather today", "hello", "open the garage door", "fix", "risk", "scan 10.0.0.1", ""]) {
      const r = classify(text);
      check(r.intent === "UNKNOWN" && r.confidence === "LOW" && r.matchedPhrase === null, `"${text}" -> ${r.intent}`);
      check(!r.requiresAssessment && !r.requiresComparison, "UNKNOWN requires nothing");
    }
    check(classify("").reason === "Request is empty.", "empty reason");
    check(classify("hello").reason === "No supported request phrase was found.", "no-match reason");
    check(classify("x".repeat(301)).reason === "Request is longer than 300 characters.", "length cap");
    pass("10 unrelated phrases -> UNKNOWN (LOW, no phrase)");
  }
  {
    const both = classify("check my network and how do I fix this");
    check(both.intent === "UNKNOWN", `ambiguous -> ${both.intent}`);
    check(
      both.reason === 'Request matches more than one intent: CHECK ("check my network"), FIX ("how do i fix this").',
      `ambiguity reason: ${both.reason}`,
    );
    check(classify("did I fix it or what should I do").intent === "UNKNOWN", "VERIFY + FIX ambiguous");
    const negated = classify("don't run a security check");
    check(negated.intent === "UNKNOWN" && negated.reason === '"run a security check" is preceded by "dont".', `negation: ${negated.reason}`);
    check(classify("never scan my network").intent === "UNKNOWN", "never -> UNKNOWN");
    pass("11 ambiguous or negated requests -> UNKNOWN with the reason", both.reason);
  }
  {
    const samples = [...intents.INTENT_PHRASES.map((p) => p.phrase), "check my network and how do I fix this", "hello", "What's wrong?"];
    for (const text of samples) {
      const first = classify(text);
      for (let i = 0; i < 3; i++) check(same(first, classify(text)), `"${text}" not deterministic`);
    }
    for (const rule of intents.INTENT_PHRASES) {
      const r = classify(rule.phrase);
      check(r.intent === rule.intent && r.matchedPhrase === rule.phrase && r.confidence === "HIGH", `listed phrase "${rule.phrase}" -> ${r.intent}`);
      check(intents.normalizeRequest(rule.phrase) === rule.phrase, `phrase "${rule.phrase}" is not normalized`);
    }
    pass("12 classifier is deterministic; every listed phrase classifies to its own intent", `${intents.INTENT_PHRASES.length} phrases`);
  }

  // =================================== CONTEXT ===================================
  const contextNone = ctx.buildAssistantContext([]);
  const contextComplete = ctx.buildAssistantContext([older, latest], readyDetail);
  const contextPartial = ctx.buildAssistantContext([older, latest, partial]);
  const contextFailed = ctx.buildAssistantContext([latest, failed]);
  const contextRunning = ctx.buildAssistantContext([latest, running]);

  {
    const c = contextNone;
    check(c.availability === "NO_ASSESSMENT" && c.latestAssessment === null, "no latest");
    check(c.risk === null && c.scope === null && c.lastError === null && c.verificationBaseline === null, "nothing invented");
    check(c.importantIssues === null && c.issueCounts === null && c.issueStatus === "NOT_APPLICABLE", "issues unknown");
    check(same(c.capabilities, { canCheck: true, canExplain: false, canFix: false, canVerify: false, canSummarize: false }), "capabilities");
    check(same(c.limitations, [ctx.CONTEXT_LIMITATIONS.noAssessment]), "limitation");
    pass("13 no assessment -> NO_ASSESSMENT, only CHECK possible");
  }
  {
    const c = contextComplete;
    check(c.availability === "ASSESSMENT_AVAILABLE", "available");
    check(c.latestAssessment?.id === latest.id && c.latestAssessment.status === "COMPLETE", "latest by timestamp");
    check(same(c.latestAssessment, {
      id: latest.id, target: TARGET, status: "COMPLETE", startedAt: latest.started_at,
      completedAt: latest.completed_at, createdAt: latest.created_at, findingCount: 7,
    }), "latest assessment fields");
    check(same(c.capabilities, { canCheck: true, canExplain: true, canFix: true, canVerify: true, canSummarize: true }), "capabilities");
    check(c.verificationBaseline?.assessmentId === latest.id, "baseline = latest COMPLETE");
    check(same(ctx.buildAssistantContext([latest, older], readyDetail), c), "input order does not matter");
    pass("14 complete assessment -> ASSESSMENT_AVAILABLE");
  }
  {
    const c = contextPartial;
    check(c.availability === "ASSESSMENT_INCOMPLETE" && c.latestAssessment?.id === partial.id, "incomplete latest");
    check(c.risk === null, "incomplete run's risk not current");
    check(c.importantIssues === null && c.issueStatus === "NOT_APPLICABLE", "no issues for incomplete run");
    check(c.verificationBaseline?.assessmentId === latest.id, "older COMPLETE remains the verification baseline");
    check(c.capabilities.canExplain === false && c.capabilities.canFix === false, "no explain/fix");
    check(c.capabilities.canVerify && c.capabilities.canSummarize, "verify/summary allowed");
    check(c.limitations[0] === ctx.CONTEXT_LIMITATIONS.incomplete, "limitation");
    check(!JSON.stringify(c).includes("88.8") && !JSON.stringify(c).includes("CRITICAL"), "incomplete risk not copied");
    pass("15 incomplete -> ASSESSMENT_INCOMPLETE, no current risk");
  }
  {
    const c = contextFailed;
    check(c.availability === "ASSESSMENT_FAILED" && c.lastError === "RuntimeError: probe crashed", "failed + error");
    check(c.risk === null && c.limitations[0] === ctx.CONTEXT_LIMITATIONS.failed, "no risk, limitation");
    check(contextRunning.availability === "ASSESSMENT_RUNNING" && contextRunning.risk === null, "running");
    check(contextRunning.lastError === null && contextRunning.limitations[0] === ctx.CONTEXT_LIMITATIONS.running, "running limitation");
    pass("16 failed -> ASSESSMENT_FAILED (and RUNNING -> ASSESSMENT_RUNNING)");
  }
  {
    const issues = contextComplete.importantIssues;
    check(issues && contextComplete.issueStatus === "AVAILABLE", "issues available");
    check(issues.map((i) => i.checkId).join("|") === "IOT-MQTT-01|IOT-MQTT-02|ZZ-99", `important order ${issues.map((i) => i.checkId).join("|")}`);
    const [mqtt, plain, other] = issues;
    check(same(mqtt, {
      checkId: "IOT-MQTT-01", severity: "HIGH", title: "MQTT broker accepts connections without a password",
      meaning: "The broker accepted a connection that supplied no username or password.",
      remediation: REMEDIATION_MQTT, ports: [1883], occurrenceCount: 1,
    }), `issue shape ${JSON.stringify(mqtt)}`);
    check(same(plain.ports, [1883, 8883]) && plain.occurrenceCount === 2, "grouped by check, ports sorted");
    check(other.title === "Backend-only fixture title" && other.meaning === null && other.remediation === null && same(other.ports, []), "unmapped check");
    const ux1 = home.summarizeIssues(latestDetail);
    check(same(issues.map((i) => [i.checkId, i.title, i.meaning, i.remediation]), ux1.important.map((i) => [i.checkId, i.title, i.summary, i.remediation])), "same as UX-1 mapping");
    check(same(contextComplete.issueCounts, { importantIssues: 3, minorIssues: 1, informationalFindings: 2 }), "counts");
    pass("17 important issues come from the UX-1 summarizeIssues mapping");
  }
  {
    const text = JSON.stringify(contextComplete.importantIssues);
    check(!text.includes("NET-01") && !text.includes("Open TCP service") && !text.includes("WEB-02"), "INFO/LOW not important");
    const infoOnly = ctx.buildAssistantContext([latest], { status: "ready", detail: { ...latestDetail, findings: [infoA, infoB, headers] } });
    check(same(infoOnly.importantIssues, []) && infoOnly.capabilities.canFix === false, "INFO/LOW only -> nothing to fix");
    check(same(infoOnly.issueCounts, { importantIssues: 0, minorIssues: 1, informationalFindings: 2 }), "counted, not important");
    pass("18 INFO (and LOW) never treated as important");
  }
  {
    check(same(contextComplete.risk, { score: 70.5, level: "HIGH" }), "risk copied");
    const odd = ctx.buildAssistantContext([{ ...latest, highest_risk: 12.345, highest_risk_level: "MODERATE" }], readyDetail);
    check(same(odd.risk, { score: 12.345, level: "MODERATE" }), "unusual values copied as-is");
    pass("19 risk score and level copied exactly from the assessment summary");
  }
  {
    const noRisk = ctx.buildAssistantContext([{ ...latest, highest_risk: null, highest_risk_level: null }], readyDetail);
    check(noRisk.risk === null, "snapshots present but no summary risk -> null, not derived");
    check(noRisk.limitations.includes(ctx.CONTEXT_LIMITATIONS.noRisk), "limitation stated");
    const levelOnly = ctx.buildAssistantContext([{ ...latest, highest_risk: null }], readyDetail);
    check(same(levelOnly.risk, { score: null, level: "HIGH" }) && levelOnly.limitations.includes(ctx.CONTEXT_LIMITATIONS.noRiskScore), "score not filled in");
    const text = JSON.stringify(contextComplete);
    check(!text.includes("57.93") && !text.includes("41.17") && !text.includes("99.1"), "no per-finding or summed scores");
    for (const file of ["context.ts", "aiContext.ts", "resolve.ts", "intents.ts"]) {
      check(!/Math\.|\.reduce\(/.test(source(`src/lib/assistant/${file}`)), `${file} computes values`);
    }
    pass("20 no frontend risk calculation (null stays null; snapshots not summed)");
  }
  {
    check(contextComplete.scope?.authorizedTarget === TARGET, "scope from record");
    const other = ctx.buildAssistantContext([{ ...latest, target: "198.51.100.7" }]);
    check(other.scope?.authorizedTarget === "198.51.100.7" && other.latestAssessment?.target === "198.51.100.7", "follows data");
    check(!JSON.stringify(contextComplete).includes("10.188.244.85"), "no hardcoded lab target");
    pass("21 target copied from the assessment record");
  }
  {
    const sparse = ctx.buildAssistantContext([{ ...latest, completed_at: null, finding_count: Number.NaN, highest_risk: null, highest_risk_level: null }]);
    check(sparse.latestAssessment?.completedAt === null && sparse.latestAssessment.findingCount === null, "missing values null");
    check(sparse.issueStatus === "LOADING" && sparse.importantIssues === null && sparse.issueCounts === null, "detail not loaded -> unknown, not empty");
    check(sparse.capabilities.canFix === false && sparse.limitations.includes(ctx.CONTEXT_LIMITATIONS.issuesLoading), "loading stated");
    const stale = ctx.buildAssistantContext([latest], { status: "ready", detail: { ...latestDetail, id: older.id } });
    check(stale.issueStatus === "LOADING" && stale.importantIssues === null, "detail for another assessment ignored");
    const broken = ctx.buildAssistantContext([latest], { status: "error", message: "Assessment not found" });
    check(broken.issueStatus === "UNAVAILABLE" && broken.importantIssues === null, "detail error -> unavailable");
    check(broken.limitations.includes(ctx.CONTEXT_LIMITATIONS.issuesUnavailable), "unavailable stated");
    check(contextComplete.lastError === null, "no error invented for COMPLETE");
    pass("22 missing values remain null / unavailable, never guessed");
  }

  // ================================== RESOLUTION =================================
  const resolve = res.resolveAssistantIntent;
  const intentOf = (text: string) => classify(text);
  {
    for (const c of [null, contextNone, contextComplete, contextPartial]) {
      const r = resolve(intentOf("check my network"), c);
      check(r.state === "READY" && r.action.type === "OPEN_ASSESSMENT" && r.workflow === "ASSESSMENT_CREATION", "CHECK always opens the form");
      check(same(r.destination, { section: "history", anchor: { id: "new-security-check", focusId: "assessment-target" } }), "form destination");
      check(r.action.assessmentId === undefined, "CHECK names no assessment");
    }
    pass("23 CHECK -> OPEN_ASSESSMENT (assessment creation workflow), never started automatically");
  }
  {
    const risk = resolve(intentOf("why is my risk high"), contextComplete);
    check(risk.action.type === "OPEN_RISK" && risk.action.assessmentId === latest.id && risk.workflow === "LATEST_ASSESSMENT_CONTEXT", "risk");
    check(same(risk.destination, { section: "security", securityTechnical: true, anchor: { id: "assessment-risk" } }), "risk destination");
    const issues = resolve(intentOf("what's wrong"), contextComplete);
    check(issues.action.type === "OPEN_SECURITY" && same(issues.destination, { section: "security", anchor: { id: "security-issues" } }), "issues");
    pass("24 EXPLAIN + complete assessment -> OPEN_RISK / OPEN_SECURITY");
  }
  {
    const none = resolve(intentOf("explain my risk"), contextNone);
    check(none.action.type === "ASK_CLARIFICATION" && none.destination === null, "no destination");
    check(none.action.reason === "No completed security assessment is available to explain.", `reason: ${none.action.reason}`);
    check(none.state === "NEEDS_ASSESSMENT" && none.blocker === "NO_ASSESSMENT", "state/blocker");
    const part = resolve(intentOf("explain my risk"), contextPartial);
    check(part.blocker === "LATEST_NOT_COMPLETE" && part.action.type === "ASK_CLARIFICATION", "partial latest blocks EXPLAIN");
    check(!JSON.stringify(part).includes(older.id) && !JSON.stringify(part).includes(latest.id), "older run not silently explained");
    const loading = resolve(intentOf("explain my risk"), null);
    check(loading.state === "LOADING" && loading.blocker === "ASSESSMENTS_LOADING", "loading");
    pass("25 EXPLAIN without a completed assessment -> ASK_CLARIFICATION", none.action.reason);
  }
  {
    const fix = resolve(intentOf("how do I fix this"), contextComplete);
    check(fix.action.type === "OPEN_FINDING" && fix.action.findingCheckId === "IOT-MQTT-01" && fix.action.assessmentId === latest.id, "top important finding");
    check(fix.workflow === "IMPORTANT_FINDINGS" && same(fix.destination, { section: "security", anchor: { id: "security-issues" } }), "destination");
    pass("26 FIX + important issue -> OPEN_FINDING (highest-severity check)", fix.action.reason);
  }
  {
    const infoOnly = ctx.buildAssistantContext([latest], { status: "ready", detail: { ...latestDetail, findings: [infoA, headers] } });
    const r = resolve(intentOf("help me fix this"), infoOnly);
    check(r.action.type === "ASK_CLARIFICATION" && r.blocker === "NO_IMPORTANT_ISSUES", "no important issue");
    check(r.action.reason === "There is no identified important issue to remediate in your latest completed check.", r.action.reason);
    check(resolve(intentOf("help me fix this"), contextNone).action.reason === "No completed security assessment with an important issue is available to fix.", "no assessment reason");
    check(resolve(intentOf("help me fix this"), ctx.buildAssistantContext([latest])).state === "LOADING", "issues loading");
    check(resolve(intentOf("help me fix this"), ctx.buildAssistantContext([latest], { status: "error", message: "x" })).blocker === "ISSUES_UNAVAILABLE", "issues unavailable");
    check(resolve(intentOf("help me fix this"), contextPartial).blocker === "LATEST_NOT_COMPLETE", "partial latest");
    pass("27 FIX without an important issue -> ASK_CLARIFICATION", r.action.reason);
  }
  {
    const r = resolve(intentOf("did I fix it"), contextPartial);
    check(r.action.type === "OPEN_REASSESSMENT" && r.action.assessmentId === latest.id, "BEFORE = latest COMPLETE");
    check(r.workflow === "REASSESSMENT_COMPARISON", "workflow");
    check(same(r.destination, { section: "history", assessmentId: latest.id, anchor: { id: "assessment-reassessment" } }), "re-assessment destination");
    check(r.action.reason.includes("nothing runs until you confirm"), "confirmation stated");
    const none = resolve(intentOf("did I fix it"), ctx.buildAssistantContext([partial, failed]));
    check(none.action.type === "ASK_CLARIFICATION" && none.blocker === "NO_COMPLETE_ASSESSMENT", "no BEFORE");
    check(none.action.reason === "Verification cannot begin because no security check has completed.", none.action.reason);
    pass("28 VERIFY -> OPEN_REASSESSMENT from the latest COMPLETE check (re-assessment/comparison workflow)");
  }
  {
    const r = resolve(intentOf("give me a summary"), contextComplete);
    check(r.action.type === "SHOW_SUMMARY" && r.action.assessmentId === latest.id && same(r.destination, { section: "security" }), "summary");
    check(resolve(intentOf("give me a summary"), contextFailed).action.type === "SHOW_SUMMARY", "failed check can be summarized honestly");
    const none = resolve(intentOf("give me a summary"), contextNone);
    check(none.action.reason === "No security summary is available because no security check has been run.", none.action.reason);
    pass("29 SUMMARY -> SHOW_SUMMARY; none without any check");
  }
  {
    const r = resolve(intentOf("open the garage door"), contextComplete);
    check(r.intent === "UNKNOWN" && r.action.type === "ASK_CLARIFICATION" && r.state === "NEEDS_CLARIFICATION", "clarification");
    check(r.workflow === "CLARIFICATION" && r.destination === null && r.action.reason === res.CLARIFICATION_REASON, "no destination");
    pass("30 UNKNOWN -> ASK_CLARIFICATION");
  }
  {
    const all = ["check my network", "why is my risk high", "what's wrong", "how do I fix this", "did I fix it", "give me a summary", "hello"];
    for (const c of [null, contextNone, contextComplete, contextPartial, contextFailed, contextRunning]) {
      for (const text of all) {
        const r = resolve(intentOf(text), c);
        check(same(r, resolve(intentOf(text), c)), "resolution deterministic");
        check(r.state === "READY" ? r.destination !== null : r.destination === null, "destination only when READY");
        check(same(r.destination, res.actionDestination(r.action)), "single action->destination mapping");
      }
    }
    check(requested.length === 0, `resolution made requests: ${requested.join(", ")}`);
    pass("resolution is pure: deterministic, no requests, destination only via actionDestination");
  }
  {
    const covered = new Set(shortcuts.ASSISTANT_SHORTCUTS.map((s) => s.intent));
    check(["CHECK", "EXPLAIN", "FIX", "VERIFY", "SUMMARY"].every((i) => covered.has(i as never)), "every supported intent has a shortcut");
    const typed: Record<string, string> = {
      check: "check my network",
      "whats-wrong": "what's wrong",
      "explain-risk": "explain my risk",
      "fix-issue": "help me fix this",
      verify: "did I fix it",
      summary: "give me a summary",
    };
    for (const c of [null, contextNone, contextComplete, contextPartial, contextFailed]) {
      for (const shortcut of shortcuts.ASSISTANT_SHORTCUTS) {
        const viaShortcut = shortcuts.resolveShortcut(shortcut.id, c);
        const viaText = resolve(intentOf(typed[shortcut.id]), c);
        check(same(viaShortcut.action, viaText.action) && same(viaShortcut.destination, viaText.destination), `${shortcut.id} shortcut and typed request diverge`);
      }
    }
    pass("shortcuts and typed requests share one intent -> action -> destination mapping");
  }

  // ================================== AI CONTEXT =================================
  const aiComplete = ai.buildAssistantAIContext(contextComplete);
  const aiPartial = ai.buildAssistantAIContext(contextPartial);
  const aiNone = ai.buildAssistantAIContext(contextNone);
  const keys = (value: object | null) => (value ? Object.keys(value).join(",") : "null");
  {
    check(keys(aiComplete) === "contract,rules,availability,scope,assessment,risk,issues,issueCounts,lastError,limitations", `top keys ${keys(aiComplete)}`);
    check(keys(aiComplete.scope) === "target" && keys(aiComplete.assessment) === "status,startedAt,completedAt", "scope/assessment keys");
    check(keys(aiComplete.risk) === "level,score" && keys(aiComplete.issueCounts) === "importantIssues,minorIssues,informationalFindings", "risk/count keys");
    check(aiComplete.issues?.every((i) => keys(i) === "severity,title,meaning,remediation,occurrences"), "issue keys");
    check(aiComplete.contract === "assistant-context/v1", "contract version");
    const text = JSON.stringify(aiComplete);
    for (const id of [latest.id, older.id, ...latestDetail.findings.map((f) => f.id)]) check(!text.includes(id), "no IDs");
    check(!text.includes("1883") && !text.includes("8883"), "no ports");
    pass("31 AI context has only the allowed fields (no IDs, ports or raw records)");
  }
  {
    const everything = JSON.stringify([aiComplete, aiPartial, ai.buildAssistantAIContext(contextFailed), contextComplete, contextPartial]);
    for (const forbidden of [SECRET, JWT, "MQTT_PASSWORD", "C:\\\\", "\\\\Users", "/opt/iot", ".env", "https://", "internal.example", "tls_probe.py", "config_path"]) {
      check(!everything.includes(forbidden), `leaked "${forbidden}"`);
    }
    check(aiPartial.lastError === "TLS probe failed at [redacted] token=[redacted] see [redacted] and [redacted]", `redacted error: ${aiPartial.lastError}`);
    check(redact.redactSecrets(REMEDIATION_MQTT) === REMEDIATION_MQTT, "guidance text untouched");
    check(redact.redactSecrets(`Authorization: Bearer ${JWT}`) === "Authorization: [redacted] [redacted]", "bearer token");
    check(redact.redactRuntimeText("failed reading /etc/app/secret.conf") === "failed reading [redacted]", "unix path");
    pass("32 no secrets, credentials, tokens, paths, URLs or env values", aiPartial.lastError ?? "");
  }
  {
    const text = JSON.stringify([aiComplete, contextComplete]);
    for (const raw of ["Mosquitto 2.0.18-fixture", "MQTT_PROBE", "mqtt_probe", "Observed detail", "0.97", "IoT-RISK-v1", "exposure", "0.66"]) {
      check(!text.includes(raw), `raw evidence/detail leaked: ${raw}`);
    }
    check(!("evidence" in aiComplete) && !("metadata" in aiComplete) && !("evidence" in contextComplete), "no evidence fields");
    pass("33 no raw evidence, observations, descriptions, confidence or score internals");
  }
  {
    const strings: string[] = [];
    const numbers: number[] = [];
    const walk = (value: unknown) => {
      if (typeof value === "string") strings.push(value);
      else if (typeof value === "number") numbers.push(value);
      else if (Array.isArray(value)) value.forEach(walk);
      else if (value && typeof value === "object") Object.values(value).forEach(walk);
    };
    walk(aiComplete);
    const ux1 = home.summarizeIssues(latestDetail).important;
    const allowed = new Set<string>([
      ai.ASSISTANT_AI_CONTRACT, ...ai.ASSISTANT_AI_RULES, ...Object.values(ctx.CONTEXT_LIMITATIONS),
      "ASSESSMENT_AVAILABLE", "COMPLETE", "HIGH", "MEDIUM", TARGET,
      latest.started_at, latest.completed_at ?? "",
      ...ux1.flatMap((i) => [i.title, i.summary ?? "", i.remediation ?? ""]),
    ]);
    for (const value of strings) check(allowed.has(value), `invented string: "${value}"`);
    const allowedNumbers = new Set([70.5, 3, 1, 2, ...ux1.map((i) => i.occurrences)]);
    for (const value of numbers) check(allowedNumbers.has(value), `invented number: ${value}`);
    check(aiNone.scope === null && aiNone.assessment === null && aiNone.risk === null && aiNone.issues === null && aiNone.issueCounts === null, "nothing when no check");
    const loadingAi = ai.buildAssistantAIContext(ctx.buildAssistantContext([latest]));
    check(loadingAi.issues === null && loadingAi.limitations.includes(ctx.CONTEXT_LIMITATIONS.issuesLoading), "unknown issues are null, not []");
    check(aiPartial.risk === null && aiPartial.issues === null, "partial run: no risk, no issues");
    check(same(aiComplete, ai.buildAssistantAIContext(contextComplete)), "deterministic");
    pass("34 every AI-context value traces to backend data or fixed rule text; unknowns are null");
  }
  {
    check(same(aiComplete.rules, [
      "Use only the supplied assessment facts.",
      "Do not invent CVEs.",
      "Do not invent vulnerabilities.",
      "Do not invent devices or services.",
      "Do not calculate a new risk score.",
      "Do not claim the target is secure.",
      "Do not claim remediation is complete unless verification data says so.",
      "State when information is unavailable.",
    ]), "rules");
    check(aiComplete.limitations.includes(ctx.CONTEXT_LIMITATIONS.noEvidence) && aiComplete.limitations.includes(ctx.CONTEXT_LIMITATIONS.scopeOnly), "scope/evidence limits");
    check(aiComplete.limitations.includes(ctx.CONTEXT_LIMITATIONS.verification), "verification limit");
    check(aiPartial.limitations[0] === ctx.CONTEXT_LIMITATIONS.incomplete && aiNone.limitations[0] === ctx.CONTEXT_LIMITATIONS.noAssessment, "state limits");
    aiComplete.rules.push("mutated");
    check(ai.buildAssistantAIContext(contextComplete).rules.length === 8, "rules copied, not shared");
    pass("35 explicit AI rules and data limitations included");
  }

  // ================================ ASSISTANT PAGE ===============================
  const noop = () => {};
  const view = (context: ReturnType<ContextLib["buildAssistantContext"]> | null, status: string | null = null) =>
    renderToStaticMarkup(
      createElement(AssistantView, { context, assessmentsError: null, onRetryAssessments: noop, messages: [], status, onRequest: noop }),
    );
  const buttonFor = (html: string, label: string) => {
    const found = [...html.matchAll(/<button[^>]*>[\s\S]*?<\/button>/g)].map((m) => m[0]).filter((b) => b.includes(label));
    check(found.length === 1, `one button "${label}"`);
    return found[0];
  };
  const enabled = (button: string) => !/^<button[^>]*disabled=""/.test(button);
  const available = (button: string) => button.includes('data-available="true"');
  {
    const html = view(contextNone);
    check(enabled(buttonFor(html, "Check my IoT network")) && available(buttonFor(html, "Check my IoT network")), "CHECK available");
    const expectations: [string, string][] = [
      ["What&#x27;s wrong?", "Available after a completed security check."],
      ["Explain my risk", "Available after a completed security check."],
      ["Help me fix an issue", "Available after a completed security check with an important issue."],
      ["Check if I fixed it", "Available after a completed security check."],
      ["Summarize my last check", "Available after a completed security check."],
    ];
    for (const [label, hint] of expectations) {
      const button = buttonFor(html, label);
      check(enabled(button) && !available(button) && button.includes(hint), `${label} answers in chat, shows "${hint}"`);
    }
    pass("page: no assessment -> only CHECK available, spec reasons shown; blocked shortcuts reply instead of being dead");
  }
  {
    const html = view(contextComplete);
    for (const label of ["Check my IoT network", "What&#x27;s wrong?", "Explain my risk", "Help me fix an issue", "Check if I fixed it", "Summarize my last check"]) {
      check(enabled(buttonFor(html, label)) && available(buttonFor(html, label)), `${label} available`);
    }
    check(buttonFor(html, "Explain my risk").includes('data-intent="EXPLAIN" data-action="OPEN_RISK"'), "architecture exposed on the button");
    check(buttonFor(html, "Help me fix an issue").includes('data-action="OPEN_FINDING"'), "fix action");
    const noImportant = view(ctx.buildAssistantContext([latest], { status: "ready", detail: { ...latestDetail, findings: [infoA, headers] } }));
    const fix = buttonFor(noImportant, "Help me fix an issue");
    check(!available(fix) && fix.includes("No important issue was found in your latest check."), "FIX unavailable without important issue");
    const loadingIssues = view(ctx.buildAssistantContext([latest]));
    check(buttonFor(loadingIssues, "Help me fix an issue").includes("Checking your latest results…"), "FIX waits for issues");
    pass("page: complete check -> all available; FIX only with an important issue");
  }
  {
    const html = view(contextPartial);
    check(html.includes("Your latest security check isn&#x27;t complete yet.") && !html.includes("CRITICAL"), "partial intro");
    for (const label of ["What&#x27;s wrong?", "Explain my risk", "Help me fix an issue"]) {
      const button = buttonFor(html, label);
      check(!available(button) && button.includes("Available when your latest security check completes."), `${label} blocked`);
    }
    check(available(buttonFor(html, "Check if I fixed it")) && available(buttonFor(html, "Summarize my last check")), "verify/summary available");
    const loading = view(null);
    check(loading.includes("Loading your latest security check…") && available(buttonFor(loading, "Check my IoT network")), "loading");
    check(buttonFor(loading, "Explain my risk").includes("Available once your security checks have loaded."), "loading hint");
    for (const html2 of [html, loading, view(contextComplete)]) {
      check((html2.match(/<textarea/g) ?? []).length === 1 && !/<input|contenteditable/i.test(html2), "one composer textarea only");
      check(!/Analyzing|Thinking|typing|AI is thinking/i.test(html2), "no fake AI wording");
    }
    const busy = view(contextComplete, "Checking what you asked for…");
    const buttons = [...busy.matchAll(/<button[^>]*>/g)].map((m) => m[0]);
    check(buttons.length >= 7 && buttons.every((b) => b.includes('disabled=""')), "every button disabled while busy");
    check(/<textarea[^>]*disabled=""/.test(busy) && busy.includes('role="status"'), "composer disabled, status shown");
    pass("page: partial latest blocks EXPLAIN/FIX; single composer; everything disabled while processing");
  }

  // ================================ BOUNDARY SCAN ================================
  {
    const files = [
      ...fs.readdirSync(`${process.cwd()}/src/lib/assistant`).filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts")).map((f) => `src/lib/assistant/${f}`),
      "src/lib/assistantActions.ts",
      "src/components/assistant/AssistantPage.tsx",
    ];
    for (const file of files) {
      // The page may hand the existing creation call to the workflow's explicit run step, nothing more.
      const text =
        file === "src/components/assistant/AssistantPage.tsx"
          ? source(file)
              .replace('import { createAssessment, fetchAssessment } from "../../api/assessments";', "")
              .replace("runAssessment: createAssessment,", "")
          : source(file);
      check(!/fetchFindings|fetchRisk|fetchExplanation|\/findings|\/risk\b|\/explanations|api\/security/.test(text), `${file} uses legacy endpoints`);
      check(!/ollama|createAssessment|apiPost|console\.|localStorage|sessionStorage|import\.meta\.env|process\.env/i.test(text), `${file} has side effects or secrets access`);
    }
    for (const file of files.filter((f) => f.startsWith("src/lib/"))) {
      check(!/from "\.\.\/(\.\.\/)?api\/(assessments|client|security)"/.test(source(file)), `${file} performs requests`);
    }
    check(requested.length === 0, `requests: ${requested.join(", ")}`);
    pass("boundary: assistant code uses no legacy endpoints, no AI call, no create/POST, no logging", `${files.length} files`);
  }
} finally {
  globalThis.fetch = realFetch;
  await server.close();
}

for (const line of results) console.log(line);
console.log(`${results.filter((line) => line.startsWith("PASS")).length} checks passed`);
