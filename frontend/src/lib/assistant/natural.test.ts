/**
 * Checks for natural questions and short follow-ups in the assistant: "What are
 * these Security?", "What is this?", "Why?", "Is it bad?", "What is running
 * there?". Answers must come from the latest recorded check, stay short, keep
 * IDs under the technical details, ask one short question when the context is
 * unclear, and never start a check. globalThis.fetch is a recorder that answers
 * only POST /api/v1/assistant/explain and fails on anything else. Fixtures are
 * test-only and never persisted.
 *
 * Run from frontend/:  node src/lib/assistant/natural.test.ts
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
type IntentsLib = typeof import("./intents.ts");
type FollowUpLib = typeof import("./followUp.ts");
type WorkflowLib = typeof import("./workflow.ts");
type AssistantApi = typeof import("../../api/assistant.ts");
type PageModule = typeof import("../../components/assistant/AssistantPage.tsx");
type FsModule = { readFileSync(path: string, encoding: "utf8"): string };
type Context = ReturnType<ContextLib["buildAssistantContext"]>;

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${message}`);
}
const results: string[] = [];
const pass = (name: string, note = "") => results.push(`PASS ${name}${note ? ` — ${note}` : ""}`);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

// ---- fixtures (shaped like a recorded MULTI_LAYER check) ----------------------------
const TARGET = "192.0.2.44";
let seq = 0;
const uuid = (prefix: string) => `${prefix}0000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`;
const SCANNED = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 554, 1883, 8080, 8443, 8883];

function summary(status: AssessmentStatus, startedAt: string, extra: Partial<AssessmentSummary> = {}): AssessmentSummary {
  return {
    id: uuid("a"),
    target: TARGET,
    assessment_type: "MULTI_LAYER",
    status,
    started_at: startedAt,
    completed_at: status === "RUNNING" ? null : startedAt.replace(":00Z", ":40Z"),
    error_summary: null,
    metadata: { ports: SCANNED } as AssessmentSummary["metadata"],
    created_at: startedAt,
    evidence_count: 7,
    finding_count: 7,
    highest_risk: null,
    highest_risk_level: null,
    ...extra,
  };
}

const older = summary("COMPLETE", "2026-10-12T08:00:00Z", { highest_risk: 41.2, highest_risk_level: "MEDIUM" });
const latest = summary("COMPLETE", "2026-10-13T19:58:00Z", { highest_risk: 70.5, highest_risk_level: "HIGH" });

function evidence(checkType: string, result: string, source: string, port: number | null, observation: Record<string, unknown>): AssessmentEvidence {
  return {
    id: uuid("e"),
    assessment_id: latest.id,
    target: TARGET,
    port,
    check_type: checkType,
    result,
    evidence_source: source,
    observation,
    observed_at: "2026-10-13T19:58:20Z",
  };
}
const nmapPort = (port: number, service: string | null, product: string | null) =>
  evidence("NMAP_PORT", "OPEN", "NMAP", port, {
    port, state: "open", reason: "syn-ack", protocol: "tcp", service_name: service, product, version: null,
  });

const scanEv = evidence("NMAP_SCAN", "RESPONDED", "NMAP", null, { host_state: "up", open_ports: [139, 445, 1883] });
const p139 = nmapPort(139, "netbios-ssn", "Microsoft Windows netbios-ssn");
const p445 = nmapPort(445, "microsoft-ds", null);
const p1883 = nmapPort(1883, "mosquitto version 2.1.2", null);
const anonEv = evidence("MQTT_ANONYMOUS_CONNECT", "ACCEPTED", "MQTT_PROBE", 1883, { connection_accepted: true });
const plainEv = evidence("MQTT_TRANSPORT_COMPARISON", "PLAINTEXT_NO_TLS", "MQTT_PROBE", 1883, { tls_port: 8883 });
const tlsEv = evidence("TLS_HANDSHAKE", "REFUSED", "TLS_PROBE", 8883, { error_type: "ConnectionRefusedError" });

const MQTT_FIX = "Require a username and password on the MQTT broker.";
function finding(findingId: string, severity: AssessmentFinding["severity"], title: string, port: number, ref: string | null): AssessmentFinding {
  return {
    id: uuid("f"),
    assessment_id: latest.id,
    finding_id: findingId,
    finding_type: `TYPE_${findingId}`,
    category: "IOT_PROTOCOL",
    title,
    severity,
    confidence: 0.9,
    description: null,
    target: TARGET,
    port,
    evidence_reference: ref,
    remediation: findingId === "IOT-MQTT-01" ? MQTT_FIX : `Recorded remediation for ${findingId}.`,
    status: "OPEN",
    created_at: "2026-10-13T19:58:30Z",
  };
}
const mqtt01 = finding("IOT-MQTT-01", "HIGH", "Anonymous MQTT access", 1883, anonEv.id);
const mqtt02 = finding("IOT-MQTT-02", "MEDIUM", "MQTT without TLS", 1883, plainEv.id);
const net01 = [139, 445, 1883].map((port, i) => finding("NET-01", "INFO", "Open port", port, [p139, p445, p1883][i].id));
const net06 = [139, 445].map((port, i) => finding("NET-06", "LOW", "Administrative port", port, [p139, p445][i].id));

const contributions = {
  authentication_security: { normalized_value: 1, weight: 0.1, contribution_to_100: 10 },
  protocol_security: { normalized_value: 1, weight: 0.1, contribution_to_100: 10 },
  network_exposure: { normalized_value: 0.6, weight: 0.1, contribution_to_100: 6 },
};
const contextInputs = {
  authentication_security: { source: "MQTT_PROBE" },
  protocol_security: { source: "ACTIVE_PROBE" },
  network_exposure: { source: "NMAP" },
};
function snapshot(findingRef: string | null, score: number, level: RiskSnapshot["risk_level"]): RiskSnapshot {
  return {
    id: uuid("r"),
    assessment_id: latest.id,
    finding_ref: findingRef,
    score,
    risk_level: level,
    score_version: "IoT-RISK-v1",
    base_severity: null,
    context_score: null,
    factor_contributions: contributions,
    context_inputs: contextInputs,
    created_at: "2026-10-13T19:58:40Z",
  };
}

const latestDetail: AssessmentDetail = {
  ...latest,
  evidence: [scanEv, p139, p445, p1883, anonEv, tlsEv, plainEv],
  findings: [mqtt01, mqtt02, ...net01, ...net06],
  risk_snapshots: [snapshot(null, 70.5, "HIGH"), snapshot(mqtt01.id, 70.5, "HIGH"), snapshot(mqtt02.id, 55.0, "MEDIUM")],
  risk_trace: {
    score_version: "IoT-RISK-v1",
    overall_rule: "HIGHEST_FINDING_RISK",
    overall_finding_refs: [mqtt01.id],
    factors: [
      { factor: "authentication_security", rule: "FINDING_TYPE", finding_refs: [mqtt01.id], evidence_refs: [anonEv.id] },
      { factor: "protocol_security", rule: "FINDING_TYPE", finding_refs: [mqtt02.id], evidence_refs: [plainEv.id] },
    ],
  },
};
/** Five important issues, to check the "most important 3 first" limit. */
const manyDetail: AssessmentDetail = {
  ...latestDetail,
  findings: [
    ...latestDetail.findings,
    finding("WEB-01", "HIGH", "HTTP without TLS", 80, null),
    finding("TLS-02", "MEDIUM", "Weak TLS", 8443, null),
    finding("NET-02", "MEDIUM", "Telnet open", 23, null),
  ],
};

// ---- fetch recorder ---------------------------------------------------------------
type Recorded = { url: string; method: string; body: string };
const recorded: Recorded[] = [];
const unexpected: string[] = [];
const explainResponse: AssistantExplainResponse = { status: "COMPLETE", answer: "Model text for the test.", source: "AI" };
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  const method = init?.method ?? "GET";
  recorded.push({ url, method, body: String(init?.body ?? "") });
  if (method === "POST" && url.endsWith("/api/v1/assistant/explain")) return json(explainResponse);
  unexpected.push(`${method} ${url}`);
  throw new Error(`unexpected request ${method} ${url}`);
}) as typeof fetch;

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
  const followUps = await load<FollowUpLib>("/src/lib/assistant/followUp.ts");
  const wf = await load<WorkflowLib>("/src/lib/assistant/workflow.ts");
  const assistantApi = await load<AssistantApi>("/src/api/assistant.ts");
  const { AssistantView } = await load<PageModule>("/src/components/assistant/AssistantPage.tsx");

  const contextComplete = ctx.buildAssistantContext([latest, older], { status: "ready", detail: latestDetail });
  const contextMany = ctx.buildAssistantContext([latest, older], { status: "ready", detail: manyDetail });
  const contextNone = ctx.buildAssistantContext([]);

  function harness(context: Context | null, detail: AssessmentDetail | null = latestDetail, workflow: Partial<AssistantWorkflowState> = {}) {
    let state: AssistantWorkflowState = { ...wf.INITIAL_WORKFLOW_STATE, ...workflow };
    const messages: AssistantMessage[] = [];
    const navigations: NavRequest[] = [];
    let id = 0;
    const conversation = conv.createAssistantConversation({
      getContext: () => context,
      getLatestDetail: () => detail,
      navigate: (request) => navigations.push(request),
      addMessage: (message) => messages.push(message),
      setStatus: () => {},
      explain: assistantApi.explainWithAssistant,
      workflow: {
        get: () => state,
        update: (patch) => {
          state = { ...state, ...patch };
        },
        runAssessment: () => Promise.reject(new Error("no check may start in these tests")),
        loadAssessment: () => Promise.reject(new Error("no check may be loaded in these tests")),
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
  const explainCalls = (from: number) =>
    recorded.slice(from).filter((call) => call.method === "POST" && call.url.endsWith("/api/v1/assistant/explain"));
  const assessmentPosts = () => recorded.filter((call) => call.method === "POST" && /\/api\/v1\/assessments\b/.test(call.url));

  const RAW_ID = /IOT-MQTT-0\d|NET-0\d|WEB-0\d|TLS-0\d|[0-9a-f]{7}0-0000-4000-8000|confidence|IoT-RISK|"[a-z_]+":/;
  const MQTT_TITLE = "MQTT broker accepts connections without a password";
  const ENC_TITLE = "MQTT traffic is not encrypted";
  const labels = (m: AssistantMessage) => (m.actions ?? []).map((a) => a.label);

  /** Asks and checks: answered, not the generic reply, no check started, no navigation. */
  async function ask(h: Harness, text: string, opts: { deterministic?: boolean } = {}) {
    const before = recorded.length;
    const outcome = await h.handleAssistantRequest(text);
    check(outcome.status === "answered", `${text}: answered`);
    const reply = h.last();
    check(reply.text !== conv.UNKNOWN_REPLY, `${text}: generic reply`);
    check(h.navigations.length === 0, `${text}: navigated`);
    if (opts.deterministic) check(recorded.length === before, `${text}: made ${recorded.length - before} request(s)`);
    return reply;
  }
  /** Short, scannable, no IDs or raw values outside technical details. */
  function compact(reply: AssistantMessage, label: string, maxLines = 7) {
    const lines = reply.text.split("\n");
    check(lines.length <= maxLines, `${label}: ${lines.length} lines`);
    check(reply.text.length <= 420, `${label}: ${reply.text.length} characters`);
    check(!RAW_ID.test(reply.text), `${label}: raw ID or value in "${reply.text}"`);
    if (reply.card?.kind === "FACTS") {
      check(reply.card.items.length <= 5, `${label}: ${reply.card.items.length} items`);
      check(!reply.card.items.some((item) => RAW_ID.test(`${item.title} ${item.detail}`)), `${label}: raw ID in items`);
    }
    if (reply.card?.kind === "ISSUES") check(reply.card.issues.length <= 3, `${label}: ${reply.card.issues.length} issues`);
  }

  // 1. Section 25 phrases never get the generic reply; deterministic ones make no request.
  {
    const deterministic = [
      "What are these Security?", "What are these security issues?", "What security issues do I have?",
      "What security problems were found?", "What did you find?", "What did the scan find?", "What issues were found?",
      "What is wrong?", "What's wrong with my network?",
      "What is this?", "Why is this a problem?", "Why?", "How do I fix this?", "What should I do?", "Is this bad?",
      "Is my network safe?", "Am I safe?", "What is my risk?", "Why is my risk high?", "Why is my score high?",
      "Are any ports open?", "Which ports are open?", "Is port 1883 open?", "Is port 8883 open?",
      "What services are running?", "What is running on port 1883?",
      "What evidence do you have?", "How do you know?",
      "How can I solve this?",
      "Did I fix it?", "Is it fixed?", "Check if I fixed it.",
      "What are these?", "Tell me about security.",
    ];
    for (const text of deterministic) {
      const reply = await ask(harness(contextComplete), text, { deterministic: true });
      compact(reply, text);
    }
    const from = recorded.length;
    for (const text of ["Give me a summary", "Summarize my security", "How did the check go?"]) {
      const reply = await ask(harness(contextComplete), text);
      check(reply.card?.kind === "RESULT", `${text}: recorded result card above the summary`);
    }
    check(explainCalls(from).every((call) => call.body === '{"intent":"SUMMARY"}'), "summaries use the existing summary explanation");
    pass("1 every listed question gets a specific answer; facts and follow-ups make no request", `${deterministic.length + 3} questions`);
  }

  // 2. "What are these Security?" variants -> the recorded issue list, compact.
  {
    const variants = [
      "What are these Security?", "What is this security?", "What are these security things?", "What are these security issues?",
      "What does this security mean?", "What are these findings?", "What are these problems?", "What are these securty isues?",
    ];
    for (const text of variants) {
      const r = intents.classifyAssistantIntent(text);
      check(r.intent === "TECHNICAL" && r.subject === "FINDINGS", `"${text}" -> ${r.intent}/${r.subject} (${r.reason})`);
    }
    const h = harness(contextComplete);
    const reply = await ask(h, "What are these Security?", { deterministic: true });
    check(
      reply.text ===
        "I found 7 findings in your latest check: 2 important issues and 5 additional lower-severity findings.\nChoose an important issue to see why it matters and how to fix it.",
      reply.text,
    );
    check(reply.card?.kind === "ISSUES" && same(reply.card.issues.map((i) => [i.title, i.severity]), [[MQTT_TITLE, "HIGH"], [ENC_TITLE, "MEDIUM"]]), "recorded issues");
    check(reply.card?.kind === "ISSUES" && reply.card.issues.every((i) => typeof i.summary === "string" && i.summary.length > 0), "one-line meaning per issue");
    check(h.state().topic === "ISSUES", "topic remembered");
    pass("2 \"What are these Security?\" and its variants list the recorded issues", `${variants.length} variants`);
  }

  // 3. Contextual follow-ups on the selected issue (section 7 example).
  {
    const h = harness(contextComplete);
    await ask(h, "What are these security issues?");
    const which = await ask(h, "What is this?", { deterministic: true });
    check(which.text === "Which issue do you mean? Choose one:" && which.card?.kind === "ISSUES", "two issues listed: asks which one");
    h.selectIssue("IOT-MQTT-01");
    const meaning = await ask(h, "What is this?", { deterministic: true });
    check(meaning.text.startsWith(`${MQTT_TITLE} — HIGH.\n`), meaning.text);
    check(same(labels(meaning), ["Why is this a problem?", "How do I fix it?", "See technical details"]), JSON.stringify(labels(meaning)));
    const why = await ask(h, "Why is this a problem?", { deterministic: true });
    check(
      why.text === `Anyone who can reach the broker may be able to connect without logging in.\nFix: ${MQTT_FIX}`,
      why.text,
    );
    const bad = await ask(h, "Is this bad?", { deterministic: true });
    check(bad.text.startsWith(`Yes. “${MQTT_TITLE}” is rated HIGH, so it's worth fixing soon.`), bad.text);
    check((await ask(h, "Why is this bad?", { deterministic: true })).text === why.text, "why variant");
    check((await ask(h, "Why?", { deterministic: true })).text === why.text, "bare why");
    const fix = await ask(h, "How do I fix this?", { deterministic: true });
    check(fix.card?.kind === "GUIDED_FIX" && fix.card.guide.checkId === "IOT-MQTT-01" && fix.card.guide.recordedFix === MQTT_FIX, "FIX shows the guided fix with the backend remediation");
    check(h.state().activeFindingCheckId === "IOT-MQTT-01", "the issue stays selected");
    for (const m of [meaning, why, bad]) compact(m, m.text.slice(0, 20));
    pass("3 \"What is this?\", \"Why is this a problem?\", \"Is this bad?\" and \"How do I fix this?\" use the selected issue");
  }

  // 4. "Which one is most serious?" selects the top issue; "How?" then fixes it.
  {
    const h = harness(contextComplete);
    await ask(h, "What did you find?");
    const top = await ask(h, "Which one is more serious?", { deterministic: true });
    check(top.text === `“${MQTT_TITLE}” is the most serious — HIGH.\nNext: “${ENC_TITLE}” — MEDIUM.\nStart with the most serious one, then run another check.`, top.text);
    check(h.state().activeFindingCheckId === "IOT-MQTT-01" && h.state().topic === "ISSUE", "top issue becomes the subject");
    const how = await ask(h, "How?", { deterministic: true });
    check(how.card?.kind === "GUIDED_FIX" && how.card.guide.checkId === "IOT-MQTT-01" && how.card.guide.recordedFix === MQTT_FIX, "How? fixes the subject");
    pass("4 \"Which one is more serious?\" ranks by recorded severity and becomes the subject");
  }

  // 5. One important issue: follow-ups need no choice.
  {
    const single: AssessmentDetail = { ...latestDetail, findings: [mqtt01, ...net01] };
    const h = harness(ctx.buildAssistantContext([latest, older], { status: "ready", detail: single }), single);
    await ask(h, "Any issues?");
    const meaning = await ask(h, "What is this?", { deterministic: true });
    check(meaning.text.startsWith(`${MQTT_TITLE} — HIGH.`), meaning.text);
    pass("5 with one important issue, \"What is this?\" explains it directly");
  }

  // 6. Risk follow-ups.
  {
    const h = harness(contextComplete);
    const status = await ask(h, "Is my network safe?", { deterministic: true });
    check(
      status.text ===
        `Your current risk is HIGH (70.5/100).\nThe main priorities from your latest check:\n• ${MQTT_TITLE} — HIGH\n• ${ENC_TITLE} — MEDIUM\nFix these first, then run another check.`,
      status.text,
    );
    check(!/completely secure|fully secure/i.test(status.text), "never claims complete security");
    const why = await ask(h, "Why?", { deterministic: true });
    check(why.text.startsWith("Your current risk is HIGH (70.5/100).\nThe largest recorded contributions are:\n• Authentication Security"), why.text);
    check(why.card?.kind === "FACTS" && !why.card.expanded, "values stay collapsed");
    const tech = await ask(h, "Show technical details", { deterministic: true });
    check(tech.card?.kind === "FACTS" && tech.card.expanded === true && tech.card.technical.some((l) => l.startsWith("Authentication Security: +10.0")), "technical details on request");
    const from = recorded.length;
    await ask(h, "Tell me more");
    check(explainCalls(from).length === 1 && explainCalls(from)[0].body === '{"intent":"EXPLAIN","subject":"RISK"}', "Tell me more: existing risk explanation");
    pass("6 \"Is my network safe?\" then \"Why?\" answers from recorded risk factors; details only on request");
  }

  // 7. Ports and services follow-ups.
  {
    const h = harness(contextComplete);
    const ports = await ask(h, "Which ports are open?", { deterministic: true });
    check(ports.text === "Your latest check recorded 3 open ports.\nAn open port is not automatically a security problem.", ports.text);
    const bad = await ask(h, "Is it bad?", { deterministic: true });
    check(bad.text.startsWith("An open port is not automatically a security problem.\nOn the open ports, your latest check found:"), bad.text);
    await ask(h, "Is port 1883 open?", { deterministic: true });
    const there = await ask(h, "What is running there?", { deterministic: true });
    check(there.text === "Port 1883 is running mosquitto version 2.1.2, as identified by the network scan.", there.text);
    const onIt = await ask(h, "What is on it?", { deterministic: true });
    check(onIt.text === there.text, "\"What is on it?\" uses the same port");
    const closed = await ask(h, "Is port 8883 open?", { deterministic: true });
    check(closed.text === "No. Port 8883 was checked and wasn't found open.", closed.text);
    const any = await ask(harness(contextComplete, latestDetail, { topic: "PORTS", topicPort: 1883 }), "Is there any port open?", { deterministic: true });
    check(any.text.startsWith("Your latest check recorded 3 open ports."), `"is there" is not "that port": ${any.text}`);
    pass("7 ports: recorded only; \"Is it bad?\" and \"What is running there?\" use the previous port");
  }

  // 8. Clarification instead of a guess.
  {
    const what = await ask(harness(contextComplete), "What is this?", { deterministic: true });
    check(what.text === "Which part would you like me to explain?", what.text);
    check(same(labels(what), ["Security issues", "Risk score", "Open ports"]), JSON.stringify(labels(what)));
    const topic = await ask(harness(contextComplete), "Tell me about security.", { deterministic: true });
    check(topic.text === "I can explain your latest security check. What would you like to see?", topic.text);
    for (const text of ["What does this mean?", "What is that?", "Why is this?", "Why?", "Is it bad?"]) {
      const r = await ask(harness(contextComplete), text, { deterministic: true });
      check(r.text === what.text, `${text}: ${r.text}`);
    }
    for (const label of ["Security issues", "Risk score", "Open ports"]) {
      const r = await ask(harness(contextComplete), label, { deterministic: true });
      check(r.text !== what.text, `${label} button is answered`);
    }
    const none = await ask(harness(contextNone, null), "What is this?", { deterministic: true });
    check(none.text === "There's no completed security check to explain yet. Run a security check first.", none.text);
    pass("8 unclear questions get one short clarification with buttons; nothing is guessed");
  }

  // 9. General knowledge is not the user's result.
  {
    for (const text of ["What is cybersecurity?", "Explain encryption.", "What is MQTT?", "What is a firewall?"]) {
      const r = intents.classifyAssistantIntent(text);
      check(r.intent === "UNKNOWN", `"${text}" -> ${r.intent}/${r.subject}`);
      check(followUps.classifyFollowUp(text) === null, `"${text}" is not a follow-up`);
      const h = harness(contextComplete, latestDetail, { topic: "ISSUE", activeFindingCheckId: "IOT-MQTT-01" });
      const before = recorded.length;
      await h.handleAssistantRequest(text);
      const reply = h.last();
      check(recorded.length === before && !reply.card, `${text}: no finding answer`);
      check(!reply.text.includes(MQTT_TITLE) && !reply.text.includes("70.5"), `${text}: no result presented as an answer`);
    }
    pass("9 general questions (cybersecurity, encryption, MQTT, firewall) are not mapped to findings");
  }

  // 10. More than 3 important issues: the most important 3 first.
  {
    const reply = await ask(harness(contextMany, manyDetail), "What issues were found?", { deterministic: true });
    check(
      reply.text ===
        "I found 10 findings in your latest check: 5 important issues and 5 additional lower-severity findings.\nShowing the most important 3 first — choose one to see why it matters and how to fix it.",
      reply.text,
    );
    check(reply.card?.kind === "ISSUES" && reply.card.issues.length === 3, "three issues shown");
    const status = await ask(harness(contextMany, manyDetail), "Am I safe?", { deterministic: true });
    check(status.text.split("\n").filter((l) => l.startsWith("• ")).length === 3 && status.text.includes("Showing 3 of 5 important issues."), status.text);
    pass("10 more than three important issues: three shown first, with the total");
  }

  // 11. Technical details only when asked.
  {
    const h = harness(contextComplete);
    h.selectIssue("IOT-MQTT-01");
    const tech = await ask(h, "See technical details", { deterministic: true });
    check(tech.text === `Technical details for “${MQTT_TITLE}”:`, tech.text);
    check(tech.card?.kind === "FACTS" && tech.card.expanded === true && tech.card.technical[0] === "Finding ID: IOT-MQTT-01 (HIGH)", "finding ID under expanded details");
    check(tech.card?.kind === "FACTS" && tech.card.technical.some((l) => l === "Port 1883/tcp: check MQTT_ANONYMOUS_CONNECT, observed ACCEPTED, source MQTT_PROBE"), JSON.stringify(tech.card));
    const html = renderToStaticMarkup(createElement(AssistantView, {
      context: contextComplete, assessmentsError: null, onRetryAssessments: () => {},
      messages: h.messages, status: null,
      onRequest: (): Promise<RequestOutcome> => Promise.resolve({ status: "rejected", reason: "empty" }),
      onOpenAction: () => {}, running: null, onRunCheck: () => {}, onSelectIssue: () => {}, onWorkflowNavigate: () => {},
    }));
    check(/<details data-technical=""[^>]*\bopen=""/.test(html), `explicitly requested details render open: ${html.match(/<details data-technical[^>]*>/)?.[0]}`);
    const list = harness(contextComplete);
    await ask(list, "What are these security issues?");
    const listHtml = renderToStaticMarkup(createElement(AssistantView, {
      context: contextComplete, assessmentsError: null, onRetryAssessments: () => {},
      messages: list.messages, status: null,
      onRequest: (): Promise<RequestOutcome> => Promise.resolve({ status: "rejected", reason: "empty" }),
      onOpenAction: () => {}, running: null, onRunCheck: () => {}, onSelectIssue: () => {}, onWorkflowNavigate: () => {},
    }));
    check((listHtml.match(/data-issue-summary=""/g) ?? []).length === 2, "each listed issue has its one-line meaning");
    check(!RAW_ID.test(listHtml.replace(/<details[\s\S]*?<\/details>/g, "").replace(/<[^>]+>/g, "")), "no IDs in the issue list");
    pass("11 technical details (finding ID, check, port, protocol, source) appear only when asked");
  }

  // 12. Verify and check never start a check.
  {
    for (const text of ["Did I fix it?", "Is it fixed?", "Check if I fixed it.", "Verify it"]) {
      const h = harness(contextComplete, latestDetail, { activeFindingCheckId: "IOT-MQTT-01", topic: "ISSUE" });
      const r = await ask(h, text, { deterministic: true });
      check((r.actions ?? []).some((a) => a.id === "run-verification"), `${text}: explicit verification button`);
      check(r.text.split("\n").length <= 2, `${text}: short`);
    }
    const c = await ask(harness(contextComplete), "Check my network", { deterministic: true });
    check((c.actions ?? []).some((a) => a.id === "run-check"), "explicit run button");
    check(assessmentPosts().length === 0, "no POST /api/v1/assessments");
    pass("12 VERIFY and CHECK only offer explicit buttons; no assessment was started");
  }

  // 13. Small typos and contractions; not every "security" question is about issues.
  {
    const cases: [string, string, string | null][] = [
      ["wat is my rsik", "SUMMARY", null],
      ["whats wrong w my netwrok", "EXPLAIN", "ISSUES"],
      ["what are these securty isues", "TECHNICAL", "FINDINGS"],
      ["Is 1883 open?", "TECHNICAL", "PORTS"],
      ["How can I solve this?", "FIX", null],
      ["Can you verify?", "UNKNOWN", null],
    ];
    for (const [text, intent, subject] of cases) {
      const r = intents.classifyAssistantIntent(text);
      check(r.intent === intent && r.subject === subject, `"${text}" -> ${r.intent}/${r.subject} (${r.reason})`);
    }
    for (const text of ["What is security?", "How does security work?", "Security tips"]) {
      const r = intents.classifyAssistantIntent(text);
      check(!(r.intent === "TECHNICAL" && r.subject === "FINDINGS"), `"${text}" is not an issue question`);
    }
    pass("13 typos and contractions are normalized; \"security\" alone is not an issue question");
  }

  const AUTH_MEANING = "The broker accepted a connection that supplied no username or password.";
  const ENC_MEANING = "The broker accepted unencrypted MQTT and no encrypted MQTT listener was reachable.";

  // 15. The reported conversation: "What are these two?" after the issue list.
  {
    const h = harness(contextComplete);
    await ask(h, "What are these security issues?", { deterministic: true });
    check(same(h.state().shownIssues, ["IOT-MQTT-01", "IOT-MQTT-02"]), "the list is remembered");
    const two = await ask(h, "What are these two?", { deterministic: true });
    check(
      two.text === `Here's what the two issues mean:\n• ${MQTT_TITLE} (HIGH): ${AUTH_MEANING}\n• ${ENC_TITLE} (MEDIUM): ${ENC_MEANING}`,
      two.text,
    );
    check(same(labels(two), ["Which one is most serious?", "How do I fix them?", "Why do they matter?"]), JSON.stringify(labels(two)));
    compact(two, "these two");
    for (const text of ["What are those two?", "Explain both", "What do these mean?", "Tell me about both of them"]) {
      const again = harness(contextComplete);
      await ask(again, "What did you find?");
      check((await ask(again, text, { deterministic: true })).text === two.text, `${text}: same answer`);
    }
    pass("15 \"What are these two?\" explains the two issues just listed");
  }

  // 16. Asking about the group: fixes, why, how serious, which first.
  {
    const h = harness(contextComplete);
    await ask(h, "What's wrong?");
    const fix = await ask(h, "How do I fix both?", { deterministic: true });
    check(fix.text === "Fix these 2 issues one at a time. Start with the HIGH severity issue.", fix.text);
    check(
      fix.card?.kind === "FIX_LIST" && same(fix.card.issues.map((i) => i.checkId), ["IOT-MQTT-01", "IOT-MQTT-02"]) && fix.card.startWith === "IOT-MQTT-01",
      "one guided fix per issue, never combined",
    );
    check((await ask(h, "How do I fix them?", { deterministic: true })).text === fix.text, "them = both");
    const why = await ask(h, "Why do they matter?", { deterministic: true });
    check(why.text.startsWith(`Why both issues matter:\n• ${MQTT_TITLE}: Anyone who can reach the broker`), why.text);
    const serious = await ask(h, "Are they dangerous?", { deterministic: true });
    check(serious.text === `How serious each one is:\n• ${MQTT_TITLE} — HIGH: fix this soon\n• ${ENC_TITLE} — MEDIUM: worth fixing, less urgent\nStart with “${MQTT_TITLE}”.`, serious.text);
    const worse = await ask(h, "Which of these two is worse?", { deterministic: true });
    check(worse.text.startsWith(`“${MQTT_TITLE}” is the most serious — HIGH.`), worse.text);
    check(h.state().activeFindingCheckId === "IOT-MQTT-01", "the most serious one becomes the subject");
    const meaning = await ask(h, "What is this?", { deterministic: true });
    check(meaning.text.startsWith(`${MQTT_TITLE} — HIGH.`), "\"this\" then means the chosen issue");
    pass("16 \"How do I fix both?\", \"Why do they matter?\", \"Are they dangerous?\", \"Which of these two is worse?\" use the listed issues");
  }

  // 17. Position, "the other one", severity and description pick one listed issue.
  {
    const h = harness(contextComplete);
    await ask(h, "What are these security issues?");
    const second = await ask(h, "Tell me about the second one", { deterministic: true });
    check(second.text.startsWith(`${ENC_TITLE} — MEDIUM.`), second.text);
    check(h.state().activeFindingCheckId === "IOT-MQTT-02" && same(h.state().shownIssues, ["IOT-MQTT-01", "IOT-MQTT-02"]), "selected, list kept");
    const other = await ask(h, "What about the other one?", { deterministic: true });
    check(other.text.startsWith(`${MQTT_TITLE} — HIGH.`), other.text);
    const high = await ask(h, "Is the high one bad?", { deterministic: true });
    check(high.text.startsWith(`Yes. “${MQTT_TITLE}” is rated HIGH`), high.text);
    const enc = await ask(h, "Why does the encryption one matter?", { deterministic: true });
    check(enc.text.startsWith("Messages sent to the broker may be readable"), enc.text);
    check(h.state().activeFindingCheckId === "IOT-MQTT-02", "description selects the issue");
    const fix = await ask(h, "How do I fix the first one?", { deterministic: true });
    check(fix.card?.kind === "GUIDED_FIX" && fix.card.guide.checkId === "IOT-MQTT-01" && fix.card.guide.recordedFix === MQTT_FIX, "FIX on the first issue, backend remediation");
    check(h.state().activeFindingCheckId === "IOT-MQTT-01", "first one selected");
    const n2 = await ask(h, "2", { deterministic: true });
    check(n2.text.startsWith(`${ENC_TITLE} — MEDIUM.`), "a bare number picks from the list");
    const verify = await ask(h, "Is the second one fixed?", { deterministic: true });
    check((verify.actions ?? []).some((a) => a.id === "run-verification") && h.state().activeFindingCheckId === "IOT-MQTT-02", "verify only offers the button");
    const ev = await ask(h, "What evidence do you have for the first one?", { deterministic: true });
    check(ev.text.endsWith(`That observation is why “${MQTT_TITLE}” was reported.`), ev.text);
    pass("17 \"the second one\", \"the other one\", \"the high one\", \"the encryption one\" and numbers pick a listed issue");
  }

  // 18. Unclear references ask; nothing is guessed.
  {
    const h = harness(contextComplete);
    await ask(h, "What did you find?");
    const mqtt = await ask(h, "What about the MQTT one?", { deterministic: true });
    check(mqtt.text === "Which issue do you mean? Choose one:" && mqtt.card?.kind === "ISSUES" && mqtt.card.issues.length === 2, mqtt.text);
    const third = await ask(h, "the third one", { deterministic: true });
    check(third.text === "Which issue do you mean? Choose one:", third.text);
    const low = await ask(h, "Explain the low one", { deterministic: true });
    check(low.text === "Your latest check didn't report an important LOW issue. These are the important ones:", low.text);
    const fresh = await ask(harness(contextComplete), "What are these two?", { deterministic: true });
    check(fresh.text === "Which part would you like me to explain?", `nothing listed yet: ${fresh.text}`);
    const first = await ask(harness(contextComplete), "the first one", { deterministic: true });
    check(first.text === "Which issue do you mean? Choose one:" && first.card?.kind === "ISSUES", "ordinal without a list shows the list");
    const none = await ask(harness(contextNone, null), "What are these two?", { deterministic: true });
    check(none.text === "There's no completed security check to explain yet. Run a security check first.", none.text);
    pass("18 ambiguous, out-of-range or unbound references ask one short question");
  }

  // 19. What "these" refers to follows the conversation.
  {
    const h = harness(contextComplete);
    await ask(h, "Is my network safe?");
    check(same(h.state().shownIssues, ["IOT-MQTT-01", "IOT-MQTT-02"]), "status bullets are a list too");
    const after = await ask(h, "What are these two?", { deterministic: true });
    check(after.text.startsWith("Here's what the two issues mean:"), after.text);
    await ask(h, "Which ports are open?");
    check(h.state().shownIssues.length === 0, "a ports answer replaces the issue list");
    const ports = await ask(h, "What are these two?", { deterministic: true });
    check(ports.text === "Which port do you mean? Your latest check recorded ports 139, 445 and 1883 as open.", `after ports: ${ports.text}`);
    pass("19 \"these\" refers to the last list shown; after a ports answer it asks which port");
  }

  // 20. Other requests keep their meaning.
  {
    const h = harness(contextComplete);
    await ask(h, "What are these security issues?");
    const verify = await ask(h, "Did I fix both?", { deterministic: true });
    check((verify.actions ?? []).some((a) => a.id === "run-verification"), "\"Did I fix both?\" is a verification request");
    const compare = await ask(h, "What changed between the two checks?", { deterministic: true });
    check(compare.text === "Run a new security check first so I can compare it with your previous check.", compare.text);
    await ask(h, "What did you find?");
    const list = await ask(h, "What are these security issues?", { deterministic: true });
    check(list.card?.kind === "ISSUES", "issue questions still list the issues");
    const port = await ask(h, "Is port 1883 open?", { deterministic: true });
    check(port.text.startsWith("Yes. Port 1883 is open"), port.text);
    check(assessmentPosts().length === 0, "no POST /api/v1/assessments");
    pass("20 verification, comparison, issue and port questions are not taken as references");
  }

  // 14. Static boundary: follow-ups and replies make no requests and compute no risk.
  {
    for (const path of ["src/lib/assistant/followUp.ts", "src/lib/assistant/replies.ts", "src/lib/assistant/references.ts"]) {
      const text = source(path);
      check(!/\bfetch\(|explainWithAssistant|\.explain\(|from "\.\.\/\.\.\/api\//.test(text), `${path} makes no requests`);
      check(!/ollama|11434|qwen/i.test(text), `${path} names no model`);
    }
    check(unexpected.length === 0, `unexpected requests: ${unexpected.join(", ")}`);
    pass("14 follow-ups and replies use recorded data only; only the explain endpoint was ever requested");
  }
} finally {
  globalThis.fetch = realFetch;
  await server.close();
}

for (const line of results) console.log(line);
console.log(`${results.filter((line) => line.startsWith("PASS")).length} checks passed`);
