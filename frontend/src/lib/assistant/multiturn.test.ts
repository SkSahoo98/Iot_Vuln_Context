/**
 * Multi-turn checks for the assistant's conversation state: a whole dialogue
 * about the listed issues (group, ranking, "the other one", why, fix, switch
 * back, AI explanation), switches to ports, risk and services, positional,
 * group and description references, short follow-ups, general questions, and
 * the boundaries (no check started from wording, AI only when an explanation
 * is asked for). globalThis.fetch is a recorder that answers only
 * POST /api/v1/assistant/explain and fails on anything else. Fixtures are
 * test-only and never persisted.
 *
 * Run from frontend/:  node src/lib/assistant/multiturn.test.ts
 */
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
import type { AssistantMessage } from "./conversation.ts";
import type { AssistantWorkflowState } from "./workflow.ts";

declare const process: { cwd(): string };

type ViteServer = {
  ssrLoadModule(url: string): Promise<Record<string, unknown>>;
  close(): Promise<void>;
};
type ConversationLib = typeof import("./conversation.ts");
type ContextLib = typeof import("./context.ts");
type WorkflowLib = typeof import("./workflow.ts");
type AssistantApi = typeof import("../../api/assistant.ts");
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
const vite = (await import(viteModuleName)) as { createServer(config: Record<string, unknown>): Promise<ViteServer> };
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
  const assistantApi = await load<AssistantApi>("/src/api/assistant.ts");

  const contextComplete = ctx.buildAssistantContext([latest, older], { status: "ready", detail: latestDetail });

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

  const AUTH_MEANING = "The broker accepted a connection that supplied no username or password.";
  const ENC_MEANING = "The broker accepted unencrypted MQTT and no encrypted MQTT listener was reachable.";
  const ENC_FIX = "Recorded remediation for IOT-MQTT-02.";
  const GROUP_TEXT = `Here's what the two issues mean:\n• ${MQTT_TITLE} (HIGH): ${AUTH_MEANING}\n• ${ENC_TITLE} (MEDIUM): ${ENC_MEANING}`;
  const CLARIFY = "Which part would you like me to explain?";
  const PORT_CHOICE = "Which port do you mean? Your latest check recorded ports 139, 445 and 1883 as open.";
  const ALLOWED_KEYS = new Set(["intent", "subject", "issue"]);
  const noGeneric = (h: Harness, label: string) =>
    check(!h.messages.some((m) => m.role === "assistant" && m.text === conv.UNKNOWN_REPLY), `${label}: generic reply in the conversation`);
  const selected = (h: Harness) => h.state().activeFindingCheckId;
  const cardText = (m: AssistantMessage) => JSON.stringify(m.card ?? null);
  /** A conversation that has just shown the two-issue list. */
  async function listed() {
    const h = harness(contextComplete);
    await ask(h, "What are these security issues?", { deterministic: true });
    return h;
  }

  // 1. The full multi-turn conversation.
  {
    const h = await listed();
    const from = recorded.length;
    const two = await ask(h, "What are these two?", { deterministic: true });
    check(two.text === GROUP_TEXT, `these two: ${two.text}`);
    const worse = await ask(h, "Which one is worse?", { deterministic: true });
    check(worse.text.startsWith(`“${MQTT_TITLE}” is the most serious — HIGH.`) && selected(h) === "IOT-MQTT-01", `worse: ${worse.text}`);
    const other = await ask(h, "What about the other one?", { deterministic: true });
    check(other.text === `${ENC_TITLE} — MEDIUM.\n${ENC_MEANING}` && selected(h) === "IOT-MQTT-02", `other: ${other.text}`);
    const why = await ask(h, "Why is that a problem?", { deterministic: true });
    check(why.text === `Messages sent to the broker may be readable by anyone who can see the network traffic.\nFix: ${ENC_FIX}`, `why: ${why.text}`);
    const fix = await ask(h, "How do I fix it?", { deterministic: true });
    check(fix.card?.kind === "GUIDED_FIX" && fix.card.guide.checkId === "IOT-MQTT-02" && fix.card.guide.recordedFix === ENC_FIX, "fix: backend remediation of the referenced issue");
    const first = await ask(h, "And the first one?", { deterministic: true });
    check(first.text === `${MQTT_TITLE} — HIGH.\n${AUTH_MEANING}` && selected(h) === "IOT-MQTT-01", `first: ${first.text}`);
    const moreFrom = recorded.length;
    const more = await ask(h, "Tell me more.");
    check(same(explainCalls(moreFrom).map((c) => c.body), ['{"intent":"EXPLAIN","subject":"ISSUES","issue":"IOT-MQTT-01"}']), "tell me more: AI explanation of the active issue");
    check(more.source === "AI" && more.card?.kind === "ISSUE" && cardText(more).includes(MQTT_TITLE), "AI text sits under the recorded issue card");
    check(explainCalls(from).length === 1, `AI requests in the conversation: ${explainCalls(from).length}`);
    for (const m of [two, worse, other, first]) compact(m, m.text.slice(0, 24));
    noGeneric(h, "multi-turn");
    pass("1 list → these two → worse → other → why → fix → first → tell me more keeps the right issue at every turn", "1 AI request (tell me more); the fix is deterministic");
  }

  // 2. Context switch to ports: positions never fall back to the old issue list.
  {
    const h = await listed();
    await ask(h, "What are these two?");
    await ask(h, "Which ports are open?", { deterministic: true });
    for (const text of ["What about the second one?", "And the first one?", "The other one", "What are these two?"]) {
      const r = await ask(h, text, { deterministic: true });
      check(r.text === PORT_CHOICE && !r.card, `${text} after ports: ${r.text}`);
      check(selected(h) === null, `${text}: no issue selected from the old list`);
    }
    noGeneric(h, "ports switch");
    pass("2 list → ports → \"the second one\" asks which port; the old issue list is not used");
  }

  // 3. Context switch to risk.
  {
    const h = await listed();
    await ask(h, "What are these two?");
    const risk = await ask(h, "What's my risk?", { deterministic: true });
    check(risk.text.startsWith("Your current risk is HIGH (70.5/100)."), risk.text);
    const why = await ask(h, "Why?", { deterministic: true });
    check(why.text.startsWith("Your current risk is HIGH (70.5/100).\nThe largest recorded contributions are:"), `why after risk: ${why.text}`);
    check(!why.text.startsWith("Here's what") && !why.text.includes("Fix:"), "not an issue explanation");
    pass("3 list → risk → \"Why?\" explains the risk, not an issue");
  }

  // 4. Context switch to services.
  {
    const h = harness(contextComplete);
    await ask(h, "What services are running?", { deterministic: true });
    const several = await ask(h, "What is that?", { deterministic: true });
    check(several.text === "Which service do you mean? Your latest check recorded services on ports 139, 445 and 1883.", several.text);
    await ask(h, "What is running on port 1883?", { deterministic: true });
    const one = await ask(h, "What is that?", { deterministic: true });
    check(one.text === "Port 1883 is running mosquitto version 2.1.2, as identified by the network scan.", one.text);

    const singleDetail: AssessmentDetail = { ...latestDetail, evidence: latestDetail.evidence.filter((e) => e.check_type !== "NMAP_PORT" || e.port === 1883) };
    const single = harness(ctx.buildAssistantContext([latest, older], { status: "ready", detail: singleDetail }), singleDetail);
    await ask(single, "What services are running?", { deterministic: true });
    const only = await ask(single, "What is that?", { deterministic: true });
    check(only.text === one.text, `exactly one service: ${only.text}`);
    pass("4 services → \"What is that?\" asks which service when several are shown, answers when exactly one is active");
  }

  // 5. Positional references.
  {
    const cases: [string, string | null, string][] = [
      ["The first one", "IOT-MQTT-01", `${MQTT_TITLE} — HIGH.`],
      ["The second one", "IOT-MQTT-02", `${ENC_TITLE} — MEDIUM.`],
      ["The last one", "IOT-MQTT-02", `${ENC_TITLE} — MEDIUM.`],
      ["The more serious one", "IOT-MQTT-01", `“${MQTT_TITLE}” is the most serious — HIGH.`],
      ["The high severity one", "IOT-MQTT-01", `${MQTT_TITLE} — HIGH.`],
      ["The third one", null, "Which issue do you mean? Choose one:"],
    ];
    for (const [text, id, start] of cases) {
      const h = await listed();
      const r = await ask(h, text, { deterministic: true });
      check(r.text.startsWith(start) && selected(h) === id, `${text}: ${r.text} (${selected(h)})`);
    }
    const h = await listed();
    await ask(h, "The second one");
    const other = await ask(h, "The other one", { deterministic: true });
    check(other.text.startsWith(`${MQTT_TITLE} — HIGH.`), `the other one: ${other.text}`);
    const noSelection = await ask(await listed(), "The other one", { deterministic: true });
    check(noSelection.text === "Which issue do you mean? Choose one:", "\"the other one\" with nothing selected asks");
    pass("5 first, second, last, other, more serious and high-severity resolve; the third of two asks", `${cases.length + 2} references`);
  }

  // 6. Group references.
  {
    for (const text of ["these two", "both", "both of them", "these issues", "those two", "the two problems"]) {
      const r = await ask(await listed(), text, { deterministic: true });
      check(r.text === GROUP_TEXT, `${text}: ${r.text}`);
    }
    pass("6 these two, both, both of them, these issues, those two and the two problems mean the displayed issues");
  }

  // 7. Description references.
  {
    for (const [text, id] of [["The authentication one", "IOT-MQTT-01"], ["The password one", "IOT-MQTT-01"], ["The encryption one", "IOT-MQTT-02"], ["The TLS one", "IOT-MQTT-02"]]) {
      const h = await listed();
      await ask(h, text, { deterministic: true });
      check(selected(h) === id, `${text} -> ${selected(h)}`);
    }
    const mqtt = await ask(await listed(), "The MQTT one", { deterministic: true });
    check(mqtt.text === "Which issue do you mean? Choose one:" && mqtt.card?.kind === "ISSUES" && mqtt.card.issues.length === 2, mqtt.text);
    const h = await listed();
    const none = await ask(h, "The telnet one", { deterministic: true });
    check(none.text === "I couldn't match that to one of the current issues. These are the current ones:" && none.card?.kind === "ISSUES", none.text);
    check(selected(h) === null, "no invented match");
    pass("7 authentication/password/encryption/TLS resolve; MQTT asks which; telnet is not matched");
  }

  // 8. Short follow-ups use the active issue; without context they ask once.
  {
    const followUps = ["Why?", "How?", "What?", "Is it bad?", "Is that serious?", "What does that mean?", "What should I do?", "Tell me more.", "Explain that.", "How do I fix it?"];
    for (const text of followUps) {
      const h = await listed();
      await ask(h, "The first one");
      const r = await ask(h, text);
      const about = `${r.text} ${cardText(r)}`;
      check(about.includes(MQTT_TITLE) || about.includes("Anyone who can reach the broker"), `${text}: not about the active issue: ${r.text}`);
      check(selected(h) === "IOT-MQTT-01", `${text}: subject kept`);
    }
    for (const text of followUps) {
      const r = await ask(harness(contextComplete), text);
      check(r.text === CLARIFY || r.text.startsWith("Which issue do you want to fix?"), `${text} without context: ${r.text}`);
    }
    pass("8 short follow-ups answer about the active issue; without context they ask one short question", `${followUps.length * 2} turns`);
  }

  // 9. "What is this?" without context.
  {
    const r = await ask(harness(contextComplete), "What is this?", { deterministic: true });
    check(r.text === CLARIFY && same(labels(r), ["Security issues", "Risk score", "Open ports"]), r.text);
    pass("9 \"What is this?\" without context offers the available subjects");
  }

  // 10. General questions stay general, even with an active issue.
  {
    for (const text of ["What is cybersecurity?", "What is MQTT?", "What is encryption?", "What is a firewall?"]) {
      const h = await listed();
      await ask(h, "The first one");
      const before = recorded.length;
      await h.handleAssistantRequest(text);
      const r = h.last();
      check(r.text === conv.UNKNOWN_REPLY && !r.card && recorded.length === before, `${text}: ${r.text}`);
    }
    pass("10 cybersecurity, MQTT, encryption and firewall questions are not answered with findings");
  }

  // 11. References cannot start or authorize a check.
  {
    const h = await listed();
    await ask(h, "The first one");
    for (const text of ["Run that again.", "Run it again", "Check it again", "Rescan"]) {
      const r = await ask(h, text, { deterministic: true });
      check(same(r.actions?.map((a) => a.id), ["run-check", "open-check-form"]), `${text}: explicit Run button only`);
      check(!r.text.includes("10.0.0.5"), "no other target");
    }
    for (const text of ["Check that other IP.", "Check 10.0.0.5", "Scan 10.0.0.5 instead"]) {
      const before = recorded.length;
      await h.handleAssistantRequest(text);
      check(recorded.length === before, `${text}: no request`);
      const r = h.last();
      check(!(r.actions ?? []).some((a) => a.id === "run-check" || a.id === "run-verification") && !r.text.includes("10.0.0.5"), `${text}: never offers to check the named address (${r.text})`);
    }
    check(h.state().running === null && assessmentPosts().length === 0, "no check started; no POST /api/v1/assessments");
    pass("11 \"Run that again\" shows the explicit Run button; other addresses are never offered or checked");
  }

  // 12. AI only where an explanation is asked for; requests carry no free text.
  {
    const h = await listed();
    const from = recorded.length;
    for (const text of ["What are these two?", "Which one is worse?", "Why?", "What ports are open?"]) await ask(h, text, { deterministic: true });
    check(explainCalls(from).length === 0, "deterministic turns made no AI request");
    await ask(h, "What are these security issues?");
    await ask(h, "The first one");
    for (const text of ["Tell me more.", "Explain this in more detail.", "Give me a deeper explanation."]) {
      const before = recorded.length;
      const r = await ask(h, text);
      check(same(explainCalls(before).map((c) => c.body), ['{"intent":"EXPLAIN","subject":"ISSUES","issue":"IOT-MQTT-01"}']), `${text}: AI explanation of the active issue`);
      check(r.card?.kind === "ISSUE" && cardText(r).includes(MQTT_TITLE) && cardText(r).includes('"HIGH"'), `${text}: recorded title and severity stay in the card`);
    }
    for (const call of explainCalls(0)) {
      check(Object.keys(JSON.parse(call.body)).every((key) => ALLOWED_KEYS.has(key)), `explain request carries only intent/subject/issue: ${call.body}`);
    }
    check(assessmentPosts().length === 0 && unexpected.length === 0, "no assessment and no other endpoint");
    pass("12 facts, ranking, why and ports need no AI; \"Tell me more\" and deeper explanations send only intent, subject and issue");
  }
} finally {
  globalThis.fetch = realFetch;
  await server.close();
}

for (const line of results) console.log(line);
console.log(`${results.filter((line) => line.startsWith("PASS")).length} checks passed`);
