/**
 * Checks for deterministic factual answers in the assistant: status questions
 * and TECHNICAL questions (ports, services, devices, findings, evidence, risk
 * factors). The real API clients are used; globalThis.fetch is a recorder that
 * answers only POST /api/v1/assistant/explain and fails on anything else, so a
 * deterministic answer that reached the model endpoint or started a check
 * would be caught. Fixtures are test-only and never persisted.
 *
 * Run from frontend/:  node src/lib/assistant/facts.test.ts
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
type FactsLib = typeof import("./facts.ts");
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

const scanEv = evidence("NMAP_SCAN", "RESPONDED", "NMAP", null, {
  args: "nmap -sT -p 21,22 192.0.2.44", host_state: "up", open_ports: [139, 445, 1883],
});
const p139 = nmapPort(139, "netbios-ssn", "Microsoft Windows netbios-ssn");
const p445 = nmapPort(445, "microsoft-ds", null);
const p1883 = nmapPort(1883, "mosquitto version 2.1.2", null);
const anonEv = evidence("MQTT_ANONYMOUS_CONNECT", "ACCEPTED", "MQTT_PROBE", 1883, { connection_accepted: true });
const plainEv = evidence("MQTT_TRANSPORT_COMPARISON", "PLAINTEXT_NO_TLS", "MQTT_PROBE", 1883, { tls_port: 8883 });
const tlsEv = evidence("TLS_HANDSHAKE", "REFUSED", "TLS_PROBE", 8883, { error_type: "ConnectionRefusedError" });

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
    remediation: `Recorded remediation for ${findingId}.`,
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
  device_criticality: { normalized_value: 0.9, weight: 0.05, contribution_to_100: 4.5 },
  firmware_security: { normalized_value: 0.5, weight: 0.05, contribution_to_100: 2.5 },
};
const contextInputs = {
  authentication_security: { source: "MQTT_PROBE" },
  protocol_security: { source: "ACTIVE_PROBE" },
  network_exposure: { source: "NMAP" },
  device_criticality: { source: "CONFIGURATION" },
  firmware_security: { source: "CONFIGURATION" },
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
/** Same check with nothing technical recorded. */
const bareDetail: AssessmentDetail = {
  ...latest,
  metadata: {},
  evidence: [],
  findings: [{ ...mqtt01, evidence_reference: null }],
  risk_snapshots: [],
  risk_trace: null,
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
  const factsLib = await load<FactsLib>("/src/lib/assistant/facts.ts");
  const wf = await load<WorkflowLib>("/src/lib/assistant/workflow.ts");
  const assistantApi = await load<AssistantApi>("/src/api/assistant.ts");
  const { AssistantView } = await load<PageModule>("/src/components/assistant/AssistantPage.tsx");

  const contextComplete = ctx.buildAssistantContext([latest, older], { status: "ready", detail: latestDetail });
  const contextBare = ctx.buildAssistantContext([latest, older], { status: "ready", detail: bareDetail });
  const contextNone = ctx.buildAssistantContext([]);
  const contextRunning = ctx.buildAssistantContext([summary("RUNNING", "2026-10-14T08:00:00Z"), latest]);

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
  const explainCalls = (from = 0) =>
    recorded.slice(from).filter((call) => call.method === "POST" && call.url.endsWith("/api/v1/assistant/explain"));

  /** Asks one question and checks it stayed deterministic: no model call, no check, no navigation. */
  async function askFact(text: string, context: Context | null = contextComplete, detail: AssessmentDetail | null = latestDetail, h?: Harness) {
    const run = h ?? harness(context, detail);
    const before = recorded.length;
    const outcome = await run.handleAssistantRequest(text);
    check(outcome.status === "answered", `${text}: answered`);
    check(recorded.length === before, `${text}: made ${recorded.length - before} request(s)`);
    check(run.navigations.length === 0, `${text}: navigated`);
    return { h: run, reply: run.last() };
  }
  const factsCard = (message: AssistantMessage) => {
    check(message.card?.kind === "FACTS", `facts card expected, got ${message.card?.kind}`);
    return message.card;
  };
  const RAW_ID = /IOT-MQTT-0\d|NET-0\d|[0-9a-f]{7}0-0000-4000-8000/;
  const STATUS_TEXT = [
    "Your current risk is HIGH (70.5/100).",
    "The main priorities from your latest check:",
    "• MQTT broker accepts connections without a password — HIGH",
    "• MQTT traffic is not encrypted — MEDIUM",
    "Fix these first, then run another check.",
  ].join("\n");

  // 1. Classification of the required questions and their variants.
  {
    const expected: [string, string, string | null][] = [
      ["Is my IoT network safe?", "SUMMARY", null],
      ["Am I safe?", "SUMMARY", null],
      ["How secure is my network?", "SUMMARY", null],
      ["What's my security status?", "SUMMARY", null],
      ["What is my risk?", "SUMMARY", null],
      ["Are any ports open?", "TECHNICAL", "PORTS"],
      ["What ports are open?", "TECHNICAL", "PORTS"],
      ["Which ports are open?", "TECHNICAL", "PORTS"],
      ["Show me open ports.", "TECHNICAL", "PORTS"],
      ["is there any port open?", "TECHNICAL", "PORTS"],
      ["Is port 1883 open?", "TECHNICAL", "PORTS"],
      ["What services are running?", "TECHNICAL", "SERVICES"],
      ["Which services are exposed?", "TECHNICAL", "SERVICES"],
      ["What services did you find?", "TECHNICAL", "SERVICES"],
      ["What devices did you check?", "TECHNICAL", "DEVICES"],
      ["What vulnerabilities did you find?", "TECHNICAL", "FINDINGS"],
      ["What security problems were found?", "TECHNICAL", "FINDINGS"],
      ["Show me the findings.", "TECHNICAL", "FINDINGS"],
      ["What evidence do you have?", "TECHNICAL", "EVIDENCE"],
      ["How do you know this is vulnerable?", "TECHNICAL", "EVIDENCE"],
      ["Why did you flag this?", "TECHNICAL", "EVIDENCE"],
      ["Why is my risk high?", "TECHNICAL", "RISK_FACTORS"],
      ["Why is my score so high?", "TECHNICAL", "RISK_FACTORS"],
      ["What contributes to my risk?", "TECHNICAL", "RISK_FACTORS"],
      ["Explain my risk", "EXPLAIN", "RISK"],
      ["Summarize results", "SUMMARY", null],
      ["Check my network", "CHECK", null],
      ["How do I fix this?", "FIX", null],
      ["Did I fix it?", "VERIFY", null],
      ["What changed?", "COMPARE", null],
    ];
    for (const [text, intent, subject] of expected) {
      const r = intents.classifyAssistantIntent(text);
      check(r.intent === intent && r.subject === subject, `"${text}" -> ${r.intent}/${r.subject} (${r.reason})`);
    }
    check(!intents.STATUS_PHRASES.includes("summarize results"), "explicit summaries are not status questions");
    pass("1 required questions classify to SUMMARY status / TECHNICAL topics; existing intents unchanged", `${expected.length} phrasings`);
  }

  // 2-4. Status questions: recorded risk and counts, no model call.
  for (const [n, text] of [[2, "Is my IoT network safe?"], [3, "Am I safe?"], [4, "What is my risk?"]] as const) {
    const { h, reply } = await askFact(text);
    check(reply.text === STATUS_TEXT, `${text}: ${reply.text}`);
    check(!reply.source && !reply.card, "plain deterministic reply, no AI label");
    check(same(reply.actions?.map((a) => a.label), ["Review issues", "How do I fix it?", "Why is my risk high?"]), `actions ${JSON.stringify(reply.actions)}`);
    check(!RAW_ID.test(reply.text), "no raw IDs");
    check(h.state().lastAction === "SUMMARY", "workflow updated");
    pass(`${n} "${text}" answered from recorded risk and issue counts`);
  }

  // 5-6. Open ports.
  for (const [n, text] of [[5, "Are any ports open?"], [6, "What ports are open?"]] as const) {
    const { reply } = await askFact(text);
    check(
      reply.text === "Your latest check recorded 3 open ports.\nAn open port is not automatically a security problem.",
      reply.text,
    );
    const card = factsCard(reply);
    check(
      same(card.items, [
        { title: "Port 139 (TCP)", detail: "Microsoft Windows netbios-ssn" },
        { title: "Port 445 (TCP)", detail: "microsoft-ds" },
        { title: "Port 1883 (TCP)", detail: "mosquitto version 2.1.2" },
      ]),
      JSON.stringify(card.items),
    );
    check(card.technical.some((line) => line.startsWith("Ports checked: 21, 22")), "checked ports only under technical details");
    check(!card.technical.join(" ").includes("nmap -sT"), "scanner arguments are never shown");
    pass(`${n} "${text}" lists only recorded open ports with recorded services`);
  }

  // 7. A specific port.
  {
    const open = (await askFact("Is port 1883 open?")).reply.text;
    check(
      open === "Yes. Port 1883 is open — the scan identified mosquitto version 2.1.2.\nAn open port is not automatically a security problem.",
      open,
    );
    const closed = (await askFact("Is port 22 open?")).reply.text;
    check(closed === "No. Port 22 was checked and wasn't found open.", closed);
    const unscanned = (await askFact("Is port 9999 open?")).reply.text;
    check(
      unscanned === "I don't have enough evidence to say whether port 9999 is open. It wasn't part of your latest check.",
      unscanned,
    );
    check((await askFact("Is 8883 open?")).reply.text === "No. Port 8883 was checked and wasn't found open.", "bare port question");
    check(factsLib.askedPort("is port 70000 open") === null && factsLib.askedPort("port 8883?") === 8883, "port parsing");
    pass("7 \"Is port 1883 open?\" answered from recorded ports and the checked-port list");
  }

  // 8. Services.
  {
    const { reply } = await askFact("What services are running?");
    check(reply.text === "Your latest check recorded 3 services on open ports.", reply.text);
    const one = (await askFact("What is running on port 1883?")).reply.text;
    check(one === "Port 1883 is running mosquitto version 2.1.2, as identified by the network scan.", one);
    check(
      same(factsCard(reply).items.map((item) => item.title), ["Microsoft Windows netbios-ssn", "microsoft-ds", "mosquitto version 2.1.2"]),
      "recorded service names only",
    );
    pass("8 \"What services are running?\" returns recorded services only");
  }

  // 9. Findings route to the existing issue list.
  {
    const { reply } = await askFact("What vulnerabilities did you find?");
    check(
      reply.text ===
        "I found 7 findings in your latest check: 2 important issues and 5 additional lower-severity findings.\nChoose an important issue to see why it matters and how to fix it.",
      reply.text,
    );
    check(
      reply.card?.kind === "ISSUES" && reply.card.issues.length === 2 && reply.card.minorIssues === 1 && reply.card.additionalFindings === 5,
      "existing issues card, with the additional findings counted",
    );
    check(
      same(reply.actions?.map((a) => a.label), ["Review issues", "Which one is most serious?", "What evidence do you have?", "View all findings"]),
      JSON.stringify(reply.actions),
    );
    pass("9 \"What vulnerabilities did you find?\" uses the existing findings list");
  }

  // 10. Evidence.
  {
    const { reply } = await askFact("What evidence do you have?");
    check(reply.text === "Here's what your latest check observed for each issue:", reply.text);
    const card = factsCard(reply);
    check(
      same(card.items, [
        {
          title: "MQTT broker accepts connections without a password (HIGH)",
          detail: "The MQTT broker on port 1883 accepted a connection without a username or password.",
        },
        {
          title: "MQTT traffic is not encrypted (MEDIUM)",
          detail: "The MQTT broker on port 1883 accepted an unencrypted connection, and no encrypted (TLS) connection was available.",
        },
        {
          title: "An administrative service is reachable (LOW)",
          detail: "The network scan found port 139 open. The network scan found port 445 open.",
        },
      ]),
      JSON.stringify(card.items),
    );
    check(card.items.every((item) => !RAW_ID.test(`${item.title} ${item.detail}`)), "no IDs outside technical details");
    check(card.technical[0] === "IOT-MQTT-01: MQTT_ANONYMOUS_CONNECT = ACCEPTED, source MQTT_PROBE, port 1883", card.technical[0]);

    const focused = harness(contextComplete, latestDetail, { activeFindingCheckId: "IOT-MQTT-02" });
    const why = (await askFact("Why did you flag this?", contextComplete, latestDetail, focused)).reply;
    check(
      why.text ===
        "The MQTT broker on port 1883 accepted an unencrypted connection, and no encrypted (TLS) connection was available.\nThat observation is why “MQTT traffic is not encrypted” was reported.",
      why.text,
    );
    check(factsCard(why).items.length === 0 && factsCard(why).technical[0].startsWith("IOT-MQTT-02:"), "only the issue under discussion");
    pass("10 \"What evidence do you have?\" answered from linked evidence records");
  }

  // 11. Risk factors.
  {
    const { reply } = await askFact("Why is my risk high?");
    check(
      reply.text ===
        [
          "Your current risk is HIGH (70.5/100).",
          "The largest recorded contributions are:",
          "• Authentication Security",
          "• Protocol Security",
          "• Network Exposure",
          "Start with the highest-severity issue: “MQTT broker accepts connections without a password” (HIGH).",
        ].join("\n"),
      reply.text,
    );
    check(!/comes from|determin|because of/i.test(reply.text), "no claim that one issue alone sets the score");
    const card = factsCard(reply);
    check(card.items.length === 0 && !card.expanded, "contribution values stay under collapsed technical details");
    check(
      same(card.technical.slice(0, 5), [
        "Authentication Security: +10.0 · observed in this check",
        "Protocol Security: +10.0 · observed in this check",
        "Network Exposure: +6.0 · observed in this check",
        "Device Criticality: +4.5 · configured, not observed",
        "Firmware Security: +2.5 · configured, not observed",
      ]),
      JSON.stringify(card.technical),
    );
    check(card.technical.includes("Overall score recorded from: IOT-MQTT-01 (HIGH)"), "trace link only under technical details");
    check(same(reply.actions?.map((a) => a.label), ["Explain my risk", "Review issues"]), "AI explanation stays one click away");
    for (const text of ["Why is my score so high?", "What contributes to my risk?"]) {
      check((await askFact(text)).reply.text === reply.text, `${text} same recorded answer`);
    }
    pass("11 \"Why is my risk high?\" answered from recorded contributors and the backend trace");
  }

  // 12. Devices.
  {
    const { reply } = await askFact("What devices did you check?");
    check(
      reply.text ===
        `Your latest check covered one authorized target: ${TARGET}. It responded with 3 open ports.\nOther devices on your network weren't checked.`,
      reply.text,
    );
    pass("12 devices: only the recorded authorized target");
  }

  // 13. Nothing recorded -> says so; nothing invented.
  {
    const ask = async (text: string) => (await askFact(text, contextBare, bareDetail)).reply;
    check((await ask("What ports are open?")).text === factsLib.PORTS_NOT_AVAILABLE, "ports not available");
    check((await ask("Is port 1883 open?")).text === factsLib.PORTS_NOT_AVAILABLE, "specific port not available");
    check((await ask("What services are running?")).text === factsLib.SERVICES_NOT_AVAILABLE, "services not available");
    check((await ask("Why is my risk high?")).text === factsLib.RISK_FACTORS_NOT_AVAILABLE, "risk factors not available");
    const ev = await ask("What evidence do you have?");
    check(factsCard(ev).items[0].detail === "Evidence not available for this finding.", "evidence not available");
    check(!/\b(139|445|1883)\b/.test(JSON.stringify((await ask("What ports are open?")))), "no port invented");
    const missing = harness(contextComplete, null);
    const r = (await askFact("What ports are open?", contextComplete, null, missing)).reply;
    check(r.tone === "error" && r.text === "I couldn't load the details of your latest check. You can try again.", "detail not loaded");
    pass("13 missing data is stated as not available; nothing is invented");
  }

  // 14. No completed check: blocked replies, no model call.
  {
    const none = (await askFact("What ports are open?", contextNone, null)).reply;
    check(none.text === "I need a completed security check before I can answer that. Run a security check first.", none.text);
    check(same(none.suggestions, ["check"]), "offers a check");
    const running = (await askFact("Why is my risk high?", contextRunning, null)).reply;
    check(running.text.startsWith("Your latest security check is still running"), running.text);
    pass("14 technical questions without a completed check are blocked without a model call");
  }

  // 15. Existing flows still work.
  {
    const from = recorded.length;
    const h = harness(contextComplete);
    await h.handleAssistantRequest("Explain my risk");
    check(explainCalls(from).length === 1 && explainCalls(from)[0].body === '{"intent":"EXPLAIN","subject":"RISK"}', "Explain my risk uses the AI explanation");
    check(h.last().source === "AI", "AI reply labelled");
    const sum = recorded.length;
    await h.handleAssistantRequest("Summarize results");
    check(explainCalls(sum).length === 1 && explainCalls(sum)[0].body === '{"intent":"SUMMARY"}', "Summarize results uses the AI summary");
    const fixFrom = recorded.length;
    await h.handleAssistantRequest("How do I fix this?");
    check(explainCalls(fixFrom).length === 0 && h.last().card?.kind === "FIX_LIST", "FIX asks which issue first");
    await h.handleAssistantRequest("Check my network");
    check(same(h.last().actions?.map((a) => a.id), ["run-check", "open-check-form"]), "CHECK offers the explicit run button");
    await h.handleAssistantRequest("Did I fix it?");
    check(same(h.last().actions?.map((a) => a.id), ["run-verification", "not-yet"]), "VERIFY offers the explicit verification button");
    await h.handleAssistantRequest("What changed?");
    check(h.last().text === "Run a new security check first so I can compare it with your previous check.", "COMPARE without a pair");
    check(!recorded.some((call) => call.method === "POST" && call.url.endsWith("/api/v1/assessments")), "no check was started");
    check(h.navigations.length === 0, "no navigation");
    pass("15 EXPLAIN (AI), SUMMARY (AI), FIX, CHECK, VERIFY and COMPARE behave as before");
  }

  // 16. Rendering: title and severity on separate lines; technical details collapsed.
  {
    const h = harness(contextComplete);
    await h.handleAssistantRequest("What ports are open?");
    h.selectIssue("IOT-MQTT-01");
    await h.handleAssistantRequest("Explain my risk");
    const html = renderToStaticMarkup(createElement(AssistantView, {
      context: contextComplete, assessmentsError: null, onRetryAssessments: () => {},
      messages: h.messages, status: null,
      onRequest: (): Promise<RequestOutcome> => Promise.resolve({ status: "rejected", reason: "empty" }),
      onOpenAction: () => {}, running: null, onRunCheck: () => {}, onSelectIssue: () => {}, onWorkflowNavigate: () => {},
    }));
    const text = html.replace(/<[^>]+>/g, "");
    check(!text.includes("passwordHIGH"), "title and severity are not run together");
    check(
      /data-issue-title="">MQTT broker accepts connections without a password<\/span><span[^>]*data-issue-severity="">Severity: <span[^>]*>HIGH<\/span>/.test(html),
      "title, then Severity: HIGH",
    );
    check(html.includes("Why it matters: </span>") && html.includes('data-next-step=""'), "structured issue card");
    check(/<details data-technical=""(?![^>]*\bopen\b)[^>]*><summary[^>]*>Show technical details<\/summary>/.test(html), "technical details collapsed");
    check(/<details data-provenance(?![^>]*\bopen\b)/.test(html), "About this explanation stays collapsed");
    const outsideDetails = html.replace(/<details[\s\S]*?<\/details>/g, "");
    check(!RAW_ID.test(outsideDetails.replace(/<[^>]+>/g, "")), "no raw IDs outside technical details");
    pass("16 cards: title then \"Severity: HIGH\"; technical details and provenance collapsed");
  }

  // 17. Static boundary of the deterministic answers.
  {
    const text = source("src/lib/assistant/facts.ts");
    check(!/\bfetch\(|explainWithAssistant|\.explain\(|from "\.\.\/\.\.\/api\/(assessments|assistant|client|security)"/.test(text), "facts.ts makes no requests and no model call");
    check(!/\*\s*(item|c)\.(weight|normalizedValue)|contribution\s*[*+]\s*/.test(text), "facts.ts does not compute risk");
    check(unexpected.length === 0, `unexpected requests: ${unexpected.join(", ")}`);
    pass("17 deterministic answers use recorded data only; only the explain endpoint was ever requested");
  }

  // 18. Environment assessment: devices, infrastructure, assets, and asset-specific findings.
  {
    const envSummaryItem: AssessmentSummary = {
      id: uuid("env"),
      target: "AUTHORIZED_IOT",
      assessment_type: "ENVIRONMENT",
      status: "COMPLETE",
      started_at: "2026-11-03T18:00:00Z",
      completed_at: "2026-11-03T18:01:00Z",
      error_summary: null,
      metadata: {
        posture: {
          assets_assessed: 3,
          assets_completed: 3,
          devices_assessed: 2,
          infrastructure_assessed: 1,
          device_summaries: [
            { device_id: "ESP32-01", ip_address: "10.32.252.105", status: "COMPLETE", highest_risk_level: null, findings_count: 0 },
            { device_id: "ESP32-02", ip_address: "10.32.252.57", status: "COMPLETE", highest_risk_level: null, findings_count: 0 },
          ],
          infrastructure_summaries: [
            { asset_id: "MQTT-BROKER", ip_address: "10.32.252.85", status: "COMPLETE", highest_risk_level: "HIGH", findings_count: 2 },
          ],
        },
      } as AssessmentSummary["metadata"],
      created_at: "2026-11-03T18:00:00Z",
      evidence_count: 5,
      finding_count: 2,
      highest_risk: 70.5,
      highest_risk_level: "HIGH",
    };

    const envDetailItem: AssessmentDetail = {
      ...envSummaryItem,
      evidence: [
        {
          id: uuid("e"),
          assessment_id: envSummaryItem.id,
          target: "10.32.252.85",
          port: 1883,
          check_type: "NMAP_PORT",
          result: "OPEN",
          evidence_source: "NMAP",
          observation: { port: 1883, state: "open", service_name: "mqtt", product: "mosquitto 2.1.2" },
          observed_at: "2026-11-03T18:00:10Z",
        },
      ],
      findings: [
        {
          id: uuid("f"),
          assessment_id: envSummaryItem.id,
          finding_id: "IOT-MQTT-01",
          finding_type: "MQTT_ANONYMOUS",
          category: "AUTHENTICATION",
          title: "Anonymous MQTT Access Allowed",
          severity: "HIGH",
          confidence: 1.0,
          description: "Broker allows anonymous connection",
          target: "10.32.252.85",
          port: 1883,
          evidence_reference: null,
          remediation: "Set allow_anonymous false",
          status: "OPEN",
          created_at: "2026-11-03T18:00:30Z",
        },
      ],
      risk_snapshots: [],
    };

    const envContext = ctx.buildAssistantContext([envSummaryItem], {
      status: "ready",
      detail: { id: envSummaryItem.id, findings: envDetailItem.findings, risk_snapshots: [] },
    });

    const askEnv = async (q: string) => (await askFact(q, envContext, envDetailItem)).reply;

    const devAns = await askEnv("How many devices were assessed?");
    check(devAns.text.includes("2 authorized IoT devices"), "answers device count");
    check(devAns.text.includes("ESP32-01") && devAns.text.includes("ESP32-02"), "lists ESP32 devices");

    const assetAns = await askEnv("How many assets were assessed?");
    check(assetAns.text.includes("3 authorized assets in total"), "answers total asset count");

    const infraAns = await askEnv("What infrastructure was assessed?");
    check(infraAns.text.includes("MQTT-BROKER") && infraAns.text.includes("10.32.252.85"), "answers infrastructure");

    const brokerAns = await askEnv("What did the MQTT broker find?");
    check(brokerAns.text.includes("Anonymous MQTT Access Allowed — HIGH"), "answers broker findings");

    const esp1Ans = await askEnv("What did ESP32-01 find?");
    check(esp1Ans.text.includes("no security findings"), "ESP32-01 has no findings");

    const esp2Ans = await askEnv("What did ESP32-02 find?");
    check(esp2Ans.text.includes("no security findings"), "ESP32-02 has no findings");

    const checkAns = await askEnv("What did my latest security check find?");
    check(checkAns.text.includes("Anonymous MQTT Access Allowed"), "answers latest check findings");

    pass("18 environment assessment: devices, infrastructure, assets, and asset findings answered deterministically");
  }
} finally {
  globalThis.fetch = realFetch;
  await server.close();
}

for (const line of results) console.log(line);
console.log(`${results.filter((line) => line.startsWith("PASS")).length} checks passed`);
