/**
 * Checks for the deterministic conversational assistant (Phase UX-3B-1).
 * The controller is driven with injected waits and recorded navigation;
 * globalThis.fetch is replaced by a recorder so any network use fails the run.
 * Fixtures are test-only and never persisted.
 *
 * Run from frontend/:  node src/lib/assistant/conversation.test.ts
 */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { AssessmentDetail, AssessmentFinding, AssessmentStatus, AssessmentSummary } from "../../api/types.ts";
import type { NavRequest } from "../navigation.ts";
import type { AssistantMessage, RequestOutcome } from "./conversation.ts";

declare const process: { cwd(): string };

type ViteServer = {
  ssrLoadModule(url: string): Promise<Record<string, unknown>>;
  close(): Promise<void>;
};
type ConversationLib = typeof import("./conversation.ts");
type ContextLib = typeof import("./context.ts");
type IntentsLib = typeof import("./intents.ts");
type ShortcutsLib = typeof import("../assistantActions.ts");
type PageModule = typeof import("../../components/assistant/AssistantPage.tsx");
type FsModule = { readFileSync(path: string, encoding: "utf8"): string };
type Context = ReturnType<ContextLib["buildAssistantContext"]>;

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
let seq = 0;
const uuid = (prefix: string) => `${prefix}0000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`;

function summary(status: AssessmentStatus, startedAt: string, extra: Partial<AssessmentSummary> = {}): AssessmentSummary {
  return {
    id: uuid("a"),
    target: TARGET,
    assessment_type: "MULTI_LAYER",
    status,
    started_at: startedAt,
    completed_at: status === "RUNNING" ? null : startedAt.replace(":00Z", ":40Z"),
    error_summary: null,
    metadata: {} as AssessmentSummary["metadata"],
    created_at: startedAt,
    evidence_count: 4,
    finding_count: 2,
    highest_risk: null,
    highest_risk_level: null,
    ...extra,
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
    remediation: "Fixture remediation text.",
    status: "OPEN",
    created_at: "2026-10-13T19:58:30Z",
  };
}

const older = summary("COMPLETE", "2026-10-12T08:00:00Z", { highest_risk: 41.2, highest_risk_level: "MEDIUM" });
const latest = summary("COMPLETE", "2026-10-13T19:58:00Z", { highest_risk: 70.5, highest_risk_level: "HIGH" });
const partial = summary("INCOMPLETE", "2026-10-14T06:00:00Z", { highest_risk: 88.8, highest_risk_level: "CRITICAL" });
const failed = summary("FAILED", "2026-10-14T07:00:00Z", { error_summary: "RuntimeError: probe crashed" });
const running = summary("RUNNING", "2026-10-14T08:00:00Z");
const important = finding(latest.id, "IOT-MQTT-01", "HIGH", "MQTT broker accepted an anonymous connection", 1883);
const latestDetail: AssessmentDetail = { ...latest, evidence: [], findings: [important], risk_snapshots: [] };

// ---- loader -------------------------------------------------------------------
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
  const actions = await load<ShortcutsLib>("/src/lib/assistantActions.ts");
  const { AssistantView } = await load<PageModule>("/src/components/assistant/AssistantPage.tsx");

  const contextNone = ctx.buildAssistantContext([]);
  const contextComplete = ctx.buildAssistantContext([latest, older], { status: "ready", detail: latestDetail });
  const contextPartial = ctx.buildAssistantContext([partial, latest, older]);
  const contextFailed = ctx.buildAssistantContext([failed, latest, older]);
  const contextRunning = ctx.buildAssistantContext([running, latest]);

  /** Controller with recorded side effects; `manual` waits resolve only on release(). */
  function harness(context: Context | null, options: { manual?: boolean; navigate?: (r: NavRequest) => void } = {}) {
    const log: string[] = [];
    const messages: AssistantMessage[] = [];
    const navigations: NavRequest[] = [];
    const statuses: (string | null)[] = [];
    const waits: number[] = [];
    const pending: (() => void)[] = [];
    let id = 0;
    let current = context;
    const conversation = conv.createAssistantConversation({
      getContext: () => current,
      navigate: (request) => {
        log.push("navigate");
        options.navigate?.(request);
        navigations.push(request);
      },
      addMessage: (message) => {
        log.push(`message:${message.role}`);
        messages.push(message);
      },
      setStatus: (label) => {
        log.push(`status:${label ?? "idle"}`);
        statuses.push(label);
      },
      wait: (ms) => {
        log.push(`wait:${ms}`);
        waits.push(ms);
        return options.manual ? new Promise<void>((resolve) => pending.push(resolve)) : Promise.resolve();
      },
      now: () => 1_700_000_000_000,
      nextId: () => `m${++id}`,
    });
    const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
    return {
      ...conversation,
      log,
      messages,
      navigations,
      statuses,
      waits,
      setContext: (next: Context | null) => {
        current = next;
      },
      async release() {
        while (pending.length) pending.shift()!();
        await flush();
      },
      flush,
    };
  }
  const reply = (h: ReturnType<typeof harness>) => h.messages.filter((m) => m.role === "assistant").at(-1);
  const ask = async (context: Context | null, text: string) => {
    const h = harness(context);
    const outcome = await h.handleAssistantRequest(text);
    return { h, outcome, reply: reply(h) };
  };

  // A. Empty input is rejected with no side effects.
  {
    for (const text of ["", "   ", "\n\t  \n"]) {
      const h = harness(contextComplete);
      const outcome = await h.handleAssistantRequest(text);
      check(same(outcome, { status: "rejected", reason: "empty" }), `empty rejected (${JSON.stringify(text)})`);
      check(h.messages.length === 0 && h.navigations.length === 0 && h.statuses.length === 0 && h.waits.length === 0, "no side effects");
    }
    pass("A empty input is rejected; no message, status or navigation");
  }

  // B. CHECK.
  {
    const { h, outcome, reply: r } = await ask(contextNone, "  Check my IoT network  ");
    check(outcome.status === "answered", "answered");
    check(h.messages[0].role === "user" && h.messages[0].text === "Check my IoT network", "user text trimmed");
    check(r?.text === "I'll set up a security check of your authorized IoT target. It starts only when you choose Run Assessment.", `CHECK reply: ${r?.text}`);
    check(r?.intent === "CHECK" && r.action?.type === "OPEN_ASSESSMENT", "intent/action recorded");
    const nav = h.navigations[0];
    check(h.navigations.length === 1 && nav.section === "history" && nav.anchor?.id === "new-security-check" && nav.anchor.focusId === "assessment-target", "opens the existing assessment form");
    check(same(h.statuses, [conv.PROCESSING_LABEL, "Opening a new security check…", null]), `statuses ${JSON.stringify(h.statuses)}`);
    check(same(h.waits, [conv.PROCESSING_MS, conv.OPEN_DELAY_MS]), "processing then open delay");
    check(requested.length === 0, "no assessment request was made");
    const typed = await ask(contextComplete, "please scan my network");
    check(typed.reply?.action?.type === "OPEN_ASSESSMENT", "typed CHECK phrasing routes the same way");
    pass("B CHECK opens the existing assessment form without starting a check");
  }

  // C. EXPLAIN (risk and issues).
  {
    const risk = await ask(contextComplete, "Explain my risk");
    check(risk.reply?.text === "I'll show you why your current risk level is what it is.", "risk reply");
    const riskNav = risk.h.navigations[0];
    check(riskNav.section === "security" && riskNav.securityTechnical === true && riskNav.anchor?.id === "assessment-risk", "opens risk details");
    check(risk.h.statuses[1] === "Opening risk details…", "risk opening label");
    const issues = await ask(contextComplete, "What's wrong?");
    check(issues.reply?.text === "I'll show you the important security issues from your latest check.", "issues reply");
    check(issues.h.navigations[0].section === "security" && issues.h.navigations[0].anchor?.id === "security-issues", "opens issues");
    check(issues.h.statuses[1] === "Opening security details…", "issues opening label");
    pass("C EXPLAIN risk/issues reply with fixed text and open the existing views");
  }

  // D. FIX.
  {
    for (const text of ["Help me fix an issue", "How do I fix this?"]) {
      const { h, reply: r } = await ask(contextComplete, text);
      check(r?.text === "I'll show you the most important issue to fix first.", `${text}: ${r?.text}`);
      check(r?.action?.type === "OPEN_FINDING" && r.action.findingCheckId === "IOT-MQTT-01", "most important issue from the resolver");
      check(h.navigations[0].section === "security" && h.navigations[0].anchor?.id === "security-issues", "opens issues");
      check(!r.text.includes("MQTT") && !r.text.includes("1883"), "reply states no finding details");
    }
    const loading = ctx.buildAssistantContext([latest, older]);
    const settling = harness(loading, { manual: true });
    const run = settling.handleAssistantRequest("Help me fix an issue");
    await settling.release();
    await settling.release();
    check(settling.messages.length === 1 && settling.statuses.at(-1) === conv.PROCESSING_LABEL, "still processing while issues load");
    settling.setContext(contextComplete);
    await settling.release();
    await settling.release();
    const settled = await run;
    check(settled.status === "answered" && settled.resolution.action.type === "OPEN_FINDING", "waits for issues, then opens the fix");
    check(same(settling.waits, [conv.PROCESSING_MS, conv.LOADING_POLL_MS, conv.LOADING_POLL_MS, conv.OPEN_DELAY_MS]), `polls while loading ${settling.waits}`);
    check(settling.navigations[0]?.anchor?.id === "security-issues", "navigates once ready");
    check(settling.messages.filter((m) => m.role === "assistant").length === 1, "one reply, no 'try again' first");
    const stuck = await ask(loading, "Help me fix an issue");
    check(stuck.reply?.text === "I'm still loading the issues from your latest check. Please try again in a moment.", "gives up after the poll limit");
    check(stuck.h.waits.length === 1 + conv.LOADING_MAX_POLLS && stuck.h.navigations.length === 0, "bounded wait, no navigation");
    pass("D FIX points to the resolver's most important issue; waits briefly while issues load");
  }

  // E. VERIFY.
  {
    const { h, reply: r } = await ask(contextPartial, "Check if I fixed it");
    check(r?.text === "I'll compare a new security check with your previous completed check. The new check runs only after you confirm it.", `VERIFY reply: ${r?.text}`);
    const nav = h.navigations[0];
    check(nav.section === "history" && nav.assessmentId === latest.id && nav.anchor?.id === "assessment-reassessment", "baseline is the latest COMPLETE check");
    check(h.statuses[1] === "Opening the re-assessment step…", "verify opening label");
    check(requested.length === 0, "no re-assessment started");
    pass("E VERIFY opens re-assessment for the latest completed check; nothing starts");
  }

  // F. SUMMARY.
  {
    const { h, reply: r } = await ask(contextComplete, "Summarize my last check");
    check(r?.text === "I'll summarize your latest security check.", "summary reply");
    check(h.navigations.length === 1 && h.navigations[0].section === "security", "opens security summary");
    check(h.statuses[1] === "Opening your security summary…", "summary opening label");
    pass("F SUMMARY opens the security summary");
  }

  // G. UNKNOWN.
  {
    for (const text of ["blah blah", "what's the weather", "don't check my iot network", "check my iot network and summarize my last check"]) {
      const { h, outcome, reply: r } = await ask(contextComplete, text);
      check(r?.text === conv.UNKNOWN_REPLY, `${text}: clarification`);
      check(r?.action?.type === "ASK_CLARIFICATION" && h.navigations.length === 0, "no navigation");
      check(outcome.status === "answered" && outcome.resolution.state === "NEEDS_CLARIFICATION", "resolver asked for clarification");
      check(same(h.waits, [conv.PROCESSING_MS]) && h.statuses.at(-1) === null, "brief processing, then idle");
    }
    check(conv.UNKNOWN_REPLY === "I can help with checking your network, explaining your risk, fixing issues, verifying changes, or summarizing your latest check. What would you like to do?", "spec text");
    pass("G UNKNOWN, negated and ambiguous requests get the clarification reply");
  }

  // H. Shortcuts and typed requests share handleAssistantRequest.
  {
    for (const context of [contextNone, contextComplete, contextPartial, contextFailed, contextRunning, null]) {
      for (const shortcut of actions.ASSISTANT_SHORTCUTS) {
        check(intents.classifyAssistantIntent(shortcut.label).intent === shortcut.intent, `${shortcut.id} label classifies as ${shortcut.intent}`);
        const { outcome } = await ask(context, shortcut.label);
        check(outcome.status === "answered", `${shortcut.id} answered`);
        const viaShortcut = actions.resolveShortcut(shortcut.id, context);
        check(outcome.resolution.intent === viaShortcut.intent && outcome.resolution.action.type === viaShortcut.action.type, `${shortcut.id} same action`);
        check(same(outcome.resolution.destination, viaShortcut.destination), `${shortcut.id} same destination`);
      }
    }
    const page = source("src/components/assistant/AssistantPage.tsx");
    check((page.match(/onRequest=\{handleAssistantRequest\}/g) ?? []).length === 1, "page passes one handler to the view");
    check((page.match(/void onRequest\(/g) ?? []).length === 1, "the view calls onRequest in one place");
    check(page.includes('request(draft, "composer")') && page.includes('request(shortcut.label, "shortcut")') && page.includes('request(label, "shortcut")'), "composer, shortcuts and suggestions use request()");
    check(!/classifyAssistantIntent|resolveAssistantIntent|actionDestination/.test(page), "page does not route on its own");
    const lib = source("src/lib/assistant/conversation.ts");
    check(lib.includes("classifyAssistantIntent(trimmed)") && lib.includes("resolveAssistantIntent(intent, context)"), "UX-3A classifier and resolver are authoritative");
    check(!/section:\s*["']|anchor:\s*\{/.test(lib), "no second routing table");
    pass("H shortcuts and typed text produce identical resolutions through one handler", "36 shortcut/context pairs");
  }

  // I. No assessment + EXPLAIN.
  {
    const { h, reply: r } = await ask(contextNone, "Explain my risk");
    check(r?.text === "I need a completed security check before I can explain your current risk.", "spec reply");
    check(same(r.suggestions, ["check"]) && h.navigations.length === 0, "offers CHECK, does not navigate");
    const label = actions.shortcutById(r.suggestions![0]).label;
    check(label === "Check my IoT network", "suggestion label");
    await h.handleAssistantRequest(label);
    check(h.navigations[0]?.section === "history" && h.navigations[0].anchor?.id === "new-security-check", "suggestion opens the assessment workflow");
    for (const [text, expected] of [
      ["What's wrong?", "I need a completed security check before I can show what's wrong."],
      ["Help me fix an issue", "I need a completed security check before I can help you fix an issue."],
      ["Check if I fixed it", "I need a completed security check before I can verify a fix."],
      ["Summarize my last check", "I haven't checked your IoT network yet, so there's nothing to summarize."],
    ] as const) {
      const other = await ask(contextNone, text);
      check(other.reply?.text === expected && other.h.navigations.length === 0, `${text}: ${other.reply?.text}`);
    }
    pass("I without a check, EXPLAIN/FIX/VERIFY/SUMMARY explain why and offer a check");
  }

  // J. Incomplete latest check.
  {
    const explain = await ask(contextPartial, "Explain my risk");
    check(explain.reply?.text === "Your latest security check isn't complete, so I can't explain a current security result yet.", `explain: ${explain.reply?.text}`);
    check(explain.h.navigations.length === 0 && same(explain.reply.suggestions, ["check", "summary"]), "no navigation; offers check/summary");
    const sum = await ask(contextPartial, "Summarize my last check");
    check(sum.reply?.text.startsWith("The latest security check did not complete, so I can't summarize a current security result."), `summary: ${sum.reply?.text}`);
    check(sum.h.navigations[0]?.section === "security", "summary shows what the partial check recorded");
    for (const message of [...explain.h.messages, ...sum.h.messages]) {
      check(!/HIGH|MEDIUM|CRITICAL|70\.5|41\.2|88\.8/.test(message.text), "older or partial results not presented as current");
    }
    pass("J incomplete latest check is never replaced by an older result");
  }

  // K. Failed latest check.
  {
    const { h, reply: r } = await ask(contextFailed, "What's wrong?");
    check(r?.text === "Your latest security check failed, so there isn't a current security result to explain.", `failed: ${r?.text}`);
    check(h.navigations.length === 0, "no navigation");
    const fix = await ask(contextFailed, "Help me fix an issue");
    check(fix.reply?.text === "Your latest security check failed, so there isn't a current issue to fix.", "failed FIX");
    const runningReply = await ask(contextRunning, "Explain my risk");
    check(runningReply.reply?.text === "Your latest security check is still running, so there isn't a current result yet." && same(runningReply.reply.suggestions, ["summary"]), "running");
    for (const message of [...h.messages, ...fix.h.messages]) check(!/RuntimeError|probe crashed|HIGH/.test(message.text), "no error text or older risk");
    pass("K failed (and running) latest check: honest reply, no fallback");
  }

  // L. Duplicate submissions are ignored while busy.
  {
    const h = harness(contextComplete, { manual: true });
    const first = h.handleAssistantRequest("Explain my risk");
    check(h.isBusy(), "busy immediately");
    const second = await h.handleAssistantRequest("Explain my risk");
    const third = await h.handleAssistantRequest("Summarize my last check");
    check(same(second, { status: "rejected", reason: "busy" }) && same(third, second), "duplicates rejected");
    await h.release();
    await h.release();
    const outcome = await first;
    check(outcome.status === "answered" && !h.isBusy(), "first finished");
    const count = () => h.messages.length;
    check(count() === 2 && h.navigations.length === 1, "one exchange, one navigation");
    const next = h.handleAssistantRequest("Summarize my last check");
    await h.release();
    await h.release();
    check((await next).status === "answered" && count() === 4, "accepted again once idle");
    pass("L duplicate and concurrent submissions are ignored until the request finishes");
  }

  // M. Message ordering.
  {
    const h = harness(contextComplete, { manual: true });
    const pending = h.handleAssistantRequest("Explain my risk");
    const count = () => h.messages.length;
    check(count() === 1 && h.messages[0].role === "user", "user message rendered before the reply");
    check(h.statuses[0] === conv.PROCESSING_LABEL, "processing state shown");
    await h.release();
    check(count() === 2 && h.navigations.length === 0, "reply before navigation");
    await h.release();
    await pending;
    check(same(h.log, [
      `status:${conv.PROCESSING_LABEL}`, "message:user", `wait:${conv.PROCESSING_MS}`, "message:assistant",
      "status:Opening risk details…", `wait:${conv.OPEN_DELAY_MS}`, "navigate", "status:idle",
    ]), `order ${h.log.join(" > ")}`);
    const plain = harness(contextComplete);
    await plain.handleAssistantRequest("blah");
    await plain.handleAssistantRequest("Summarize my last check");
    check(plain.messages.map((m) => `${m.id}:${m.role}`).join(",") === "m1:user,m2:assistant,m3:user,m4:assistant", "alternating, unique ids");
    const closing = harness(contextComplete, { manual: true });
    const cut = closing.handleAssistantRequest("Explain my risk");
    closing.close();
    await closing.release();
    check((await cut).status === "rejected" && closing.messages.length === 1 && closing.navigations.length === 0, "closed controller adds and opens nothing");
    pass("M user message, processing, reply, opening, navigation — in that order");
  }

  // N. Errors are generic and sanitized.
  {
    const apiError = Object.assign(
      new Error("Backend request failed (500) for /api/v1/assessments/x token=abc123 at C:\\srv\\backend\\app.py\n    at handler (http://127.0.0.1:8000/app.js:1:1)"),
      { status: 500 },
    );
    const h = harness(contextComplete, { navigate: () => { throw apiError; } });
    const outcome = await h.handleAssistantRequest("Explain my risk");
    const r = reply(h)!;
    check(outcome.status === "failed" && r.tone === "error" && r.text === conv.ERROR_REPLY, `generic error reply only: ${r.text}`);
    check(!/abc123|C:\\|\/api\/v1|127\.0\.0\.1|app\.js|handler|redacted/.test(r.text), `sanitized: ${r.text}`);
    check(h.statuses.at(-1) === null && !h.isBusy(), "idle after error");
    for (const error of [new TypeError("x is undefined\n at stack"), "raw string", { message: "no status" }, null]) {
      check(conv.errorReply(error) === conv.ERROR_REPLY, "unknown errors give only the generic text");
    }
    check(conv.errorReply({ status: 0, message: "Unable to connect to security backend." }) === `${conv.ERROR_REPLY} Unable to connect to security backend.`, "short API message kept");
    check(conv.errorReply({ status: 500, message: "x".repeat(400) }) === conv.ERROR_REPLY, "long message dropped");
    check(conv.errorReply({ status: 403, message: "Target is not authorized." }) === `${conv.ERROR_REPLY} Target is not authorized.`, "short safe detail appended");
    check(conv.errorReply({ status: 500, message: "Backend request failed (500) for /api/v1/assessments/abc" }) === conv.ERROR_REPLY, "message with a path dropped");
    check(conv.ERROR_REPLY === "I couldn't complete that action. You can try again.", "spec text");
    const contextError = harness(null);
    contextError.setContext(null);
    check((await contextError.handleAssistantRequest("Explain my risk")).status === "answered" && reply(contextError)?.text.includes("still loading"), "loading context answered, not crashed");
    pass("N failures show the generic reply plus at most a short API message with nothing to redact");
  }

  // O/P. Enter submits; Shift+Enter does not.
  {
    check(conv.composerKeyAction({ key: "Enter", shiftKey: false }) === "submit", "Enter submits");
    check(conv.composerKeyAction({ key: "Enter", shiftKey: false, isComposing: false }) === "submit", "Enter submits (not composing)");
    pass("O Enter submits");
    check(conv.composerKeyAction({ key: "Enter", shiftKey: true }) === "newline", "Shift+Enter newline");
    check(conv.composerKeyAction({ key: "Enter", shiftKey: false, isComposing: true }) === "newline", "IME Enter does not submit");
    check(conv.composerKeyAction({ key: "a", shiftKey: false }) === "none", "other keys");
    const page = source("src/components/assistant/AssistantPage.tsx");
    check(/if \(action === "submit"\) \{\s*event\.preventDefault\(\);\s*request\(draft, "composer"\);/.test(page), "only submit prevents default (newline stays native)");
    pass("P Shift+Enter (and IME composition) inserts a newline instead of submitting");
  }

  // Intro text, message safety and rendering.
  {
    check(conv.introText(contextNone) === "I haven't checked your IoT network yet.", "none");
    check(conv.introText(contextComplete) === "I have your latest security check available.", "available");
    check(conv.introText(contextPartial) === "Your latest security check isn't complete yet.", "incomplete");
    check(conv.introText(contextFailed) === "Your latest security check did not complete successfully.", "failed");

    const h = harness(contextComplete);
    await h.handleAssistantRequest("my password=hunter2 token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln see https://internal.example/x");
    const userText = h.messages[0].text;
    check(!/hunter2|eyJ|internal\.example/.test(userText) && userText.includes("[redacted]"), `user text redacted: ${userText}`);
    const allowedKeys = new Set(["id", "role", "text", "timestamp", "intent", "action", "suggestions", "tone"]);
    for (const message of h.messages) {
      for (const key of Object.keys(message)) check(allowedKeys.has(key), `unexpected message field ${key}`);
    }
    await h.handleAssistantRequest("Help me fix an issue");
    const serialized = JSON.stringify(h.messages);
    check(!/evidence|observation|metadata|risk_snapshots|1883|Fixture remediation|anonymous connection/i.test(serialized), "no evidence or finding records in chat state");
    pass("intro sentences match availability; chat state holds only UI text and resolver actions");

    const messages: AssistantMessage[] = [
      { id: "u1", role: "user", text: "Explain my risk", timestamp: 1 },
      { id: "a1", role: "assistant", text: "I need a completed security check before I can explain your current risk.", timestamp: 2, suggestions: ["check"] },
      { id: "a2", role: "assistant", text: conv.ERROR_REPLY, timestamp: 3, tone: "error" },
    ];
    const render = (status: string | null) =>
      renderToStaticMarkup(createElement(AssistantView, {
        context: contextNone, assessmentsError: null, onRetryAssessments: () => {}, messages, status,
        onRequest: (): Promise<RequestOutcome> => Promise.resolve({ status: "rejected", reason: "empty" }),
      }));
    const html = render(null);
    check(/<ol[^>]*role="log"[^>]*aria-live="polite"/.test(html), "conversation is a live log");
    check(/justify-end[^>]*><div[^>]*><span class="sr-only">You: <\/span>Explain my risk/.test(html), "user bubble right with label");
    check(/justify-start[^>]*><div[^>]*><span class="sr-only">Assistant: <\/span><p>I need a completed/.test(html), "assistant bubble left with label");
    const order = ["I haven&#x27;t checked your IoT network yet.", ">Explain my risk</", "I need a completed", "I couldn&#x27;t complete that action"].map((t) => html.indexOf(t));
    check(order.every((i, n) => i >= 0 && (n === 0 || i > order[n - 1])), `render order ${order}`);
    check((html.match(/>Check my IoT network<\/button>/g) ?? []).length === 1, "suggestion pill rendered");
    check(html.includes('placeholder="Ask about your security..."') && html.includes('aria-label="Send message"'), "composer placeholder and Send label");
    check(!/[{[]"|&quot;id&quot;/.test(html), "no raw JSON");
    const busy = render("Opening risk details…");
    check(/<p role="status"[^>]*>Opening risk details…<\/p>/.test(busy), "processing status");
    check(!/animate-|Thinking|typing/i.test(busy), "no typing or thinking animation");
    pass("view renders ordered, labelled bubbles, suggestions and a calm status");
  }

  check(requested.length === 0, `requests: ${requested.join(", ")}`);
  pass("no network request, assessment, database or Ollama call during the run");
} finally {
  globalThis.fetch = realFetch;
  await server.close();
}

for (const line of results) console.log(line);
console.log(`${results.filter((line) => line.startsWith("PASS")).length} checks passed`);
