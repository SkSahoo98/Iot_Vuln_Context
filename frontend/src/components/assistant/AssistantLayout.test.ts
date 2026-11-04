/**
 * Checks for the Assistant workspace layout: chat and the status/actions
 * sidebar side by side on desktop, stacked (chat, status, actions) on small
 * screens, the status card for every latest-check state, and the six existing
 * shortcuts as compact rows. Rendering only; any request fails the run.
 *
 * Run from frontend/:  node src/components/assistant/AssistantLayout.test.ts
 */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { AssessmentDetail, AssessmentFinding, AssessmentStatus, AssessmentSummary } from "../../api/types.ts";
import type { RequestOutcome } from "../../lib/assistant/conversation.ts";

type ViteServer = {
  ssrLoadModule(url: string): Promise<Record<string, unknown>>;
  close(): Promise<void>;
};
type ContextLib = typeof import("../../lib/assistant/context.ts");
type PageModule = typeof import("./AssistantPage.tsx");
type ShellModule = typeof import("../layout/AppShell.tsx");
type Context = ReturnType<ContextLib["buildAssistantContext"]>;

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${message}`);
}
const results: string[] = [];
const pass = (name: string, note = "") => results.push(`PASS ${name}${note ? ` — ${note}` : ""}`);

const requested: string[] = [];
const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL) => {
  requested.push(String(input));
  throw new Error(`unexpected request ${String(input)}`);
}) as typeof fetch;

// ---- fixtures -------------------------------------------------------------------
const TARGET = "192.0.2.44";
let seq = 0;
const uuid = (prefix: string) => `${prefix}0000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`;
const NOW = Date.parse("2026-10-13T22:58:40Z");

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
    evidence_count: 7,
    finding_count: 3,
    highest_risk: null,
    highest_risk_level: null,
    ...extra,
  };
}
function finding(assessmentId: string, findingId: string, severity: AssessmentFinding["severity"], port: number): AssessmentFinding {
  return {
    id: uuid("f"), assessment_id: assessmentId, finding_id: findingId, finding_type: `TYPE_${findingId}`,
    category: "IOT_PROTOCOL", title: `Backend title ${findingId}`, severity, confidence: 0.9, description: null,
    target: TARGET, port, evidence_reference: null, remediation: "Fixture remediation.", status: "OPEN",
    created_at: "2026-10-13T19:58:30Z",
  };
}

const latest = summary("COMPLETE", "2026-10-13T19:58:00Z", { highest_risk: 70.5, highest_risk_level: "HIGH" });
const detail: AssessmentDetail = {
  ...latest,
  evidence: [],
  findings: [
    finding(latest.id, "IOT-MQTT-01", "HIGH", 1883),
    finding(latest.id, "IOT-MQTT-02", "MEDIUM", 1883),
    finding(latest.id, "NET-06", "LOW", 139),
    finding(latest.id, "NET-06", "LOW", 445),
  ],
  risk_snapshots: [],
};
const partial = summary("INCOMPLETE", "2026-10-14T06:00:00Z", { highest_risk: 88.8, highest_risk_level: "CRITICAL" });
const failed = summary("FAILED", "2026-10-14T07:00:00Z");
const running = summary("RUNNING", "2026-10-14T08:00:00Z");

// ---- loader -----------------------------------------------------------------------
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
declare const process: { cwd(): string };

try {
  const load = async <T>(url: string) => (await server.ssrLoadModule(url)) as unknown as T;
  const ctx = await load<ContextLib>("/src/lib/assistant/context.ts");
  const { AssistantView } = await load<PageModule>("/src/components/assistant/AssistantPage.tsx");
  const { AppShell } = await load<ShellModule>("/src/components/layout/AppShell.tsx");

  const noop = () => {};
  const view = (context: Context | null, extra: { status?: string | null; assessmentsError?: string | null } = {}) =>
    renderToStaticMarkup(
      createElement(AssistantView, {
        context,
        assessmentsError: extra.assessmentsError ?? null,
        onRetryAssessments: noop,
        messages: [],
        status: extra.status ?? null,
        onRequest: (): Promise<RequestOutcome> => Promise.resolve({ status: "rejected", reason: "empty" }),
        now: NOW,
      }),
    );
  const between = (html: string, start: string, end: string) => {
    const from = html.indexOf(start);
    check(from !== -1, `missing ${start}`);
    const to = html.indexOf(end, from);
    return html.slice(from, to === -1 ? undefined : to);
  };
  const statusCard = (html: string) => between(html, "data-security-status=", 'aria-labelledby="assistant-actions"');
  const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");

  const complete = ctx.buildAssistantContext([latest], { status: "ready", detail });
  const none = ctx.buildAssistantContext([]);

  // 1. Two columns on desktop, chat first; stacked order on small screens.
  {
    const html = view(complete);
    const workspace = html.match(/<div data-assistant-workspace=""[^>]*class="([^"]*)"/)?.[1] ?? "";
    check(/^grid\b/.test(workspace) && workspace.includes("lg:grid-cols-[minmax(0,3fr)_minmax(20rem,2fr)]"), `two columns from lg: ${workspace}`);
    check(workspace.includes("lg:h-[calc(100dvh-var(--assistant-offset))]") && workspace.includes("lg:grid-rows-[minmax(0,1fr)]"), "workspace fits the viewport on desktop");
    check(!/(?:^|\s)(?:sm|md):grid-cols/.test(workspace), "no forced columns below lg");
    const order = ['data-assistant-chat=""', 'data-security-status=', 'aria-labelledby="assistant-actions"'].map((m) => html.indexOf(m));
    check(order.every((i, n) => i !== -1 && (n === 0 || i > order[n - 1])), `chat, status, actions order ${order}`);
    check(html.indexOf('data-assistant-sidebar=""') > html.indexOf("<form"), "sidebar after the composer");
    pass("1 desktop: chat left, status/actions right; mobile stack is chat, status, actions");
  }

  // 2. Only the conversation scrolls inside the chat; composer stays attached.
  {
    const html = view(complete);
    const chat = between(html, 'data-assistant-chat=""', 'data-assistant-sidebar=""');
    const log = chat.match(/<ol[^>]*role="log"[^>]*class="([^"]*)"/)?.[1] ?? "";
    check(log.includes("flex-1") && log.includes("overflow-y-auto") && log.includes("min-h-0") && log.includes("lg:max-h-none"), `log scrolls: ${log}`);
    check(/(?:^|\s)relative(?:\s|$)/.test(log), "screen-reader labels stay inside the scrolling log");
    check((chat.match(/overflow-y-auto/g) ?? []).length === 1, "one scroll area in the chat panel");
    check(/data-assistant-chat=""[^>]*class="[^"]*flex-col/.test(html), "chat panel is a column");
    check(chat.indexOf("How can I help with your security?") < chat.indexOf('role="log"') && chat.indexOf('role="log"') < chat.indexOf("<form"), "header, conversation, composer");
    check(!/font-display|text-3xl/.test(between(chat, "<h2", "</h2>")), "chat header is not a second page title");
    pass("2 chat panel: header, one scrolling conversation, composer at the bottom");
  }

  // 3. Status card: complete latest check.
  {
    const card = statusCard(view(complete));
    check(card.includes(">Your security status<"), "heading");
    check(/>HIGH<\/span> risk/.test(card) && card.includes("uppercase"), "risk level as text, shown upper-case");
    check(/>70\.5<\/span> \/ 100/.test(card), "recorded score");
    check(text(card).includes("Last checked 3 hours ago"), `checked time: ${text(card)}`);
    check(text(card).includes("2 important issues") && text(card).includes("2 additional findings") && !text(card).includes("minor issue"), `counts: ${text(card)}`);
    check(!/\bsafe\b|secure\b/i.test(text(card)), "no safety claim");
    const loadingIssues = statusCard(view(ctx.buildAssistantContext([latest])));
    check(loadingIssues.includes("Loading the issues from your latest check…") && !/important issue/.test(loadingIssues), "counts wait for the issues");
    pass("3 status card shows recorded level, score, time and issue counts");
  }

  // 4. Status card: no check, running, incomplete, failed, loading, error.
  {
    const empty = view(none);
    check(text(statusCard(empty)).includes("No security check yet") && empty.includes("Your network has not been checked yet."), "no check yet");
    const checkButton = [...empty.matchAll(/<button[^>]*>[\s\S]*?<\/button>/g)].map((m) => m[0]).filter((b) => b.includes("Check my IoT network"));
    check(checkButton.length === 1 && checkButton[0].includes("bg-[var(--accent-soft)]"), "the existing Check action is the suggested next step");
    const states: [Context, string][] = [
      [ctx.buildAssistantContext([running, latest], { status: "ready", detail }), "Check in progress"],
      [ctx.buildAssistantContext([partial, latest], { status: "ready", detail }), "Latest check incomplete"],
      [ctx.buildAssistantContext([failed, latest], { status: "ready", detail }), "Latest check failed"],
    ];
    for (const [context, title] of states) {
      const card = statusCard(view(context));
      check(text(card).includes(title), `${title}: ${text(card)}`);
      check(!/HIGH|CRITICAL|70\.5|88\.8|important issue/.test(card), `${title}: no older or partial result shown as current`);
    }
    check(text(statusCard(view(null))).includes("Loading your security status…"), "loading");
    check(text(statusCard(view(null, { assessmentsError: "database unavailable" }))).includes("Couldn&#x27;t load your security checks."), "load error");
    pass("4 status card: no check, running, incomplete, failed, loading and error states");
  }

  // 5. The six existing shortcuts as compact rows in the sidebar.
  {
    const html = view(complete);
    const sidebar = between(html, 'data-assistant-sidebar=""', "</aside>");
    const buttons = [...sidebar.matchAll(/<button[^>]*>[\s\S]*?<\/button>/g)].map((m) => m[0]);
    const labels = ["Check my IoT network", "What&#x27;s wrong?", "Explain my risk", "Help me fix an issue", "Check if I fixed it", "Summarize my last check"];
    check(buttons.length === 6, `six actions (${buttons.length})`);
    labels.forEach((label, i) => check(buttons[i].includes(`>${label}<`), `${label} in position ${i + 1}`));
    for (const button of buttons) {
      check(/<svg[^>]*aria-hidden="true"/.test(button), "decorative icon hidden from screen readers");
      check(button.includes("min-h-12") && !button.includes("min-h-[4.25rem]"), "compact row");
      check(/data-intent="[A-Z]+" data-action="[A-Z_]+" data-available="(true|false)"/.test(button), "resolver attributes kept");
    }
    check((sidebar.match(/<ul class="space-y-1">/g) ?? []).length === 3, "three groups of two");
    check(text(sidebar).includes("Run a security check of your authorized target.") && text(sidebar).includes("Review the overall result."), "one-line descriptions");
    check(sidebar.includes("Explanations are written from your latest completed security check."), "honest note kept");
    const busy = view(complete, { status: "Checking what you asked for…" });
    check([...busy.matchAll(/<button[^>]*>/g)].every((m) => m[0].includes('disabled=""')), "every action disabled while busy");
    pass("5 sidebar: six compact actions in three groups, same resolver attributes, disabled while busy");
  }

  // 6. Wider, tighter shell only for the Assistant.
  {
    const shell = (section: "assistant" | "security") =>
      renderToStaticMarkup(createElement(AppShell, {
        section, apiOnline: true, onNavigate: noop, onOpenStatus: noop, onRefresh: noop, children: createElement("p", null, "x"),
      }));
    const assistant = shell("assistant");
    const security = shell("security");
    check(/<header[\s\S]*?max-w-7xl/.test(assistant) && /<main class="[^"]*max-w-7xl[^"]*md:pb-5/.test(assistant), "assistant header and main share the wider width");
    check(/<header[\s\S]*?max-w-6xl/.test(security) && /<main class="[^"]*max-w-6xl[^"]*md:pb-12/.test(security), "other sections unchanged");
    pass("6 Assistant uses a wider, tighter shell; other sections unchanged");
  }

  check(requested.length === 0, `rendering made requests: ${requested.join(", ")}`);
  pass("rendering made no requests");
} finally {
  globalThis.fetch = realFetch;
  await server.close();
}

for (const line of results) console.log(line);
console.log(`${results.filter((line) => line.startsWith("PASS")).length} checks passed`);
