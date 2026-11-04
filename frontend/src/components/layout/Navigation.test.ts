/**
 * Checks for the AI-first shell and navigation (Phase UX-2). Components are
 * loaded through Vite's SSR loader and rendered with react-dom/server;
 * globalThis.fetch is replaced by a recorder that never reaches the network.
 *
 * Run from frontend/:  node src/components/layout/Navigation.test.ts
 */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { AssessmentStatus, AssessmentSummary } from "../../api/types.ts";

declare const process: { cwd(): string };

type ViteServer = {
  ssrLoadModule(url: string): Promise<Record<string, unknown>>;
  close(): Promise<void>;
};
type AppModule = typeof import("../../App.tsx");
type ShellModule = typeof import("./AppShell.tsx");
type NavLib = typeof import("../../lib/navigation.ts");
type ActionsLib = typeof import("../../lib/assistantActions.ts");
type ContextLib = typeof import("../../lib/assistant/context.ts");
type FormatLib = typeof import("../../lib/format.ts");
type AssistantModule = typeof import("../assistant/AssistantPage.tsx");
type SecurityModule = typeof import("../security/SecurityPage.tsx");
type HistoryModule = typeof import("../assessments/AssessmentsPage.tsx");
type MoreModule = typeof import("../more/MorePage.tsx");
type PanelModule = typeof import("../assessments/ReassessmentPanel.tsx");
type FsModule = { readFileSync(path: string, encoding: "utf8"): string };

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${message}`);
}

const results: string[] = [];
const pass = (name: string, note = "") =>
  results.push(`PASS ${name}${note ? ` — ${note}` : ""}`);

// ---- fetch recorder -------------------------------------------------------
const requested: string[] = [];
const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL) => {
  requested.push(String(input));
  throw new Error(`unexpected request ${String(input)}`);
}) as typeof fetch;

// ---- fixtures (test-only, API response shape, never persisted) -----------
const TARGET = "192.0.2.44";
let seq = 0;
const uuid = () => `a0000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`;

function summary(
  status: AssessmentStatus,
  startedAt: string,
  extra: Partial<AssessmentSummary> = {},
): AssessmentSummary {
  return {
    id: uuid(),
    target: TARGET,
    assessment_type: "MULTI_LAYER",
    status,
    started_at: startedAt,
    completed_at: status === "RUNNING" ? null : startedAt.replace(":00Z", ":40Z"),
    error_summary: null,
    metadata: {} as AssessmentSummary["metadata"],
    created_at: startedAt,
    evidence_count: 9,
    finding_count: 7,
    highest_risk: null,
    highest_risk_level: null,
    ...extra,
  };
}

const olderComplete = summary("COMPLETE", "2026-10-12T08:00:00Z", {
  highest_risk: 41.2,
  highest_risk_level: "MEDIUM",
});
const latestComplete = summary("COMPLETE", "2026-10-13T19:58:00Z", {
  highest_risk: 70.5,
  highest_risk_level: "HIGH",
});
const newerPartial = summary("INCOMPLETE", "2026-10-14T06:00:00Z", {
  highest_risk: 88.8,
  highest_risk_level: "CRITICAL",
  error_summary: "TLS check timed out.",
  finding_count: 1,
});
const history = [newerPartial, latestComplete, olderComplete];
const NOW = Date.parse("2026-10-13T20:10:40Z");

/** Inner HTML of every `<nav aria-label="Primary">`. */
function primaryNavs(html: string): string[] {
  return [...html.matchAll(/<nav aria-label="Primary"[^>]*>([\s\S]*?)<\/nav>/g)].map((m) => m[1]);
}
const buttonLabels = (html: string) =>
  [...html.matchAll(/<button[^>]*>([\s\S]*?)<\/button>/g)].map((m) =>
    m[1].replace(/<[^>]+>/g, "").trim(),
  );
const buttonClasses = (html: string) =>
  [...html.matchAll(/<button[^>]*class="([^"]*)"/g)].map((m) => m[1]);
/** The single `<button>` element whose content includes `text`. */
function buttonWith(html: string, text: string): string {
  const matches = [...html.matchAll(/<button[^>]*>[\s\S]*?<\/button>/g)]
    .map((m) => m[0])
    .filter((button) => button.includes(text));
  check(matches.length === 1, `one button containing "${text}" (${matches.length})`);
  return matches[0];
}
const TOUCH = /(^|\s)min-h-(11|12|14|\[(3\.35|4\.25)rem\])(?=\s|$)/;

// ---- loader ---------------------------------------------------------------
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
  const { default: App } = await load<AppModule>("/src/App.tsx");
  const { AppShell } = await load<ShellModule>("/src/components/layout/AppShell.tsx");
  const nav = await load<NavLib>("/src/lib/navigation.ts");
  const actions = await load<ActionsLib>("/src/lib/assistantActions.ts");
  const contextLib = await load<ContextLib>("/src/lib/assistant/context.ts");
  /** Destination of a shortcut for the given history (and optional latest detail). */
  const route = (
    id: Parameters<ActionsLib["resolveShortcut"]>[0],
    list: AssessmentSummary[],
    detail: Parameters<ContextLib["buildAssistantContext"]>[1] = null,
  ) => actions.resolveShortcut(id, contextLib.buildAssistantContext(list, detail)).destination;
  const format = await load<FormatLib>("/src/lib/format.ts");
  const { AssistantPage } = await load<AssistantModule>("/src/components/assistant/AssistantPage.tsx");
  const { SecurityPage } = await load<SecurityModule>("/src/components/security/SecurityPage.tsx");
  const { AssessmentsPage } = await load<HistoryModule>("/src/components/assessments/AssessmentsPage.tsx");
  const { MorePage, MORE_GROUPS } = await load<MoreModule>("/src/components/more/MorePage.tsx");
  const { ReassessmentPanelView } = await load<PanelModule>("/src/components/assessments/ReassessmentPanel.tsx");

  const noop = () => {};
  const shell = (section: Parameters<typeof AppShell>[0]["section"]) =>
    renderToStaticMarkup(
      createElement(AppShell, {
        section,
        apiOnline: true,
        onNavigate: noop,
        onOpenStatus: noop,
        onRefresh: noop,
        children: null,
      }),
    );
  const assistant = (assessments: AssessmentSummary[] | null, error: string | null = null) =>
    renderToStaticMarkup(
      createElement(AssistantPage, {
        assessments,
        assessmentsError: error,
        onRetryAssessments: noop,
        onNavigate: noop,
        messages: [],
        onMessage: noop,
        now: NOW,
      }),
    );
  const historyPage = (props: Partial<Parameters<typeof AssessmentsPage>[0]> = {}) =>
    renderToStaticMarkup(
      createElement(AssessmentsPage, {
        assessments: history,
        loading: false,
        error: null,
        selectedAssessmentId: null,
        onSelectAssessment: noop,
        onRefresh: noop,
        ...props,
      }),
    );
  const securityPage = (initialTechnicalOpen = false) =>
    renderToStaticMarkup(
      createElement(SecurityPage, {
        assessments: [latestComplete, olderComplete],
        assessmentsError: null,
        onRetryAssessments: noop,
        deviceContext: null,
        initialTechnicalOpen,
        onNavigate: noop,
        onScrollTo: noop,
        onReassessmentCreated: noop,
      }),
    );

  const appHtml = renderToStaticMarkup(createElement(App));
  const navs = primaryNavs(appHtml);
  const PRIMARY = ["Assistant", "Security", "History", "More"];

  // 1-4. The four primary items, in order, in both header and dock.
  {
    check(navs.length === 2, `header + dock navigation (${navs.length})`);
    for (const html of navs) {
      check(buttonLabels(html).join("|") === PRIMARY.join("|"), `primary items (${buttonLabels(html).join("|")})`);
    }
    check(nav.PRIMARY_SECTIONS.join("|") === "assistant|security|history|more", "section order");
    check(nav.DEFAULT_SECTION === "assistant", "Assistant is the default screen");
    check(appHtml.includes("How can I help with your security?"), "App opens on Assistant");
    pass("1 Assistant is a primary item and the default screen");
    pass("2 Security is a primary item");
    pass("3 History is a primary item");
    pass("4 More is a primary item");
  }

  // 5. Old sections are no longer primary.
  {
    for (const html of navs) {
      for (const old of ["Overview", "Devices", "Findings", "Risk", "AI", "Assessments"]) {
        check(!buttonLabels(html).some((label) => label.includes(old)), `"${old}" not in primary nav`);
      }
    }
    for (const secondary of ["devices", "findings", "risk", "ai"] as const) {
      check(nav.isSecondarySection(secondary), `${secondary} is secondary`);
      check(nav.primarySectionOf(secondary) === "more", `${secondary} highlights More`);
      const html = shell(secondary);
      for (const block of primaryNavs(html)) {
        check(/aria-current="page"[^>]*>[\s\S]*?More<\/span>|aria-current="page"[^>]*>[\s\S]*?More<\/button>/.test(block), `More active on ${secondary}`);
      }
      check(html.includes("<span aria-hidden=\"true\">‹</span> More"), `${secondary} has a back link to More`);
    }
    check(nav.sectionFromHash("#overview") === "security", "old #overview link lands on Security");
    check(nav.sectionFromHash("#assessments") === "history", "old #assessments link lands on History");
    pass("5 Overview/Devices/Findings/Risk/AI no longer primary; old links redirect");
  }

  // 6. Assistant -> CHECK entry point.
  {
    const empty = assistant([]);
    check(empty.includes("I haven&#x27;t checked your IoT network yet."), "empty context line");
    check(!/^<button[^>]*disabled=""/.test(buttonWith(empty, "Check my IoT network")), "CHECK enabled without history");
    const request = route("check", []);
    check(request?.section === "history", "CHECK opens History");
    check(request?.anchor?.id === "new-security-check" && request.anchor.focusId === "assessment-target", "CHECK scrolls to and focuses the form");
    const page = historyPage();
    check(page.includes('id="new-security-check"') && page.includes('id="assessment-target"'), "History has the check form anchor and target field");
    check(page.includes(`value="${newerPartial.target}"`), "target prefilled from the latest check");
    pass("6 Assistant CHECK opens the existing assessment form");
  }

  // Assistant context line uses real assessment data.
  {
    const completeOnly = assistant([latestComplete, olderComplete]);
    check(completeOnly.includes("I have your latest security check available."), "complete statement");
    check(completeOnly.includes(">HIGH</span> risk"), "risk level from the record");
    check(completeOnly.includes("checked 12 minutes ago"), "relative time");
    check(completeOnly.includes(">Summarize my last check<"), "SUMMARY entry");
    const partial = assistant(history);
    check(partial.includes("Your latest security check isn&#x27;t complete yet.") && !partial.includes("CRITICAL"), "partial run's risk not shown");
    check(assistant(null).includes("Loading your latest security check…"), "loading");
    const failed = assistant(null, "database unavailable");
    check(failed.includes("database unavailable") && failed.includes(">Retry<"), "error + retry");
    check(!/\bsafe\b|network is secure/i.test(completeOnly + partial), "no safety claim");
    pass("Assistant context line comes from the latest assessment record");
  }

  // 7. Security -> security home (+ technical details).
  {
    const completeList = [latestComplete, olderComplete];
    const withIssue = {
      status: "ready" as const,
      detail: {
        id: latestComplete.id,
        risk_snapshots: [],
        findings: [{
          id: uuid(), assessment_id: latestComplete.id, finding_id: "IOT-MQTT-01", finding_type: "MQTT_ANONYMOUS_ACCESS",
          category: "IOT_PROTOCOL", title: "Backend title", severity: "HIGH" as const, confidence: 0.9, description: null,
          target: TARGET, port: 1883, evidence_reference: null, remediation: "Fixture remediation.", status: "OPEN",
          created_at: "2026-10-13T19:58:30Z",
        }],
      },
    };
    check(route("summary", history)?.section === "security", "SUMMARY opens Security");
    const whatsWrong = route("whats-wrong", completeList);
    check(whatsWrong?.section === "security" && whatsWrong.anchor?.id === "security-issues", "EXPLAIN opens issues");
    check(route("whats-wrong", history) === null, "EXPLAIN needs the latest check to be COMPLETE");
    const fix = route("fix-issue", completeList, withIssue);
    check(fix?.section === "security" && fix.anchor?.id === "security-issues", "FIX opens issues with fixes");
    check(route("fix-issue", completeList) === null, "FIX waits for the latest issues");
    const risk = route("explain-risk", completeList);
    check(risk?.section === "security" && risk.securityTechnical === true && risk.anchor?.id === "assessment-risk", "Explain risk opens technical risk");
    const closed = securityPage();
    check(closed.includes(">70.5</span>") && closed.includes(">HIGH</span> risk."), "security home status");
    check(closed.includes('id="security-issues"'), "issues section anchor");
    check(closed.includes('id="security-technical"') && closed.includes(">Show technical details<"), "technical section");
    check(!closed.includes("Loading assessment details..."), "details not loaded until opened");
    const open = securityPage(true);
    check(open.includes("Loading assessment details...") && open.includes(">Hide technical details<"), "technical details open on request");
    pass("7 Security shows the security home with technical details on demand");
  }

  // 8. History -> assessment history as "Security check" cards.
  {
    const page = historyPage();
    check(page.includes(">Security checks<"), "history heading");
    check((page.match(/>Security check</g) ?? []).length === 3, "one card per check");
    check(page.includes(format.formatGeneratedAt(latestComplete.started_at) ?? "!"), "human-readable time");
    check(/HIGH<\/span> · <span[^>]*>70\.5\/100/.test(page), "risk line for COMPLETE");
    check(page.includes(">Partial check<") && page.includes("No risk rating for this check"), "partial check has no risk");
    check(!page.includes("88.8"), "incomplete risk hidden");
    check(page.includes("7 findings") && page.includes("1 finding<"), "finding counts");
    check(page.includes(">View details<"), "View details");
    check(page.includes(TARGET), "target");
    pass("8 History lists security checks as readable cards");
  }

  // 9. More exposes the secondary pages and real tools only.
  {
    const html = renderToStaticMarkup(createElement(MorePage, { onNavigate: noop, onOpenStatus: noop }));
    for (const label of ["Devices", "Technical findings", "Risk &amp; research", "AI analysis (legacy)", "System status"]) {
      check(html.includes(`>${label}<`), `More lists ${label}`);
    }
    check(!/Settings|Account|Profile/i.test(html), "no invented pages");
    const sections = MORE_GROUPS.flatMap((group) => group.entries)
      .map((entry) => (entry.action.kind === "section" ? entry.action.section : "status"))
      .sort()
      .join("|");
    check(sections === "ai|devices|findings|risk|status", `More targets (${sections})`);
    pass("9 More exposes Devices, legacy findings/risk/AI and System status");
  }

  // 10. No new backend endpoint; nothing fetched by the shell itself.
  {
    check(requested.length === 0, `rendering issued requests: ${requested.join(", ")}`);
    const uxFiles = [
      "src/App.tsx",
      "src/lib/navigation.ts",
      "src/lib/assistantActions.ts",
      "src/hooks/useAnchorScroll.ts",
      "src/components/assistant/AssistantPage.tsx",
      "src/components/security/SecurityPage.tsx",
      "src/components/more/MorePage.tsx",
      "src/components/layout/PrimaryNav.tsx",
      "src/components/layout/BottomDock.tsx",
      "src/components/layout/Header.tsx",
      "src/components/layout/AppShell.tsx",
    ];
    for (const file of uxFiles) {
      const text = source(file);
      check(!/["'`]\/api\/v1|\bfetch\(/.test(text), `${file} calls the API directly`);
    }
    const assistantPage = "src/components/assistant/AssistantPage.tsx";
    for (const file of uxFiles.slice(1).filter((name) => name !== assistantPage)) {
      check(!/from "\.\.\/(\.\.\/)?api\/(assessments|security|client)"/.test(source(file)), `${file} imports an API module`);
    }
    const assistantApi = [...source(assistantPage).matchAll(/import \{([^}]*)\} from "\.\.\/\.\.\/api\/(\w+)"/g)]
      .map((m) => `${m[2]}:${m[1].trim()}`)
      .sort();
    check(
      assistantApi.join(",") === "assessments:createAssessment, fetchAssessment,assistant:explainWithAssistant",
      `Assistant reads GET /assessments/{id}, creates checks through the existing POST and calls only the explanation endpoint (${assistantApi.join(", ")})`,
    );
    check(
      (source(assistantPage).match(/\bcreateAssessment\b/g) ?? []).length === 2 &&
        source(assistantPage).includes("runAssessment: createAssessment,"),
      "createAssessment is only handed to the workflow's explicit run step",
    );
    const assistantEndpoints = [...source("src/api/assistant.ts").matchAll(/["'`](\/api\/[^"'`]*)["'`]/g)].map((m) => m[1]);
    check(
      assistantEndpoints.join(",") === "/api/v1/assistant/explain",
      `assistant API uses only POST /api/v1/assistant/explain (${assistantEndpoints.join(", ")})`,
    );
    const api = source("src/api/assessments.ts");
    const endpoints = [...api.matchAll(/["'`](\/api\/[^"'`]*)["'`]/g)].map((m) => m[1]);
    check(endpoints.length === 3, `three assessment calls (${endpoints.length})`);
    check(
      endpoints.every((path) => /^\/api\/v1\/assessments(\/\$\{[^}]+\})?$/.test(path)),
      `assessment endpoints unchanged (${endpoints.join(", ")})`,
    );
    pass("10 shell adds no API call; assessment endpoints plus the backend explanation endpoint");
  }

  // 11. No fake AI.
  {
    const pages = [assistant([]), assistant(history), assistant([latestComplete])];
    for (const html of pages) {
      check((html.match(/<textarea/g) ?? []).length === 1 && !/<input|contenteditable/i.test(html), "one composer, nothing else editable");
      check(/<label for="assistant-input"[^>]*>Ask about your security<\/label>/.test(html), "composer is labelled");
      check(!/Analyzing|Thinking|typing|Generating|Ollama|LLM/i.test(html), "no fake AI activity");
      check(
        html.includes("Explanations are written from your latest completed security check.") &&
          html.includes("follow fixed rules"),
        "honest note",
      );
    }
    for (const file of ["src/components/assistant/AssistantPage.tsx", "src/lib/assistantActions.ts", "src/lib/assistant/conversation.ts"]) {
      const text = source(file);
      check(!/fetchExplanation|ollama|setInterval|Math\.random/i.test(text), `${file} simulates AI`);
    }
    for (const file of ["src/components/assistant/AssistantPage.tsx", "src/lib/assistantActions.ts"]) {
      check(!/setTimeout/.test(source(file)), `${file} adds its own timers`);
    }
    pass("11 Assistant composer: no direct model call, typing indicator or simulated text");
  }

  // 12. Existing assessment navigation still works.
  {
    const verify = route("verify", history);
    check(verify?.section === "history" && verify.assessmentId === latestComplete.id, "VERIFY selects latest COMPLETE, not the newer partial run");
    check(verify.anchor?.id === "assessment-reassessment", "VERIFY scrolls to re-assessment");
    check(route("verify", [newerPartial]) === null, "VERIFY unavailable without a COMPLETE check");
    for (const id of ["whats-wrong", "explain-risk", "fix-issue", "summary"] as const) {
      check(route(id, []) === null, `${id} unavailable without history`);
    }
    const selected = historyPage({ selectedAssessmentId: latestComplete.id });
    check(selected.includes('aria-pressed="true"') && selected.includes(">Showing details below<"), "selected card");
    check(selected.includes('id="assessment-details"') && selected.includes("Loading assessment details..."), "details render for selection");
    const empty = assistant([]);
    const verifyButton = buttonWith(empty, "Check if I fixed it");
    check(verifyButton.includes('data-available="false"'), "VERIFY unavailable without a COMPLETE check");
    check(verifyButton.includes("Available after a completed security check."), "VERIFY states why");
    check(buttonWith(assistant(history), "Check if I fixed it").includes('data-available="true"'), "VERIFY available with a COMPLETE check");
    pass("12 History selection and details unchanged; actions resolve to real records");
  }

  // 13. Comparison and re-assessment remain reachable.
  {
    const tabs = historyPage();
    check(tabs.includes(">Compare checks<") && tabs.includes(">Checks &amp; details<"), "both views offered");
    const compared = historyPage({
      initialComparison: { beforeId: olderComplete.id, afterId: latestComplete.id },
    });
    check(/id="assessment-view-compare"[^>]*aria-selected="true"|aria-selected="true"[^>]*id="assessment-view-compare"/.test(compared), "compare view opened");
    check(compared.includes("Pre-selected from a re-assessment"), "pair preselected");
    const panel = renderToStaticMarkup(
      createElement(ReassessmentPanelView, {
        original: { id: latestComplete.id, target: latestComplete.target, status: latestComplete.status },
        state: { phase: "idle" },
        onRequest: noop,
        onCancel: noop,
        onConfirm: noop,
        onDismiss: noop,
        onOpenAssessment: noop,
      }),
    );
    check(panel.includes('id="assessment-reassessment"') && panel.includes("Re-assess this target"), "re-assessment anchor");
    check(requested.length === 0, "nothing started automatically");
    pass("13 comparison preselection and re-assessment panel reachable");
  }

  // 14. Structural overflow and touch targets.
  {
    const appShell = shell("assistant");
    check(appShell.includes("app-atmosphere overflow-x-clip"), "shell clips horizontal overflow");
    check(!appShell.includes("overflow-x-hidden"), "sticky header not broken by overflow-x-hidden");
    const dock = navs[1];
    check(/max-w-sm/.test(appHtml) && (dock.match(/min-w-0 flex-1/g) ?? []).length === 4, "dock items share the width");
    check((dock.match(/truncate/g) ?? []).length === 4, "dock labels truncate");
    const pages = [
      appShell,
      shell("devices"),
      assistant(history),
      renderToStaticMarkup(createElement(MorePage, { onNavigate: noop, onOpenStatus: noop })),
    ];
    for (const html of pages) {
      check(!/\b(min-)?w-\[\d{3,}px\]/.test(html), "no fixed wide elements");
      for (const classes of buttonClasses(html)) {
        check(TOUCH.test(classes), `touch target below 44px: ${classes}`);
      }
    }
    const historyControls = historyPage().split('id="assessment-panel-compare"')[0];
    for (const classes of buttonClasses(historyControls).filter((c) => c.includes("rounded-full"))) {
      check(TOUCH.test(classes), `History control below 44px: ${classes}`);
    }
    check(!/group-hover:|hover:(block|flex|inline|opacity-100|visible)/.test(pages.join("")), "nothing revealed only on hover");
    pass("14 no wide fixed elements; buttons meet 44px; nothing hover-only");
  }
} finally {
  globalThis.fetch = realFetch;
  await server.close();
}

for (const line of results) console.log(line);
console.log(`${results.filter((line) => line.startsWith("PASS")).length} checks passed`);
