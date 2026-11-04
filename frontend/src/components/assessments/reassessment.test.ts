/**
 * Checks for the Phase 3G-B re-assessment workflow. Every backend call is
 * mocked: globalThis.fetch is replaced by a stub that never reaches the
 * network, so no assessment is created. Components are loaded through Vite's
 * SSR loader and rendered with react-dom/server; no dependency is added.
 *
 * Run from frontend/:  node src/components/assessments/reassessment.test.ts
 */
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { AssessmentDetail, AssessmentStatus, AssessmentSummary } from "../../api/types.ts";

declare const process: { cwd(): string };

type ViteServer = {
  ssrLoadModule(url: string): Promise<Record<string, unknown>>;
  close(): Promise<void>;
};
type FlowModule = typeof import("./reassessment.ts");
type PanelModule = typeof import("./ReassessmentPanel.tsx");
type ComparisonModule = typeof import("./AssessmentComparison.tsx");
type ApiModule = typeof import("../../api/assessments.ts");
type ClientModule = typeof import("../../api/client.ts");
type State = import("./reassessment.ts").ReassessmentState;

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${message}`);
}

const results: string[] = [];
const pass = (name: string, note = "") =>
  results.push(`PASS ${name}${note ? ` — ${note}` : ""}`);

type FetchCall = { url: string; method: string; body: string | null };
let fetchCalls: FetchCall[] = [];
let fetchReply: () => Response = () => {
  throw new Error("unexpected fetch");
};
const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  fetchCalls.push({
    url: String(input),
    method: init?.method ?? "GET",
    body: typeof init?.body === "string" ? init.body : null,
  });
  return fetchReply();
}) as typeof fetch;

const jsonResponse = (status: number, payload: unknown) =>
  new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

// Test-only fixtures in the API response shape; never persisted.
const TARGET = "192.0.2.10";
const ORIGINAL_ID = "a0000000-0000-4000-8000-000000000001";
const NEW_ID = "b0000000-0000-4000-8000-000000000002";
const summary = (id: string, status: AssessmentStatus, startedAt: string): AssessmentSummary => ({
  id,
  target: TARGET,
  assessment_type: "MULTI_LAYER",
  status,
  started_at: startedAt,
  completed_at: status === "RUNNING" ? null : startedAt,
  error_summary: null,
  metadata: {} as AssessmentSummary["metadata"],
  created_at: startedAt,
  evidence_count: 0,
  finding_count: 0,
  highest_risk: null,
  highest_risk_level: null,
});
const detail = (
  id: string,
  status: AssessmentStatus,
  errorSummary: string | null = null,
): AssessmentDetail => ({
  ...summary(id, status, "2026-10-13T10:00:00Z"),
  error_summary: errorSummary,
  evidence: [],
  findings: [],
  risk_snapshots: [],
});
const original = detail(ORIGINAL_ID, "COMPLETE");

const viteModuleName = "vite";
const vite = (await import(viteModuleName)) as {
  createServer(config: Record<string, unknown>): Promise<ViteServer>;
};
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
  const flowModule = (await server.ssrLoadModule(
    "/src/components/assessments/reassessment.ts",
  )) as unknown as FlowModule;
  const { ReassessmentPanel, ReassessmentPanelView } = (await server.ssrLoadModule(
    "/src/components/assessments/ReassessmentPanel.tsx",
  )) as unknown as PanelModule;
  const { AssessmentComparison } = (await server.ssrLoadModule(
    "/src/components/assessments/AssessmentComparison.tsx",
  )) as unknown as ComparisonModule;
  const { createAssessment } = (await server.ssrLoadModule(
    "/src/api/assessments.ts",
  )) as unknown as ApiModule;
  const { ApiError } = (await server.ssrLoadModule(
    "/src/api/client.ts",
  )) as unknown as ClientModule;

  const noop = () => {};
  const renderView = (state: State, status: AssessmentStatus = "COMPLETE") =>
    renderToStaticMarkup(
      createElement(ReassessmentPanelView, {
        original: { ...original, status },
        state,
        onRequest: noop,
        onCancel: noop,
        onConfirm: noop,
        onDismiss: noop,
        onOpenAssessment: noop,
      }),
    );

  function makeFlow(
    run: (target: string) => Promise<AssessmentDetail>,
    status: AssessmentStatus = "COMPLETE",
  ) {
    const states: State[] = [];
    const created: AssessmentDetail[] = [];
    const completed: { beforeId: string; afterId: string }[] = [];
    const flow = flowModule.createReassessmentFlow({
      original: { id: ORIGINAL_ID, target: TARGET, status },
      run,
      onState: (state) => states.push(state),
      onCreated: (value) => created.push(value),
      onComplete: (pair) => completed.push(pair),
    });
    return { flow, states, created, completed };
  }

  const verificationWords = /resolved|remediated|still reported|resolution not confirmed|verified|fixed/i;

  // 1 + 13. COMPLETE assessment shows the action; rendering issues no request.
  {
    fetchCalls = [];
    let runCalls = 0;
    const html = renderToStaticMarkup(
      createElement(ReassessmentPanel, {
        assessment: original,
        run: async () => {
          runCalls += 1;
          return detail(NEW_ID, "COMPLETE");
        },
      }),
    );
    check(html.includes("Re-assess this target"), "action button rendered");
    check(html.includes(TARGET), "target shown");
    check(runCalls === 0, "rendering did not start an assessment");
    check(fetchCalls.length === 0, `rendering issued ${fetchCalls.length} fetch call(s)`);
    pass("1 COMPLETE assessment shows \"Re-assess this target\"");
    pass("13 rendering the action makes no network request");
  }

  // 2. Non-COMPLETE assessments do not offer or allow it.
  for (const status of ["RUNNING", "INCOMPLETE", "FAILED"] as const) {
    check(!flowModule.isReassessable({ status }), `${status} not reassessable`);
    check(renderView({ phase: "idle" }, status) === "", `${status}: nothing rendered`);
    const html = renderToStaticMarkup(
      createElement(ReassessmentPanel, { assessment: detail(ORIGINAL_ID, status) }),
    );
    check(!html.includes("Re-assess"), `${status}: container renders no action`);
    let runCalls = 0;
    const { flow, states } = makeFlow(async () => {
      runCalls += 1;
      return detail(NEW_ID, "COMPLETE");
    }, status);
    flow.request();
    await flow.confirm();
    check(states.length === 0 && runCalls === 0, `${status}: flow refuses to start`);
  }
  check(flowModule.isReassessable({ status: "COMPLETE" }), "COMPLETE reassessable");
  pass("2 RUNNING / INCOMPLETE / FAILED do not allow re-assessment");

  // 3. Confirmation required, with the required content.
  {
    let runCalls = 0;
    const { flow } = makeFlow(async () => {
      runCalls += 1;
      return detail(NEW_ID, "COMPLETE");
    });
    await flow.confirm();
    check(runCalls === 0 && flow.getState().phase === "idle", "confirm without request ignored");
    flow.request();
    check(flow.getState().phase === "confirming", "request opens confirmation");
    check(runCalls === 0, "request alone does not run");
    const html = renderView({ phase: "confirming" });
    check(html.includes(`Re-assess <span class="mono">${TARGET}</span>?`), "title names target");
    check(/active security assessment probes/.test(html), "active probes stated");
    check(/several minutes/.test(html), "duration stated");
    check(/authorized/.test(html), "authorization stated");
    check(html.includes(">Cancel<") && html.includes(">Start Re-assessment<"), "both buttons");
    check(/does not change\s+the target/.test(html), "no automatic remediation implied");
    flow.cancel();
    pass("3 confirmation required before any request");
  }

  // 4. Cancel does not call createAssessment.
  {
    let runCalls = 0;
    const { flow, states } = makeFlow(async () => {
      runCalls += 1;
      return detail(NEW_ID, "COMPLETE");
    });
    flow.request();
    flow.cancel();
    await flow.confirm();
    check(runCalls === 0, "run not called after cancel");
    check(states.map((s) => s.phase).join(",") === "confirming,idle", "confirming -> idle");
    pass("4 Cancel does not call createAssessment");
  }

  // 5. Confirm sends exactly { target } via the real API client (fetch stubbed).
  {
    fetchCalls = [];
    fetchReply = () => jsonResponse(201, detail(NEW_ID, "COMPLETE"));
    const { flow, completed } = makeFlow(createAssessment);
    flow.request();
    await flow.confirm();
    check(fetchCalls.length === 1, `one request, got ${fetchCalls.length}`);
    const [call] = fetchCalls;
    check(call.method === "POST", "method POST");
    check(call.url.endsWith("/api/v1/assessments"), `POST path (${call.url})`);
    check(call.body === JSON.stringify({ target: TARGET }), `body exactly {target} (${call.body})`);
    check(completed.length === 1, "complete callback fired");
    pass("5 confirm calls createAssessment with exactly { target }", call.body ?? "");
  }

  // 6 + 7. Running state while pending; second submissions blocked.
  {
    const pending = deferred<AssessmentDetail>();
    let runCalls = 0;
    const run = () => {
      runCalls += 1;
      return pending.promise;
    };
    const { flow } = makeFlow(run);
    flow.request();
    const first = flow.confirm();
    check(flow.getState().phase === "running", "running while pending");
    check(flowModule.isReassessmentInFlight(), "in-flight guard set");

    await flow.confirm();
    flow.request();
    await flow.confirm();
    check(runCalls === 1, `repeated clicks: run called ${runCalls}x`);

    // A second flow (e.g. a remounted panel) is also blocked.
    const other = makeFlow(run);
    other.flow.request();
    await other.flow.confirm();
    check(runCalls === 1, "second flow did not start a request");
    check(other.flow.getState().phase === "blocked", "second flow shows blocked");
    check(
      renderView({ phase: "blocked" }).includes("already running in this browser tab"),
      "blocked message",
    );

    const running = renderView({ phase: "running" });
    check(running.includes("Assessment running..."), "running title");
    check(running.includes("Active probes are being executed"), "running detail");
    check(running.includes("several minutes"), "duration note");
    check(!running.includes("Start Re-assessment"), "start button not shown while running");
    check(!/%|step \d|stage/i.test(running), "no fake progress");

    pending.resolve(detail(NEW_ID, "COMPLETE"));
    await first;
    check(!flowModule.isReassessmentInFlight(), "guard released after result");
    pass("6 double-submit protection: one createAssessment call");
    pass("7 running state shown while the request is pending");
  }

  // 8 + 9. COMPLETE result stores BEFORE/AFTER and preselects comparison.
  {
    const created = detail(NEW_ID, "COMPLETE");
    const { flow, completed, created: createdList } = makeFlow(async () => created);
    flow.request();
    await flow.confirm();
    const state = flow.getState();
    check(state.phase === "complete", "complete phase");
    check(state.beforeId === ORIGINAL_ID && state.afterId === NEW_ID, "state pair");
    check(
      completed.length === 1 &&
        completed[0].beforeId === ORIGINAL_ID &&
        completed[0].afterId === NEW_ID,
      "onComplete receives BEFORE=original, AFTER=new",
    );
    check(createdList.length === 1, "onCreated fired (history refresh)");
    const html = renderView(state);
    check(html.includes(ORIGINAL_ID) && html.includes(NEW_ID), "IDs shown");
    check(!verificationWords.test(html), "no verification wording");
    pass("8 COMPLETE result -> BEFORE = original ID, AFTER = returned ID");

    fetchCalls = [];
    const comparisonHtml = renderToStaticMarkup(
      createElement(AssessmentComparison, {
        assessments: [
          summary(NEW_ID, "COMPLETE", "2026-10-13T11:00:00Z"),
          summary(ORIGINAL_ID, "COMPLETE", "2026-10-13T10:00:00Z"),
        ],
        loading: false,
        error: null,
        onRefresh: noop,
        initialBeforeId: ORIGINAL_ID,
        initialAfterId: NEW_ID,
      }),
    );
    const selected = (selectId: string) => {
      const match = new RegExp(`<select[^>]*id="${selectId}"[^>]*>([\\s\\S]*?)</select>`).exec(
        comparisonHtml,
      );
      return match ? /<option value="([^"]*)" selected=""/.exec(match[1])?.[1] : undefined;
    };
    check(selected("comparison-before") === ORIGINAL_ID, "BEFORE select preselected");
    check(selected("comparison-after") === NEW_ID, "AFTER select preselected");
    check(comparisonHtml.includes("Pre-selected from a re-assessment"), "preselection notice");
    check(fetchCalls.length === 0, "comparison not run automatically");
    check(!comparisonHtml.includes("Comparing..."), "no comparison started");
    pass("9 COMPLETE result preselects the comparison (by ID, not position)");
  }

  // 10. INCOMPLETE result does not open verification.
  {
    const created = detail(NEW_ID, "INCOMPLETE", "MQTT probe could not complete");
    const { flow, completed, created: createdList } = makeFlow(async () => created);
    flow.request();
    await flow.confirm();
    check(flow.getState().phase === "not_complete", "not_complete phase");
    check(completed.length === 0, "comparison not opened");
    check(createdList.length === 1, "history still refreshed");
    const html = renderView(flow.getState());
    check(html.includes("INCOMPLETE"), "status shown");
    check(html.includes("Comparison was not started"), "comparison not started text");
    check(html.includes("MQTT probe could not complete"), "error_summary shown");
    check(html.includes(NEW_ID), "new ID shown");
    check(!verificationWords.test(html), "no verification wording");
    pass("10 INCOMPLETE result shows details and does not open comparison");
  }

  // 11. FAILED result does not open verification.
  {
    const created = detail(NEW_ID, "FAILED", "Assessment failed: probe error");
    const { flow, completed } = makeFlow(async () => created);
    flow.request();
    await flow.confirm();
    check(flow.getState().phase === "failed", "failed phase");
    check(completed.length === 0, "comparison not opened");
    const html = renderView(flow.getState());
    check(html.includes("The re-assessment failed."), "failed title");
    check(html.includes("Assessment failed: probe error"), "error_summary shown");
    check(html.includes(NEW_ID), "new ID shown");
    check(!verificationWords.test(html), "no verification wording");
    pass("11 FAILED result shows details and does not open comparison");
  }

  // 12. Errors come from the existing ApiError handling.
  {
    const forbidden = `Target ${TARGET} is not in ASSESSMENT_ALLOWED_TARGETS`;
    fetchCalls = [];
    fetchReply = () => jsonResponse(403, { detail: forbidden });
    const { flow, completed } = makeFlow(createAssessment);
    flow.request();
    await flow.confirm();
    const state = flow.getState();
    check(state.phase === "error", "error phase");
    check(state.message === forbidden, `403 detail passed through (${state.message})`);
    check(state.httpStatus === 403, "status 403 kept");
    check(completed.length === 0, "no comparison on error");
    check(!flowModule.isReassessmentInFlight(), "guard released after error");
    const html = renderView(state);
    check(html.includes("HTTP 403") && html.includes(forbidden), "403 rendered");

    fetchReply = () => new Response("boom", { status: 500 });
    const server500 = makeFlow(createAssessment);
    server500.flow.request();
    await server500.flow.confirm();
    const s500 = server500.flow.getState();
    check(
      s500.phase === "error" &&
        s500.httpStatus === 500 &&
        s500.message === "Backend request failed (500) for /api/v1/assessments",
      "500 uses client fallback message",
    );

    fetchReply = () => {
      throw new TypeError("network down");
    };
    const offline = makeFlow(createAssessment);
    offline.flow.request();
    await offline.flow.confirm();
    const s0 = offline.flow.getState();
    check(
      s0.phase === "error" && s0.httpStatus === null && /Unable to connect/.test(s0.message),
      "connection failure uses client message",
    );

    const direct = flowModule.errorState(new ApiError("detail text", 422));
    check(
      direct.phase === "error" && direct.message === "detail text" && direct.httpStatus === 422,
      "ApiError mapped",
    );
    pass("12 403 / 500 / connection errors use the existing API client messages");
  }
} finally {
  globalThis.fetch = realFetch;
  await server.close();
}

for (const line of results) console.log(line);
console.log(`${results.filter((line) => line.startsWith("PASS")).length} checks passed`);
