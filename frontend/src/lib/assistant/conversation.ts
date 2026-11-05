/**
 * Conversation layer on top of the UX-3A classifier and resolver. CHECK and
 * VERIFY replies are fixed confirmations of the resolved action. EXPLAIN, FIX
 * and SUMMARY of a complete latest check go through the injected `explain`
 * dependency with only an intent, subject and optional check ID; the backend
 * decides what the explanation is based on. Status questions ("Am I safe?")
 * and TECHNICAL questions (ports, services, evidence, risk factors) are
 * answered from recorded values only and never use `explain`. Nothing here
 * talks to a model.
 *
 * With the optional `workflow` dependency (UX-3C) the conversation keeps track
 * of the issue under discussion and offers next steps. A check is started only
 * by runCheck(), which the UI calls from an explicit button click; no typed or
 * classified request can reach it.
 */
import type {
  AssistantExplainBasis,
  AssistantExplainRequest,
  AssistantExplainResponse,
  AssistantExplainSource,
} from "../../api/assistant";
import type { AssessmentDetail } from "../../api/types";
import {
  createReassessmentFlow,
  isReassessmentInFlight,
} from "../../components/assessments/reassessment";
import type { AssistantShortcutId } from "../assistantActions";
import type { NavRequest } from "../navigation";
import type { AssistantContext, AssistantIssue } from "./context";
import {
  WORKFLOW_ACTIONS,
  comparisonSummary,
  contextResultCard,
  guidedFixAction,
  issueCard,
  issuesCard,
  runResultReply,
  selectedIssue,
  type AssistantActionButton,
  type AssistantCard,
  type AssistantWorkflowState,
  type ConversationTopic,
  type WorkflowActionId,
  type WorkflowRunKind,
} from "./workflow";
import {
  ALL_FINDINGS_PHRASES,
  classifyAssistantIntent,
  FINDING_COUNT_PHRASES,
  normalizeRequest,
  NO_PHRASE_REASON,
  STATUS_PHRASES,
  type AssistantIntent,
  type AssistantIntentResult,
} from "./intents";
import {
  askedPort,
  devicesAnswer,
  evidenceAnswer,
  issueTechnicalAnswer,
  portChoiceAnswer,
  portsAnswer,
  recordedOpenPorts,
  riskFactorsAnswer,
  servicesAnswer,
  statusAnswer,
  withTechnicalOpen,
  assetFindingsAnswer,
  type FactAnswer,
} from "./facts";
import { classifyFollowUp, type FollowUpKind } from "./followUp";
import {
  bindReference,
  resolveReferenceRequest,
  type ConversationContext,
  type ResolvedReference,
} from "./references";
import {
  ASPECT_REQUEST,
  VERIFICATION_HEADLINE,
  buildGuidedRemediation,
  fixAspect,
  guidePlace,
  guideSectionText,
  verifyIssue,
  type FixAspect,
} from "./guidedFix";
import {
  askedFindingCount,
  buildAllFindingsResponse,
  buildClarificationResponse,
  buildFindingCountResponse,
  buildFixListResponse,
  buildIssueExplanationResponse,
  buildIssueGroupResponse,
  buildIssueSummaryResponse,
  buildMostSeriousResponse,
  buildNoMatchResponse,
  buildNoSeverityResponse,
  buildPortIssuesResponse,
  buildWhichIssueResponse,
} from "./replies";
import { redactRuntimeText, redactSecrets } from "./redact";
import {
  actionDestination,
  resolveAssistantIntent,
  workflowDestination,
  type WorkflowDestinationId,
  type AssistantAction,
  type AssistantActionType,
  type AssistantResolution,
} from "./resolve";

export type AssistantMessageRole = "user" | "assistant";

/** UI state only: text the user typed or a fixed reply, never backend records. */
export type AssistantMessage = {
  id: string;
  role: AssistantMessageRole;
  text: string;
  timestamp: number;
  intent?: AssistantIntent;
  action?: AssistantAction;
  /** Shortcuts offered as next steps, e.g. "Check my IoT network". */
  suggestions?: AssistantShortcutId[];
  tone?: "error";
  /** Set on explanation replies from the backend; `action` is then offered as an Open button. */
  source?: AssistantExplainSource;
  /** Recorded sections the backend used for that explanation. */
  basis?: AssistantExplainBasis[];
  /** Deterministic backend values shown above any explanation text. */
  card?: AssistantCard;
  /** Next steps; only run-* buttons start a check, and only when clicked. */
  actions?: AssistantActionButton[];
};

export const MAX_CONVERSATION_MESSAGES = 50;

/** Fixed pauses so the processing state and the reply are readable before navigation. */
export const PROCESSING_MS = 350;
export const OPEN_DELAY_MS = 900;
/** While the checks or latest issues are still loading, re-read the context before replying. */
export const LOADING_POLL_MS = 250;
export const LOADING_MAX_POLLS = 20;

export const PROCESSING_LABEL = "Checking what you asked for…";

const OPENING_LABEL: Record<Exclude<AssistantActionType, "ASK_CLARIFICATION">, string> = {
  OPEN_ASSESSMENT: "Opening a new security check…",
  OPEN_SECURITY: "Opening security details…",
  OPEN_FINDING: "Opening security details…",
  OPEN_RISK: "Opening risk details…",
  OPEN_REASSESSMENT: "Opening the re-assessment step…",
  SHOW_SUMMARY: "Opening your security summary…",
};

export function openingLabel(type: AssistantActionType): string {
  return type === "ASK_CLARIFICATION" ? PROCESSING_LABEL : OPENING_LABEL[type];
}

export const UNKNOWN_REPLY =
  "I can help with checking your network, explaining your risk, fixing issues, verifying changes, or summarizing your latest check. What would you like to do?";

export const ERROR_REPLY = "I couldn't complete that action. You can try again.";

export type AssistantReply = { text: string; suggestions?: AssistantShortcutId[] };

/** Opening sentence for the conversation, from AssistantContext only. */
export function introText(context: AssistantContext): string {
  switch (context.availability) {
    case "NO_ASSESSMENT":
      return "I haven't checked your IoT network yet.";
    case "ASSESSMENT_AVAILABLE":
      return "I have your latest security check available.";
    case "ASSESSMENT_INCOMPLETE":
      return "Your latest security check isn't complete yet.";
    case "ASSESSMENT_FAILED":
      return "Your latest security check did not complete successfully.";
    case "ASSESSMENT_RUNNING":
      return "Your latest security check is still running.";
  }
}

function needsCheckReply(intent: AssistantIntentResult): string {
  switch (intent.intent) {
    case "EXPLAIN":
      return intent.subject === "RISK"
        ? "I need a completed security check before I can explain your current risk."
        : "I need a completed security check before I can show what's wrong.";
    case "FIX":
      return "I need a completed security check before I can help you fix an issue.";
    case "VERIFY":
      return "I need a completed security check before I can verify a fix.";
    case "FIXED":
      return "I need a completed security check before I can verify a change. Run a security check first.";
    case "COMPARE":
      return "I need a completed security check before I can show what changed. Run a security check first.";
    case "TECHNICAL":
      return "I need a completed security check before I can answer that. Run a security check first.";
    default:
      return "I haven't checked your IoT network yet, so there's nothing to summarize.";
  }
}

function notCompleteReply(intent: AssistantIntentResult, context: AssistantContext | null): string {
  const fix = intent.intent === "FIX";
  switch (context?.availability) {
    case "ASSESSMENT_FAILED":
      return fix
        ? "Your latest security check failed, so there isn't a current issue to fix."
        : "Your latest security check failed, so there isn't a current security result to explain.";
    case "ASSESSMENT_RUNNING":
      return "Your latest security check is still running, so there isn't a current result yet.";
    default:
      return fix
        ? "Your latest security check isn't complete, so I can't point to a current issue to fix yet."
        : "Your latest security check isn't complete, so I can't explain a current security result yet.";
  }
}

function summaryReply(context: AssistantContext | null): string {
  switch (context?.availability) {
    case "ASSESSMENT_INCOMPLETE":
      return "The latest security check did not complete, so I can't summarize a current security result. I'll show you what it recorded.";
    case "ASSESSMENT_FAILED":
      return "The latest security check failed, so there isn't a current security result to summarize. I'll show you what happened.";
    case "ASSESSMENT_RUNNING":
      return "Your latest security check is still running, so there isn't a result to summarize yet. I'll show you its status.";
    default:
      return "I'll summarize your latest security check.";
  }
}

/** Fixed reply for a resolution. Confirms the action; states no findings. */
export function assistantReply(
  intent: AssistantIntentResult,
  resolution: AssistantResolution,
  context: AssistantContext | null,
): AssistantReply {
  if (resolution.state === "READY") {
    switch (resolution.action.type) {
      case "OPEN_ASSESSMENT":
        return {
          text: "I'll set up a security check of your authorized IoT target. It starts only when you choose Run Assessment.",
        };
      case "OPEN_RISK":
        return { text: "I'll show you why your current risk level is what it is." };
      case "OPEN_SECURITY":
        return { text: "I'll show you the important security issues from your latest check." };
      case "OPEN_FINDING":
        return { text: "I'll show you the most important issue to fix first." };
      case "OPEN_REASSESSMENT":
        return {
          text: "I'll compare a new security check with your previous completed check. The new check runs only after you confirm it.",
        };
      case "SHOW_SUMMARY":
        return { text: summaryReply(context) };
    }
  }

  if (intent.intent === "UNKNOWN") return { text: UNKNOWN_REPLY };

  switch (resolution.blocker) {
    case "ASSESSMENTS_LOADING":
      return { text: "I'm still loading your security checks. Please try again in a moment." };
    case "NO_ASSESSMENT":
    case "NO_COMPLETE_ASSESSMENT":
      return { text: needsCheckReply(intent), suggestions: ["check"] };
    case "LATEST_NOT_COMPLETE":
      return {
        text: notCompleteReply(intent, context),
        suggestions: context?.availability === "ASSESSMENT_RUNNING" ? ["summary"] : ["check", "summary"],
      };
    case "ISSUES_LOADING":
      return { text: "I'm still loading the issues from your latest check. Please try again in a moment." };
    case "ISSUES_UNAVAILABLE":
      return { text: "I couldn't load the issues from your latest check. You can try again." };
    case "NO_IMPORTANT_ISSUES":
      return {
        text: "Your latest completed check didn't report an important issue to fix.",
        suggestions: ["summary"],
      };
    default:
      return { text: UNKNOWN_REPLY };
  }
}

export const EXPLAINING_LABEL = "Preparing an explanation from your latest security check…";

/**
 * The minimal backend request for an explanation, or null when the request
 * stays deterministic: CHECK, VERIFY, anything blocked, and any latest check
 * that isn't complete (an older check is never explained as current).
 */
export function explainRequestFor(
  intent: AssistantIntentResult,
  resolution: AssistantResolution,
  context: AssistantContext | null,
): AssistantExplainRequest | null {
  if (resolution.state !== "READY" || context?.availability !== "ASSESSMENT_AVAILABLE") {
    return null;
  }
  switch (resolution.intent) {
    case "EXPLAIN":
      return { intent: "EXPLAIN", subject: intent.subject === "RISK" ? "RISK" : "ISSUES" };
    case "FIX":
      return { intent: "FIX" };
    case "SUMMARY":
      return { intent: "SUMMARY" };
    default:
      return null;
  }
}

const SOURCE_LABEL: Record<AssistantExplainSource, string> = {
  AI: "AI explanation based on your latest security check.",
  DETERMINISTIC_FALLBACK:
    "AI explanation unavailable. Standard summary based on your latest security check.",
  DETERMINISTIC: "Based on your latest security check.",
};

export function sourceLabel(source: AssistantExplainSource): string {
  return SOURCE_LABEL[source];
}

const OPEN_ACTION_LABEL: Partial<Record<AssistantActionType, string>> = {
  OPEN_RISK: "Open risk details",
  OPEN_SECURITY: "Open security issues",
  OPEN_FINDING: "Open issue details",
  SHOW_SUMMARY: "Open security summary",
};

/** Label for the Open button under an explanation; null when there is nothing to open. */
export function openActionLabel(type: AssistantActionType): string | null {
  return OPEN_ACTION_LABEL[type] ?? null;
}

const MAX_EXPLANATION_CHARS = 2000;
const NEEDS_CHECK_SUGGESTIONS: AssistantShortcutId[] = ["check"];

export type ExplanationReply = {
  text: string;
  source?: AssistantExplainSource;
  basis?: AssistantExplainBasis[];
  suggestions?: AssistantShortcutId[];
  tone?: "error";
};

export const EXPLAIN_BASIS_ORDER: readonly AssistantExplainBasis[] = [
  "RISK_RESULT",
  "RISK_CONTRIBUTORS",
  "FINDINGS",
  "REMEDIATION",
  "LIMITATIONS",
];

/** Known section names only, in a fixed order; anything else is dropped. */
export function explanationBasis(value: unknown): AssistantExplainBasis[] {
  if (!Array.isArray(value)) return [];
  return EXPLAIN_BASIS_ORDER.filter((item) => value.includes(item));
}

function controlledText(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const text = value.trim();
  if (!text || text.length > MAX_EXPLANATION_CHARS) return null;
  return redactSecrets(text);
}

/** Message for a backend explanation response; anything unexpected becomes the generic error. */
export function explanationReply(response: AssistantExplainResponse | null | undefined): ExplanationReply {
  const failure: ExplanationReply = { text: ERROR_REPLY, tone: "error" };
  if (!response || typeof response !== "object") return failure;
  switch (response.status) {
    case "COMPLETE": {
      const text = controlledText(response.answer);
      const source = response.source;
      if (!text || !source || !(source in SOURCE_LABEL)) return failure;
      const basis = explanationBasis(response.basis);
      return basis.length ? { text, source, basis } : { text, source };
    }
    case "NEEDS_ASSESSMENT":
    case "ASSESSMENT_INCOMPLETE":
    case "ASSESSMENT_FAILED":
    case "OUT_OF_SCOPE": {
      const text = controlledText(response.message);
      return text ? { text, suggestions: NEEDS_CHECK_SUGGESTIONS } : failure;
    }
    case "ASSESSMENT_RUNNING": {
      const text = controlledText(response.message);
      return text ? { text, suggestions: ["summary"] } : failure;
    }
    case "ISSUE_NOT_FOUND": {
      const text = controlledText(response.message);
      return text ? { text, suggestions: ["whats-wrong"] } : failure;
    }
    default:
      return { text: controlledText(response.message) ?? ERROR_REPLY, tone: "error" };
  }
}

const MAX_ERROR_DETAIL = 160;

/**
 * Short explanation for a known API error (an object with a numeric status
 * and a message), first line only. A message that contains a secret, URL or
 * path, or anything else, yields null so only the generic reply is shown.
 */
export function safeErrorDetail(error: unknown): string | null {
  if (!error || typeof error !== "object") return null;
  const { status, message } = error as { status?: unknown; message?: unknown };
  if (typeof status !== "number" || typeof message !== "string") return null;
  const firstLine = (message.split(/\r?\n/)[0] ?? "").replace(/\s+/g, " ").trim();
  if (!firstLine || firstLine.length > MAX_ERROR_DETAIL) return null;
  if (redactRuntimeText(firstLine) !== firstLine) return null;
  return firstLine;
}

export function errorReply(error: unknown): string {
  const detail = safeErrorDetail(error);
  return detail ? `${ERROR_REPLY} ${detail}` : ERROR_REPLY;
}

export type ComposerKey = { key: string; shiftKey: boolean; isComposing?: boolean };

/** Enter sends; Shift+Enter (and Enter during IME composition) inserts a newline. */
export function composerKeyAction(event: ComposerKey): "submit" | "newline" | "none" {
  if (event.key !== "Enter") return "none";
  if (event.shiftKey || event.isComposing) return "newline";
  return "submit";
}

export type RequestOutcome =
  | { status: "rejected"; reason: "empty" | "busy" | "closed" }
  | { status: "answered"; resolution: AssistantResolution }
  | { status: "failed" };

export type ConversationDeps = {
  /** Current context; null while assessments are loading. */
  getContext: () => AssistantContext | null;
  /** The app's existing navigation (UX-2 NavRequest). */
  navigate: (request: NavRequest) => void;
  addMessage: (message: AssistantMessage) => void;
  /** Processing label while a request is handled; null when idle. */
  setStatus: (label: string | null) => void;
  /** Backend explanation endpoint; without it every reply stays deterministic. */
  explain?: (request: AssistantExplainRequest) => Promise<AssistantExplainResponse>;
  /** UX-3C workflow; without it the UX-3B behaviour is unchanged. */
  workflow?: WorkflowDeps;
  /** The already-loaded GET /assessments/{id} of the latest COMPLETE check, or null. */
  getLatestDetail?: () => AssessmentDetail | null;
  wait?: (ms: number) => Promise<void>;
  now?: () => number;
  nextId?: () => string;
  isReadOnly?: boolean;
};

export type WorkflowDeps = {
  /** Kept by the app so it survives leaving the Assistant. */
  get: () => AssistantWorkflowState;
  update: (patch: Partial<AssistantWorkflowState>) => void;
  /** The existing POST /api/v1/assessments; called only from runCheck(). */
  runAssessment: (target: string) => Promise<AssessmentDetail>;
  /** The existing GET /api/v1/assessments/{id}. */
  loadAssessment: (assessmentId: string) => Promise<AssessmentDetail>;
  onAssessmentCreated?: (created: AssessmentDetail) => void;
};

export type NavigationActionId = Extract<WorkflowActionId, WorkflowDestinationId>;

export type AssistantConversation = {
  handleAssistantRequest: (text: string) => Promise<RequestOutcome>;
  isBusy: () => boolean;
  /** Open the destination of an explanation's action (the Open button). */
  openAction: (action: AssistantAction) => void;
  /** Explicit "Run security check" / "Run verification check" click. */
  runCheck: (kind: WorkflowRunKind) => Promise<void>;
  /** The user chose an issue from a list in the conversation. */
  selectIssue: (checkId: string) => void;
  /** Explicit "Start guided fix" / "View guided fix" click for one issue. */
  startGuidedFix: (checkId: string) => void;
  /** Explicit "Not yet" click: no verification check is started. */
  declineVerification: () => void;
  openWorkflowAction: (id: NavigationActionId) => void;
  /** Stop after the current step; nothing further is added or opened. */
  close: () => void;
};

export const COMPARING_LABEL = "Comparing your checks…";
const ISSUES_UNAVAILABLE_REPLY = "I couldn't load the issues from your latest check. You can try again.";
const STALE_ISSUE_REPLY = "That issue isn't in your latest security check anymore.";
const RUNNING_REPLY = "A security check is already running. I'll show the result when it finishes.";

const DETAIL_UNAVAILABLE_REPLY = "I couldn't load the details of your latest check. You can try again.";

/** "What's wrong?" lists the issues; "why is this risky" explains one or all. */
function asksForIssueList(intent: AssistantIntentResult): boolean {
  return intent.matchedPhrase === null || intent.matchedPhrase === "what is wrong" || intent.matchedPhrase === "whats wrong";
}

function asksForStatus(intent: AssistantIntentResult): boolean {
  return intent.intent === "SUMMARY" && intent.matchedPhrase !== null && STATUS_PHRASES.includes(intent.matchedPhrase);
}

/** "How do you know this is vulnerable?" is about the issue under discussion. */
function refersToCurrentIssue(text: string): boolean {
  return / (this|it|that) /.test(` ${normalizeRequest(text)} `);
}

/**
 * Requests that may refer to listed issues. CHECK, VERIFY, COMPARE, SUMMARY
 * and questions about ports, services, devices or risk keep their own
 * meaning, so "Did I fix both?" stays a verification request.
 */
function mayRefer(intent: AssistantIntentResult): boolean {
  switch (intent.intent) {
    case "UNKNOWN":
    case "EXPLAIN":
    case "FIX":
      return intent.subject !== "RISK";
    case "TECHNICAL":
      return intent.subject === "FINDINGS" || intent.subject === "EVIDENCE";
    default:
      return false;
  }
}

/** "How do I fix the more serious one?", "What should I do first?": the most severe issue. */
function asksForMostSerious(text: string): boolean {
  return / (more|most) (serious|important|dangerous|urgent) | (worse|worst|first) /.test(` ${normalizeRequest(text)} `);
}

/** "What is running there?" is about the port of the previous answer; "Is there any port open?" is not. */
function refersToPreviousPort(text: string): boolean {
  const padded = ` ${normalizeRequest(text)} `;
  return / (on it|on that|on this|that port|this port) /.test(padded) || /(?<! is| are) there /.test(padded);
}

const EXPLAIN_WHY_PHRASE = normalizeRequest(WORKFLOW_ACTIONS.explainWhy.label);

const NO_CHECK_TO_EXPLAIN_REPLY = "There's no completed security check to explain yet. Run a security check first.";

let messageSequence = 0;
const defaultId = () => `msg-${Date.now().toString(36)}-${++messageSequence}`;
const defaultWait = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export function createAssistantConversation(deps: ConversationDeps): AssistantConversation {
  const wait = deps.wait ?? defaultWait;
  const now = deps.now ?? Date.now;
  const nextId = deps.nextId ?? defaultId;
  let busy = false;
  let closed = false;

  type Reply = Omit<AssistantMessage, "id" | "role" | "timestamp">;
  /** Adds a reply; an issue list (card or `shown`) becomes what "these two" and "the first one" refer to. */
  const addReply = (message: Reply, shown?: readonly string[]) => {
    deps.addMessage({ id: nextId(), role: "assistant", timestamp: now(), ...message });
    const listed = shown ?? (message.card?.kind === "ISSUES" ? message.card.issues.map((issue) => issue.checkId) : null);
    if (listed && deps.workflow) deps.workflow.update({ shownIssues: [...listed] });
  };
  const replyWith = (answer: FactAnswer, intent: AssistantIntent | undefined) =>
    addReply(
      {
        text: answer.text,
        ...(intent ? { intent } : {}),
        ...(answer.card ? { card: answer.card } : {}),
        ...(answer.actions.length ? { actions: answer.actions } : {}),
      },
      answer.shown,
    );

  /**
   * Explanation through the backend. The card and next steps are deterministic
   * and shown whether or not an explanation could be prepared.
   */
  async function explainWith(
    request: AssistantExplainRequest,
    resolution: AssistantResolution,
    context: AssistantContext,
    options: { card?: AssistantCard; actions: AssistantActionButton[]; openButton?: boolean },
  ): Promise<RequestOutcome> {
    const explain = deps.explain!;
    deps.setStatus(EXPLAINING_LABEL);
    const response = await explain(request);
    if (closed) return { status: "rejected", reason: "closed" };
    if (response?.status === "ISSUE_NOT_FOUND") return staleIssueReply(context, resolution);
    const explanation = explanationReply(response);
    const answered = Boolean(explanation.source);
    addReply({
      text: explanation.text,
      intent: resolution.intent,
      ...(answered ? { source: explanation.source } : {}),
      ...(explanation.basis ? { basis: explanation.basis } : {}),
      ...(options.card ? { card: options.card } : {}),
      ...(answered && options.openButton ? { action: resolution.action } : {}),
      ...(options.actions.length ? { actions: options.actions } : {}),
      ...(explanation.suggestions ? { suggestions: explanation.suggestions } : {}),
      ...(explanation.tone ? { tone: explanation.tone } : {}),
    });
    return { status: "answered", resolution };
  }

  async function waitForIssues(context: AssistantContext): Promise<AssistantContext | null> {
    let current: AssistantContext | null = context;
    for (let poll = 0; poll < LOADING_MAX_POLLS && current?.issueStatus === "LOADING"; poll++) {
      await wait(LOADING_POLL_MS);
      if (closed) return null;
      current = deps.getContext();
    }
    return current;
  }

  function staleIssueReply(context: AssistantContext, resolution: AssistantResolution): RequestOutcome {
    deps.workflow?.update({ activeFindingCheckId: null });
    const hasIssues = (context.importantIssues?.length ?? 0) > 0;
    addReply({
      text: hasIssues ? `${STALE_ISSUE_REPLY} Choose one of the current issues.` : STALE_ISSUE_REPLY,
      intent: resolution.intent,
      ...(hasIssues ? { card: issuesCard(context) } : {}),
    });
    return { status: "answered", resolution };
  }

  /**
   * Status questions ("Am I safe?") and TECHNICAL questions about a complete
   * latest check, answered from recorded values only; never through `explain`.
   * Returns null otherwise, so blocked and not-complete states keep their replies.
   */
  async function handleFacts(
    intent: AssistantIntentResult,
    resolution: AssistantResolution,
    initialContext: AssistantContext | null,
    text: string,
  ): Promise<RequestOutcome | null> {
    const status = asksForStatus(intent);
    if (!status && intent.intent !== "TECHNICAL") return null;
    if (resolution.state !== "READY" || initialContext?.availability !== "ASSESSMENT_AVAILABLE") return null;
    const context = await waitForIssues(initialContext);
    if (!context) return { status: "rejected", reason: "closed" };
    const answered: RequestOutcome = { status: "answered", resolution };
    const assessmentId = context.latestAssessment?.id ?? null;
    const flow = deps.workflow;
    const reply = (answer: FactAnswer) => replyWith(answer, resolution.intent);

    if (status) {
      flow?.update({ stage: "REVIEW", lastAction: "SUMMARY", activeAssessmentId: assessmentId, topic: "RISK" });
      reply(statusAnswer(context));
      return answered;
    }

    if (intent.subject === "FINDINGS") {
      if (context.issueStatus !== "AVAILABLE") {
        addReply({ text: ISSUES_UNAVAILABLE_REPLY, intent: "TECHNICAL", tone: "error" });
        return answered;
      }
      flow?.update({ stage: "REVIEW", lastAction: "EXPLAIN", activeAssessmentId: assessmentId, topic: "ISSUES" });
      const loaded = deps.getLatestDetail?.() ?? null;
      const detail = loaded && loaded.id === assessmentId ? loaded : null;
      if (detail) {
        const assetAns = assetFindingsAnswer(detail, text);
        if (assetAns) {
          reply(assetAns);
          return answered;
        }
      }
      const phrase = intent.matchedPhrase ?? "";
      if (context.findingCounts && FINDING_COUNT_PHRASES.includes(phrase)) {
        reply(buildFindingCountResponse(context, askedFindingCount(phrase)));
      } else if (context.findingCounts && ALL_FINDINGS_PHRASES.includes(phrase)) {
        reply(buildAllFindingsResponse(context, detail));
      } else {
        reply(buildIssueSummaryResponse(context));
      }
      return answered;
    }

    const loaded = deps.getLatestDetail?.() ?? null;
    const detail = loaded && loaded.id === assessmentId ? loaded : null;
    if (!detail) {
      addReply({ text: DETAIL_UNAVAILABLE_REPLY, intent: "TECHNICAL", tone: "error" });
      return answered;
    }
    flow?.update({ stage: "REVIEW", activeAssessmentId: assessmentId });
    const port = askedPort(text) ?? (flow && refersToPreviousPort(text) ? flow.get().topicPort : null);
    switch (intent.subject) {
      case "PORTS":
        flow?.update({ topic: "PORTS", topicPort: port, shownIssues: [] });
        reply(portsAnswer(detail, port));
        break;
      case "SERVICES":
        flow?.update({ topic: "PORTS", topicPort: port, shownIssues: [] });
        reply(servicesAnswer(detail, port));
        break;
      case "DEVICES":
        flow?.update({ topic: "PORTS", topicPort: null, shownIssues: [] });
        reply(devicesAnswer(detail, text));
        break;
      case "EVIDENCE": {
        const state = flow?.get();
        const focused = state && (refersToCurrentIssue(text) || state.topic === "ISSUE");
        const current = flow && focused ? selectedIssue(context, flow.get()).issue : null;
        flow?.update({ topic: current ? "ISSUE" : "ISSUES" });
        reply(evidenceAnswer(detail, current?.checkId ?? null));
        break;
      }
      default:
        flow?.update({ topic: "RISK", shownIssues: [] });
        reply(riskFactorsAnswer(detail));
    }
    return answered;
  }

  /** The loaded detail of the context's latest check, or null. */
  function detailOf(context: AssistantContext): AssessmentDetail | null {
    const latest = deps.getLatestDetail?.() ?? null;
    return latest && latest.id === context.latestAssessment?.id ? latest : null;
  }

  /**
   * The guided fix of one issue, or one section of it, built from the
   * recorded fix and recorded evidence only. No explanation is requested;
   * "Explain why this matters" offers the existing AI explanation instead.
   */
  function guidedReply(context: AssistantContext, issue: AssistantIssue, aspect: FixAspect, intent?: AssistantIntent): void {
    const detail = detailOf(context);
    const guide = buildGuidedRemediation(issue, guidePlace(issue, context.latestAssessment?.target ?? null, detail), detail);
    deps.workflow?.update({
      stage: "FIX",
      lastAction: "FIX",
      activeFindingCheckId: issue.checkId,
      activeAssessmentId: context.latestAssessment?.id ?? null,
      topic: "ISSUE",
    });
    const about = intent ? { intent } : {};
    if (aspect === "STEPS") {
      addReply({
        text:
          guide.mode === "STEPS"
            ? `Here's how to fix “${issue.title}”, step by step.`
            : `I can explain what needs to change for “${issue.title}”, but I can't give exact steps.`,
        ...about,
        card: { kind: "GUIDED_FIX", guide },
        actions: [WORKFLOW_ACTIONS.completedFix, WORKFLOW_ACTIONS.checkFixed, WORKFLOW_ACTIONS.explainWhy],
      });
      return;
    }
    addReply({
      text: guideSectionText(guide, aspect),
      ...about,
      actions:
        aspect === "WHERE"
          ? [WORKFLOW_ACTIONS.showSteps, WORKFLOW_ACTIONS.whatAffect]
          : aspect === "IMPACT"
            ? [WORKFLOW_ACTIONS.showSteps, WORKFLOW_ACTIONS.howKnowFixed]
            : [WORKFLOW_ACTIONS.checkFixed, WORKFLOW_ACTIONS.showSteps],
    });
  }

  /**
   * UX-3C handling. Returns null to fall back to the UX-3B behaviour, which
   * still covers every blocked or not-complete state.
   */
  async function handleWorkflow(
    intent: AssistantIntentResult,
    resolution: AssistantResolution,
    initialContext: AssistantContext | null,
    text: string,
  ): Promise<RequestOutcome | null> {
    const flow = deps.workflow;
    if (!flow || !initialContext) return null;
    let context: AssistantContext = initialContext;
    const workflow = flow.get();
    const baseline = context.verificationBaseline;
    const available = context.availability === "ASSESSMENT_AVAILABLE";
    const answered: RequestOutcome = { status: "answered", resolution };

    switch (intent.intent) {
      case "CHECK": {
        if (deps.isReadOnly) {
          addReply({
            text: "Active vulnerability assessments are disabled in this cloud monitoring deployment. You can execute authorized security assessments through the local laboratory environment.",
            intent: "CHECK",
          });
          return answered;
        }
        if (workflow.running) {
          addReply({ text: RUNNING_REPLY, intent: "CHECK" });
          return answered;
        }
        if (!baseline) return null;
        flow.update({ stage: "CHECK", lastAction: "CHECK" });
        addReply({
          text: `I'll run a new security check of your authorized IoT target, ${baseline.target}. It starts only when you choose Run security check.`,
          intent: "CHECK",
          actions: [WORKFLOW_ACTIONS.runCheck, WORKFLOW_ACTIONS.openCheckForm],
        });
        return answered;
      }

      case "VERIFY":
      case "FIXED": {
        if (deps.isReadOnly) {
          addReply({
            text: "Active vulnerability assessments are disabled in this cloud monitoring deployment. You can execute authorized security assessments through the local laboratory environment.",
            intent: intent.intent,
          });
          return answered;
        }
        if (resolution.state !== "READY" || !baseline) {
          if (intent.intent === "VERIFY") return null;
          addReply({ text: needsCheckReply(intent), intent: "FIXED", suggestions: ["check"] });
          return answered;
        }
        if (workflow.running) {
          addReply({ text: RUNNING_REPLY, intent: intent.intent });
          return answered;
        }
        // "I fixed it" is the user's statement only; whether it is fixed is known after a new check.
        const { issue } = selectedIssue(context, workflow);
        flow.update({ stage: "VERIFY", lastAction: "VERIFY" });
        const run = "Nothing runs until you choose Run verification check.";
        let reply: string;
        if (intent.intent === "FIXED") {
          reply = issue
            ? `Ready to verify?\nYour previous check found “${issue.title}”.\nI'll run a new security check of your authorized target, ${baseline.target}, and compare the result. ${run}`
            : `Ready to verify?\nI'll run a new security check of your authorized target, ${baseline.target}, and compare it with your last completed check. ${run}`;
        } else {
          reply = issue
            ? `Only a new security check can show whether “${issue.title}” is fixed.\nI'll run one of ${baseline.target} and compare it with your last completed check. ${run}`
            : `I can verify that with a new security check of ${baseline.target}, compared with your last completed check.\n${run}`;
        }
        addReply({ text: reply, intent: intent.intent, actions: [WORKFLOW_ACTIONS.runVerification, WORKFLOW_ACTIONS.notYet] });
        return answered;
      }

      case "COMPARE": {
        if (workflow.running) {
          addReply({ text: "Your new check is still running. I can compare once it finishes.", intent: "COMPARE" });
          return answered;
        }
        const beforeId = workflow.baselineAssessmentId;
        const afterId = workflow.latestAssessmentId;
        // A pair is only current while its AFTER check is still the latest one
        // (the list may not have reloaded yet, so BEFORE still counts).
        const latestId = context.latestAssessment?.id;
        if (!beforeId || !afterId || (latestId !== afterId && latestId !== beforeId)) {
          addReply({
            text: "Run a new security check first so I can compare it with your previous check.",
            intent: "COMPARE",
            ...(baseline ? { actions: [WORKFLOW_ACTIONS.runVerification] } : { suggestions: ["check"] }),
          });
          return answered;
        }
        deps.setStatus(COMPARING_LABEL);
        let summary: ReturnType<typeof comparisonSummary>;
        try {
          const [before, after] = await Promise.all([flow.loadAssessment(beforeId), flow.loadAssessment(afterId)]);
          if (closed) return { status: "rejected", reason: "closed" };
          summary = comparisonSummary(before, after);
        } catch {
          if (closed) return { status: "rejected", reason: "closed" };
          addReply({ text: "I couldn't load the two checks to compare them. You can try again.", intent: "COMPARE", tone: "error" });
          return answered;
        }
        flow.update({ stage: "COMPARE" });
        addReply(
          summary.comparable
            ? {
                text: summary.text,
                intent: "COMPARE",
                card: summary.card,
                actions: [WORKFLOW_ACTIONS.openComparison, WORKFLOW_ACTIONS.summarizeNewCheck],
              }
            : { text: summary.text, intent: "COMPARE", actions: [WORKFLOW_ACTIONS.openComparison] },
        );
        return answered;
      }

      case "EXPLAIN": {
        if (!available || resolution.state !== "READY" || !deps.explain) return null;
        const assessmentId = context.latestAssessment?.id ?? null;
        if (intent.subject === "RISK") {
          flow.update({ stage: "EXPLAIN", lastAction: "EXPLAIN", activeAssessmentId: assessmentId, topic: "RISK", shownIssues: [] });
          return explainWith({ intent: "EXPLAIN", subject: "RISK" }, resolution, context, {
            card: contextResultCard(context),
            actions: [WORKFLOW_ACTIONS.reviewIssues],
            openButton: true,
          });
        }
        const loaded = await waitForIssues(context);
        if (!loaded) return { status: "rejected", reason: "closed" };
        context = loaded;
        if (context.issueStatus !== "AVAILABLE") {
          addReply({ text: ISSUES_UNAVAILABLE_REPLY, intent: "EXPLAIN", tone: "error" });
          return answered;
        }
        if (asksForIssueList(intent)) {
          flow.update({ stage: "REVIEW", lastAction: "EXPLAIN", activeAssessmentId: assessmentId, topic: "ISSUES" });
          const list = buildIssueSummaryResponse(context);
          addReply({
            text: list.text,
            intent: "EXPLAIN",
            ...(list.card ? { card: list.card } : {}),
            actions: list.actions,
          });
          return answered;
        }
        const { issue, stale } = selectedIssue(context, flow.get());
        if (stale) return staleIssueReply(context, resolution);
        // "Explain why this matters" follows a guided fix: the steps are shown, so offer the way to verify instead.
        const fromGuide = intent.matchedPhrase === EXPLAIN_WHY_PHRASE;
        flow.update({ stage: "EXPLAIN", lastAction: "EXPLAIN", activeAssessmentId: assessmentId, topic: issue ? "ISSUE" : "ISSUES" });
        if (issue) {
          return explainWith({ intent: "EXPLAIN", subject: "ISSUES", issue: issue.checkId }, resolution, context, {
            card: issueCard(issue, false),
            actions: fromGuide
              ? [WORKFLOW_ACTIONS.completedFix, WORKFLOW_ACTIONS.checkFixed]
              : [WORKFLOW_ACTIONS.howFix, WORKFLOW_ACTIONS.technicalDetails],
          });
        }
        return explainWith({ intent: "EXPLAIN", subject: "ISSUES" }, resolution, context, {
          actions: [WORKFLOW_ACTIONS.reviewIssues, WORKFLOW_ACTIONS.howFix],
        });
      }

      case "FIX": {
        if (!available || resolution.state !== "READY") return null;
        const loaded = await waitForIssues(context);
        if (!loaded) return { status: "rejected", reason: "closed" };
        context = loaded;
        if (context.issueStatus !== "AVAILABLE") {
          addReply({ text: ISSUES_UNAVAILABLE_REPLY, intent: "FIX", tone: "error" });
          return answered;
        }
        const issues = context.importantIssues ?? [];
        // No important issue: the backend's deterministic FIX answer says so.
        if (!issues.length) return null;
        const aspect = fixAspect(intent.matchedPhrase);
        let issue: AssistantIssue | null;
        let choices: readonly AssistantIssue[] = issues;
        if (aspect === "STEPS" && asksForMostSerious(text)) {
          const ranked = buildMostSeriousResponse(context);
          issue = ranked.top;
          if (!issue) choices = issues.filter((item) => item.severity === issues[0].severity);
        } else {
          const { issue: chosen, stale } = selectedIssue(context, flow.get());
          if (stale) return staleIssueReply(context, resolution);
          issue = chosen ?? (issues.length === 1 ? issues[0] : null);
        }
        if (!issue) {
          // More than one issue fits: ask which, never guess.
          flow.update({ stage: "FIX", lastAction: "FIX", topic: "ISSUES", activeFindingCheckId: null });
          replyWith(buildFixListResponse(choices, true), "FIX");
          return answered;
        }
        guidedReply(context, issue, aspect, "FIX");
        return answered;
      }

      case "SUMMARY": {
        if (!available || resolution.state !== "READY" || !deps.explain) return null;
        flow.update({ stage: "REVIEW", lastAction: "SUMMARY", activeAssessmentId: context.latestAssessment?.id ?? null, topic: "RISK", shownIssues: [] });
        return explainWith({ intent: "SUMMARY" }, resolution, context, {
          card: contextResultCard(context),
          actions: [WORKFLOW_ACTIONS.reviewIssues, WORKFLOW_ACTIONS.explainRisk, WORKFLOW_ACTIONS.verifyAfterFixing],
          openButton: true,
        });
      }

      default:
        return null;
    }
  }

  async function runCheck(kind: WorkflowRunKind): Promise<void> {
    const flow = deps.workflow;
    if (!flow) return;
    if (deps.isReadOnly) {
      addReply({
        text: "Active vulnerability assessments are disabled in this cloud monitoring deployment. You can execute authorized security assessments through the local laboratory environment.",
      });
      return;
    }
    const label = kind === "VERIFY" ? WORKFLOW_ACTIONS.runVerification.label : WORKFLOW_ACTIONS.runCheck.label;
    if (flow.get().running || isReassessmentInFlight()) {
      addReply({ text: RUNNING_REPLY });
      return;
    }
    const baseline = deps.getContext()?.verificationBaseline ?? null;
    if (!baseline) {
      addReply({
        text: "I need a completed check of your authorized target before I can run one from here. You can use the check form instead.",
        actions: [WORKFLOW_ACTIONS.openCheckForm],
      });
      return;
    }
    deps.addMessage({ id: nextId(), role: "user", text: label, timestamp: now() });
    const fixing = kind === "VERIFY" ? flow.get().activeFindingCheckId : null;
    flow.update({ running: { kind, target: baseline.target }, stage: kind === "VERIFY" ? "VERIFY" : "CHECK" });

    const run = createReassessmentFlow({
      original: { id: baseline.assessmentId, target: baseline.target, status: "COMPLETE" },
      run: flow.runAssessment,
      onState: () => {},
    });
    run.request();
    await run.confirm();
    const state = run.getState();
    if ("created" in state) flow.onAssessmentCreated?.(state.created);
    // The result is kept by the app, so it is added even if the page was left.
    const result = runResultReply(kind, state, flow.get());
    const verdict =
      fixing && state.phase === "complete" ? await issueVerdict(state.beforeId, state.created, fixing) : null;
    flow.update(result.patch);
    if (verdict) {
      addReply({ ...verdict, intent: kind });
      return;
    }
    addReply({
      text: result.text,
      intent: kind,
      ...(result.card ? { card: result.card } : {}),
      ...(result.actions ? { actions: result.actions } : {}),
      ...(result.tone ? { tone: result.tone } : {}),
    });
  }

  /**
   * Whether the issue being fixed was observed in the verification check,
   * decided by the existing comparison engine; null when the previous check
   * can't be loaded or didn't report the issue (the general result is shown).
   */
  async function issueVerdict(beforeId: string, after: AssessmentDetail, checkId: string): Promise<Reply | null> {
    const flow = deps.workflow!;
    let before: AssessmentDetail;
    deps.setStatus(COMPARING_LABEL);
    try {
      before = await flow.loadAssessment(beforeId);
    } catch {
      return null;
    } finally {
      deps.setStatus(null);
    }
    const result = verifyIssue(before, after, checkId);
    if (!result) return null;
    const actions =
      result.status === "STILL_PRESENT"
        ? [guidedFixAction(checkId), WORKFLOW_ACTIONS.beforeAfter, WORKFLOW_ACTIONS.seeTechnical]
        : result.status === "NOT_COMPARABLE"
          ? [WORKFLOW_ACTIONS.openComparison]
          : [WORKFLOW_ACTIONS.beforeAfter, WORKFLOW_ACTIONS.reviewIssues];
    return { text: VERIFICATION_HEADLINE[result.status], card: { kind: "VERIFICATION", result }, actions };
  }

  function startGuidedFix(checkId: string): void {
    const flow = deps.workflow;
    if (!flow || closed || busy) return;
    const context = deps.getContext();
    const issue = context?.importantIssues?.find((item) => item.checkId === checkId) ?? null;
    if (!context || !issue || context.availability !== "ASSESSMENT_AVAILABLE") {
      flow.update({ activeFindingCheckId: null });
      addReply({ text: STALE_ISSUE_REPLY, suggestions: ["whats-wrong"] });
      return;
    }
    deps.addMessage({ id: nextId(), role: "user", text: `Show me how to fix “${issue.title}”`, timestamp: now() });
    guidedReply(context, issue, "STEPS", "FIX");
  }

  function declineVerification(): void {
    if (!deps.workflow || closed || busy) return;
    deps.addMessage({ id: nextId(), role: "user", text: WORKFLOW_ACTIONS.notYet.label, timestamp: now() });
    addReply({
      text: "No problem — nothing was started. When you're ready, choose “Check whether it's fixed”.",
      actions: [WORKFLOW_ACTIONS.checkFixed],
    });
  }

  function selectIssue(checkId: string): void {
    const flow = deps.workflow;
    if (!flow || closed || busy) return;
    const context = deps.getContext();
    const issue = context?.importantIssues?.find((item) => item.checkId === checkId) ?? null;
    if (!context || !issue) {
      flow.update({ activeFindingCheckId: null });
      addReply({ text: STALE_ISSUE_REPLY, suggestions: ["whats-wrong"] });
      return;
    }
    deps.addMessage({ id: nextId(), role: "user", text: issue.title, timestamp: now() });
    flow.update({
      activeFindingCheckId: issue.checkId,
      activeAssessmentId: context.latestAssessment?.id ?? null,
      stage: "REVIEW",
      topic: "ISSUE",
    });
    addReply({
      text: `You're looking at “${issue.title}”.`,
      card: issueCard(issue, false),
      actions: [WORKFLOW_ACTIONS.whyProblem, WORKFLOW_ACTIONS.howFix, WORKFLOW_ACTIONS.technicalDetails],
    });
  }

  /** Classified request -> resolution -> recorded facts, workflow step, explanation or fixed reply. */
  async function answer(intent: AssistantIntentResult, text: string): Promise<RequestOutcome> {
    let context = deps.getContext();
    let resolution = resolveAssistantIntent(intent, context);
    for (let poll = 0; poll < LOADING_MAX_POLLS && resolution.state === "LOADING"; poll++) {
      await wait(LOADING_POLL_MS);
      if (closed) return { status: "rejected", reason: "closed" };
      context = deps.getContext();
      resolution = resolveAssistantIntent(intent, context);
    }

    const factOutcome = await handleFacts(intent, resolution, context, text);
    if (factOutcome) return factOutcome;

    const workflowOutcome = await handleWorkflow(intent, resolution, context, text);
    if (workflowOutcome) return workflowOutcome;

    const explainRequest = deps.explain ? explainRequestFor(intent, resolution, context) : null;
    if (deps.explain && explainRequest) {
      deps.setStatus(EXPLAINING_LABEL);
      const response = await deps.explain(explainRequest);
      if (closed) return { status: "rejected", reason: "closed" };
      const explanation = explanationReply(response);
      deps.addMessage({
        id: nextId(),
        role: "assistant",
        text: explanation.text,
        timestamp: now(),
        intent: resolution.intent,
        ...(explanation.source ? { source: explanation.source, action: resolution.action } : {}),
        ...(explanation.basis ? { basis: explanation.basis } : {}),
        ...(explanation.suggestions ? { suggestions: explanation.suggestions } : {}),
        ...(explanation.tone ? { tone: explanation.tone } : {}),
      });
      return { status: "answered", resolution };
    }

    const reply = assistantReply(intent, resolution, context);
    deps.addMessage({
      id: nextId(),
      role: "assistant",
      text: reply.text,
      timestamp: now(),
      intent: resolution.intent,
      action: resolution.action,
      ...(reply.suggestions ? { suggestions: reply.suggestions } : {}),
    });

    if (resolution.destination) {
      deps.setStatus(openingLabel(resolution.action.type));
      await wait(OPEN_DELAY_MS);
      if (closed) return { status: "rejected", reason: "closed" };
      deps.navigate(resolution.destination);
    }
    return { status: "answered", resolution };
  }

  /** The request a follow-up stands for, answered exactly as if the user had typed it. */
  const answerAs = (request: string) => answer(classifyAssistantIntent(request), request);

  /**
   * A short follow-up, read against the issue under discussion and the topic
   * of the last answer. Without either it asks one short question instead of
   * guessing. Every answer is deterministic except "Tell me more", which uses
   * the existing explanation request for the same subject.
   */
  const ISSUES_INTENT = classifyAssistantIntent("what is wrong");
  const EVIDENCE_INTENT = classifyAssistantIntent("what evidence do you have");

  /**
   * The complete latest check a contextual question is about, or the reply
   * that says why there is none (still loading, no check, not complete).
   * With `issues` it also waits for the issue list of that check.
   */
  async function conversationReady(
    unclear: AssistantIntentResult,
    issues: boolean,
  ): Promise<{ context: AssistantContext } | { outcome: RequestOutcome }> {
    let context = deps.getContext();
    for (let poll = 0; poll < LOADING_MAX_POLLS && context === null; poll++) {
      await wait(LOADING_POLL_MS);
      if (closed) return { outcome: { status: "rejected", reason: "closed" } };
      context = deps.getContext();
    }
    const clarify = resolveAssistantIntent(unclear, context);
    if (!context) {
      addReply({ text: "I'm still loading your security checks. Please try again in a moment." });
      return { outcome: { status: "answered", resolution: clarify } };
    }
    if (context.availability !== "ASSESSMENT_AVAILABLE") {
      addReply({
        text:
          context.availability === "NO_ASSESSMENT"
            ? NO_CHECK_TO_EXPLAIN_REPLY
            : notCompleteReply(ISSUES_INTENT, context),
        suggestions: context.availability === "ASSESSMENT_RUNNING" ? ["summary"] : ["check"],
      });
      return { outcome: { status: "answered", resolution: clarify } };
    }
    if (!issues) return { context };
    const loaded = await waitForIssues(context);
    if (!loaded) return { outcome: { status: "rejected", reason: "closed" } };
    if (loaded.issueStatus !== "AVAILABLE") {
      addReply({ text: ISSUES_UNAVAILABLE_REPLY, tone: "error" });
      return { outcome: { status: "answered", resolution: resolveAssistantIntent(ISSUES_INTENT, loaded) } };
    }
    return { context: loaded };
  }

  /** Conversation context for reference resolution: the issues last shown and the one under discussion. */
  function conversationContext(context: AssistantContext): ConversationContext {
    const important = context.importantIssues ?? [];
    const byId = new Map(important.map((issue) => [issue.checkId, issue]));
    const state = deps.workflow!.get();
    return {
      shown: state.shownIssues.map((id) => byId.get(id)).filter((issue): issue is AssistantIssue => Boolean(issue)),
      selected: selectedIssue(context, state).issue,
      important,
    };
  }

  /**
   * A request that refers to issues by position, number, severity or
   * description ("What are these two?", "How do I fix the first one?").
   * The reference is bound to the issues the conversation last showed; what is
   * asked about them is answered from recorded values, or by the same request
   * about the chosen issue ("how do i fix it") through the normal pipeline.
   */
  async function handleReference(found: ResolvedReference, intent: AssistantIntentResult): Promise<RequestOutcome> {
    const flow = deps.workflow!;
    const ready = await conversationReady(intent, true);
    if ("outcome" in ready) return ready.outcome;
    const { context } = ready;
    const reference = bindReference(found.match, conversationContext(context));
    const assessmentId = context.latestAssessment?.id ?? null;
    const respond = (reply: FactAnswer, about: AssistantIntentResult = ISSUES_INTENT): RequestOutcome => {
      const resolution = resolveAssistantIntent(about, context);
      replyWith(reply, resolution.intent);
      return { status: "answered", resolution };
    };
    const focus = (chosen: AssistantIssue) =>
      flow.update({ activeFindingCheckId: chosen.checkId, activeAssessmentId: assessmentId, topic: "ISSUE", stage: "REVIEW" });
    const latestDetail = () => {
      const latest = deps.getLatestDetail?.() ?? null;
      return latest && latest.id === assessmentId ? latest : null;
    };
    const detailUnavailable = (): RequestOutcome => {
      addReply({ text: DETAIL_UNAVAILABLE_REPLY, tone: "error" });
      return { status: "answered", resolution: resolveAssistantIntent(EVIDENCE_INTENT, context) };
    };

    switch (reference.kind) {
      case "NONE": {
        const current = conversationContext(context);
        if (!current.important.length) return respond(buildIssueSummaryResponse(context));
        flow.update({ topic: "ISSUES" });
        return respond(buildNoMatchResponse(context, current.shown.length ? current.shown : current.important));
      }
      case "UNBOUND": {
        // The last answer was not an issue list: positions refer to what it showed, never to an older list.
        const topic = flow.get().topic;
        if (topic === "PORTS") {
          const detail = latestDetail();
          const choice = detail ? portChoiceAnswer(detail, "port") : null;
          if (choice) return respond(choice, classifyAssistantIntent("what ports are open"));
        }
        const positional = found.match.kind === "ORDINAL" || found.match.kind === "OTHER";
        if (positional && topic !== "PORTS" && topic !== "RISK" && (context.importantIssues?.length ?? 0) > 0) {
          flow.update({ topic: "ISSUES" });
          return respond(buildWhichIssueResponse(context));
        }
        flow.update({ topic: null });
        return respond(buildClarificationResponse("WHAT"), intent);
      }
      case "NO_SEVERITY":
        flow.update({ topic: "ISSUES" });
        return respond(buildNoSeverityResponse(context, reference.severity));
      case "AMBIGUOUS":
        flow.update({ topic: "ISSUES" });
        return respond(buildWhichIssueResponse({ ...context, importantIssues: reference.candidates }));
      case "ISSUE": {
        const { issue } = reference;
        focus(issue);
        switch (found.aspect) {
          case "FIX":
            return answerAs(ASPECT_REQUEST[fixAspect(intent.matchedPhrase)]);
          case "VERIFY":
            return answerAs("did i fix it");
          case "TECHNICAL":
          case "EVIDENCE": {
            const detail = latestDetail();
            if (!detail) return detailUnavailable();
            return respond(
              found.aspect === "TECHNICAL" ? issueTechnicalAnswer(detail, issue) : evidenceAnswer(detail, issue.checkId),
              EVIDENCE_INTENT,
            );
          }
          case "MOST_SERIOUS":
          case "SEVERITY":
            return respond(buildIssueExplanationResponse(issue, "SEVERITY"));
          default:
            return respond(buildIssueExplanationResponse(issue, found.aspect === "WHY" ? "WHY" : "MEANING"));
        }
      }
      case "ISSUES": {
        const { issues } = reference;
        flow.update({ topic: "ISSUES", activeFindingCheckId: null, activeAssessmentId: assessmentId, stage: "REVIEW" });
        switch (found.aspect) {
          case "MOST_SERIOUS": {
            const ranked = buildMostSeriousResponse({ ...context, importantIssues: issues });
            if (ranked.top) focus(ranked.top);
            return respond(ranked);
          }
          case "VERIFY":
            return answerAs("did i fix it");
          case "TECHNICAL":
          case "EVIDENCE": {
            const detail = latestDetail();
            if (!detail) return detailUnavailable();
            const evidence = evidenceAnswer(detail, issues.map((issue) => issue.checkId));
            return respond(found.aspect === "TECHNICAL" ? withTechnicalOpen(evidence) : evidence, EVIDENCE_INTENT);
          }
          default:
            return respond(buildIssueGroupResponse(issues, found.aspect));
        }
      }
    }
  }

  async function handleFollowUp(kind: FollowUpKind, unclear: AssistantIntentResult): Promise<RequestOutcome> {
    const flow = deps.workflow!;
    const ready = await conversationReady(unclear, kind !== "TOPIC");
    if ("outcome" in ready) return ready.outcome;
    const { context } = ready;
    const clarify = resolveAssistantIntent(unclear, context);
    const issuesIntent = ISSUES_INTENT;
    const respond = (reply: FactAnswer, about: AssistantIntentResult = issuesIntent): RequestOutcome => {
      const resolution = about === unclear ? clarify : resolveAssistantIntent(about, context);
      replyWith(reply, resolution.intent);
      return { status: "answered", resolution };
    };

    if (kind === "TOPIC") {
      flow.update({ topic: null });
      return respond(buildClarificationResponse("TOPIC"), unclear);
    }
    const issues = context.importantIssues ?? [];
    const state = flow.get();
    const selected = selectedIssue(context, state);
    let topic: ConversationTopic | null = state.topic;
    if (selected.stale && (topic === "ISSUE" || topic === null)) {
      return staleIssueReply(context, resolveAssistantIntent(issuesIntent, context));
    }
    let issue: AssistantIssue | null = selected.issue;
    if (topic === "ISSUE" && !issue) topic = null;
    if (topic === null && issue) topic = "ISSUE";
    if (topic === "ISSUES" && issues.length === 1) {
      topic = "ISSUE";
      issue = issues[0];
    }
    const assessmentId = context.latestAssessment?.id ?? null;
    const focus = (chosen: AssistantIssue) =>
      flow.update({ activeFindingCheckId: chosen.checkId, activeAssessmentId: assessmentId, topic: "ISSUE", stage: "REVIEW" });
    const detailOrNull = () => {
      const latest = deps.getLatestDetail?.() ?? null;
      return latest && latest.id === assessmentId ? latest : null;
    };

    if (kind === "MOST_SERIOUS") {
      const ranked = buildMostSeriousResponse(context);
      if (ranked.top) focus(ranked.top);
      else flow.update({ topic: "ISSUES" });
      return respond(ranked);
    }
    if (kind === "SERVICE_THERE") {
      return answerAs(state.topicPort !== null ? `what is running on port ${state.topicPort}` : "what services are running");
    }
    if (kind === "TECHNICAL_DETAILS") {
      const detail = detailOrNull();
      if (!detail) {
        addReply({ text: DETAIL_UNAVAILABLE_REPLY, tone: "error" });
        return { status: "answered", resolution: resolveAssistantIntent(issuesIntent, context) };
      }
      const evidenceIntent = classifyAssistantIntent("what evidence do you have");
      switch (topic) {
        case "ISSUE":
          return respond(issueTechnicalAnswer(detail, issue!), evidenceIntent);
        case "RISK":
          return respond(withTechnicalOpen(riskFactorsAnswer(detail)), classifyAssistantIntent("why is my risk high"));
        case "PORTS":
          return respond(withTechnicalOpen(portsAnswer(detail, state.topicPort)), classifyAssistantIntent("what ports are open"));
        default:
          return respond(withTechnicalOpen(evidenceAnswer(detail, null)), evidenceIntent);
      }
    }

    switch (topic) {
      case "ISSUE":
        focus(issue!);
        switch (kind) {
          case "HOW":
            return answerAs("how do i fix it");
          case "MORE":
            return answerAs("why is this risky");
          default:
            return respond(buildIssueExplanationResponse(issue!, kind === "MEANING" ? "MEANING" : kind === "WHY" ? "WHY" : "SEVERITY"));
        }
      case "ISSUES":
        if (kind === "HOW") return answerAs("how do i fix it");
        return respond(buildWhichIssueResponse(context));
      case "RISK":
        switch (kind) {
          case "HOW":
            return answerAs("how do i fix it");
          case "MORE":
            return answerAs("explain my risk");
          case "SEVERITY":
            return answerAs("is my network safe");
          default:
            return answerAs("why is my risk high");
        }
      case "PORTS":
        switch (kind) {
          case "HOW":
            return answerAs("how do i fix it");
          case "MEANING":
          case "MORE": {
            if (state.topicPort !== null) return answerAs(`what is running on port ${state.topicPort}`);
            const detail = detailOrNull();
            const ports = detail ? recordedOpenPorts(detail) : null;
            if (ports?.length === 1) return answerAs(`what is running on port ${ports[0].port}`);
            const choice = detail ? portChoiceAnswer(detail, "service") : null;
            return choice ? respond(choice, classifyAssistantIntent("what services are running")) : answerAs("what services are running");
          }
          default:
            return respond(buildPortIssuesResponse(context, state.topicPort), classifyAssistantIntent("what ports are open"));
        }
      default:
        flow.update({ topic: null });
        return respond(buildClarificationResponse("WHAT"), unclear);
    }
  }

  async function handleAssistantRequest(text: string): Promise<RequestOutcome> {
    if (closed) return { status: "rejected", reason: "closed" };
    const trimmed = text.trim();
    if (!trimmed) return { status: "rejected", reason: "empty" };
    if (busy) return { status: "rejected", reason: "busy" };

    busy = true;
    deps.setStatus(PROCESSING_LABEL);
    try {
      const intent = classifyAssistantIntent(trimmed);
      deps.addMessage({
        id: nextId(),
        role: "user",
        text: redactSecrets(trimmed),
        timestamp: now(),
        intent: intent.intent,
      });

      await wait(PROCESSING_MS);
      if (closed) return { status: "rejected", reason: "closed" };

      // "These two", "the first one", "the HIGH one": bound to the issues last shown.
      const reference = deps.workflow && mayRefer(intent) ? resolveReferenceRequest(trimmed) : null;
      if (reference) return await handleReference(reference, intent);

      // A short follow-up ("Why?", "What is this?") only when nothing else matched.
      const followUp =
        deps.workflow && intent.intent === "UNKNOWN" && intent.reason === NO_PHRASE_REASON
          ? classifyFollowUp(trimmed)
          : null;
      if (followUp) return await handleFollowUp(followUp, intent);
      return await answer(intent, trimmed);
    } catch (error) {
      if (!closed) {
        deps.addMessage({
          id: nextId(),
          role: "assistant",
          text: errorReply(error),
          timestamp: now(),
          tone: "error",
        });
      }
      return { status: "failed" };
    } finally {
      busy = false;
      if (!closed) deps.setStatus(null);
    }
  }

  return {
    handleAssistantRequest,
    isBusy: () => busy,
    openAction: (action) => {
      const destination = actionDestination(action);
      if (!closed && !busy && destination) deps.navigate(destination);
    },
    runCheck,
    selectIssue,
    startGuidedFix,
    declineVerification,
    openWorkflowAction: (id) => {
      if (closed || busy || !deps.workflow) return;
      const { baselineAssessmentId: beforeId, latestAssessmentId: afterId } = deps.workflow.get();
      const destination = workflowDestination(id, beforeId && afterId ? { beforeId, afterId } : null);
      if (destination) deps.navigate(destination);
    },
    close: () => {
      closed = true;
    },
  };
}
