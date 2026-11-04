/**
 * UX-3C workflow state and the deterministic content the assistant shows
 * between steps (check results, issue lists, comparisons). Everything here is
 * built from backend records through the existing helpers: summarizeIssues for
 * issues, overallSnapshot for risk and compareAssessments for BEFORE/AFTER.
 * Nothing here runs a check, calls a model or decides whether an issue is fixed.
 */
import type { AssessmentDetail, AssessmentFinding } from "../../api/types";
import type { ReassessmentState } from "../../components/assessments/reassessment";
import { compareAssessments, overallSnapshot } from "../assessmentComparison";
import { countFindings, pluralize, summarizeIssues, type FindingCounts } from "../securityHome";
import type { AssistantContext, AssistantIssue } from "./context";
import type { GuidedRemediation, IssueVerification } from "./guidedFix";

export type WorkflowStage = "IDLE" | "CHECK" | "REVIEW" | "EXPLAIN" | "FIX" | "VERIFY" | "COMPARE";

export type WorkflowLastAction = "CHECK" | "EXPLAIN" | "FIX" | "VERIFY" | "SUMMARY" | null;

export type WorkflowRunKind = "CHECK" | "VERIFY";

/** What the last answer was about; short follow-ups ("Why?") refer to it. */
export type ConversationTopic = "ISSUE" | "ISSUES" | "RISK" | "PORTS";

/** Frontend-only; never persisted or sent to the backend. */
export type AssistantWorkflowState = {
  /** Assessment the conversation is currently about. */
  activeAssessmentId: string | null;
  /** Catalog check ID of the issue being discussed. */
  activeFindingCheckId: string | null;
  topic: ConversationTopic | null;
  /** Port the last ports or services answer was about, if one was named. */
  topicPort: number | null;
  /** Check IDs of the issues the last issue list showed, in display order ("these two", "the first one"). */
  shownIssues: string[];
  /** BEFORE side of the last check run from the assistant. */
  baselineAssessmentId: string | null;
  /** AFTER side of that run; set only when the new check is COMPLETE. */
  latestAssessmentId: string | null;
  stage: WorkflowStage;
  lastAction: WorkflowLastAction;
  /** A check started by an explicit click and not finished yet. */
  running: { kind: WorkflowRunKind; target: string } | null;
};

export const INITIAL_WORKFLOW_STATE: AssistantWorkflowState = {
  activeAssessmentId: null,
  activeFindingCheckId: null,
  topic: null,
  topicPort: null,
  shownIssues: [],
  baselineAssessmentId: null,
  latestAssessmentId: null,
  stage: "IDLE",
  lastAction: null,
  running: null,
};

export type WorkflowActionId =
  | "run-check"
  | "run-verification"
  | "open-check-form"
  | "review-issues"
  | "technical-details"
  | "open-comparison"
  | "select-issue"
  | "guided-fix"
  | "not-yet"
  | "ask";

/**
 * A button under an assistant message. "ask" sends its label through the
 * classifier like typed text; run-* are the only actions that start a check.
 * "guided-fix" opens the guided fix of `checkId`; "not-yet" declines a
 * verification check without starting anything.
 */
export type AssistantActionButton = {
  id: WorkflowActionId;
  label: string;
  checkId?: string;
  primary?: boolean;
};

const ask = (label: string, primary = false): AssistantActionButton => ({ id: "ask", label, primary });

export const WORKFLOW_ACTIONS = {
  runCheck: { id: "run-check", label: "Run security check", primary: true },
  runVerification: { id: "run-verification", label: "Run verification check", primary: true },
  openCheckForm: { id: "open-check-form", label: "Open check form" },
  reviewIssues: { id: "review-issues", label: "Review issues" },
  technicalDetails: { id: "technical-details", label: "Technical details" },
  viewAllFindings: { id: "technical-details", label: "View all findings" },
  openComparison: { id: "open-comparison", label: "Open full comparison" },
  explainRisk: ask("Explain my risk"),
  summarize: ask("Summarize results"),
  summarizeNewCheck: ask("Summarize the new check"),
  whyRisky: ask("Why is this risky?"),
  howFix: ask("How do I fix it?"),
  fixedIt: ask("I fixed it"),
  checkAgain: ask("Check again"),
  verifyAfterFixing: ask("Verify after fixing"),
  seeChanges: ask("See what changed", true),
  whyRiskHigh: ask("Why is my risk high?"),
  riskContributors: ask("What contributes to my risk?"),
  openPorts: ask("What ports are open?"),
  services: ask("What services are running?"),
  evidence: ask("What evidence do you have?"),
  whyProblem: ask("Why is this a problem?"),
  tellMore: ask("Tell me more"),
  seeTechnical: ask("See technical details"),
  mostSerious: ask("Which one is most serious?"),
  securityIssues: ask("Security issues"),
  riskScore: ask("Risk score"),
  portsShort: ask("Open ports"),
  fixThem: ask("How do I fix them?"),
  whyTheyMatter: ask("Why do they matter?"),
  completedFix: ask("I've completed the fix", true),
  checkFixed: ask("Check whether it's fixed"),
  explainWhy: ask("Explain why this matters"),
  showSteps: ask("Show me how to fix it"),
  whatAffect: ask("What might this affect?"),
  howKnowFixed: ask("How do I know it's fixed?"),
  beforeAfter: ask("View before & after", true),
  notYet: { id: "not-yet", label: "Not yet" },
} as const satisfies Record<string, AssistantActionButton>;

export const guidedFixAction = (checkId: string, label = "View guided fix"): AssistantActionButton => ({
  id: "guided-fix",
  label,
  checkId,
});

/** Issue lists show at most this many issues at first. */
export const MAX_LISTED_ISSUES = 3;

/** Navigation-only actions; they may be used while an explanation is loading. */
export const NAVIGATION_ACTIONS: readonly WorkflowActionId[] = [
  "open-check-form",
  "review-issues",
  "technical-details",
  "open-comparison",
];

export type CardIssue = {
  checkId: string;
  title: string;
  severity: string;
  /** One plain-language line under the title, shown in issue lists. */
  summary?: string;
};

export type RiskPoint = { score: number; level: string };

/** One recorded fact in plain words, e.g. a port and the service found on it. */
export type FactItem = { title: string; detail: string | null };

export type AssistantCard =
  | {
      kind: "RESULT";
      /** The check this result is about; "View all findings" opens it only while it is the latest. */
      assessmentId: string | null;
      riskLevel: string | null;
      riskScore: number | null;
      importantIssues: number | null;
      issues: CardIssue[];
      /** Every recorded finding by severity; null when the findings aren't known. */
      findings: FindingCounts | null;
    }
  | {
      kind: "ISSUES";
      issues: CardIssue[];
      minorIssues: number;
      /** LOW and INFO findings of the check; null when not known. */
      additionalFindings: number | null;
    }
  | {
      kind: "ISSUE";
      issue: CardIssue;
      meaning: string | null;
      /** Backend remediation, shown only on fix replies. */
      remediation: string | null;
      next: string | null;
    }
  | {
      kind: "FACTS";
      items: FactItem[];
      /** Recorded identifiers and raw values, shown only when the user expands them. */
      technical: string[];
      /** Shown open because the user asked for the technical details. */
      expanded?: boolean;
    }
  | {
      kind: "COMPARISON";
      before: RiskPoint | null;
      after: RiskPoint | null;
      /** AFTER - BEFORE from compareRisk; null when not comparable. */
      delta: number | null;
      /** Recorded findings by severity in each check. */
      counts: { before: FindingCounts; after: FindingCounts };
      resolved: CardIssue[];
      added: CardIssue[];
      remaining: CardIssue[];
      notRechecked: CardIssue[];
    }
  /** Guided fix of one issue; built from the recorded fix only. */
  | { kind: "GUIDED_FIX"; guide: GuidedRemediation }
  /** "How do I fix both?": one guided fix per issue, chosen by the user. */
  | { kind: "FIX_LIST"; issues: CardIssue[]; startWith: string | null }
  /** Result of a verification check for the issue being fixed, from the comparison engine. */
  | { kind: "VERIFICATION"; result: IssueVerification };

const toCardIssue = (issue: Pick<AssistantIssue, "checkId" | "title" | "severity">): CardIssue => ({
  checkId: issue.checkId,
  title: issue.title,
  severity: issue.severity,
});

/** Risk and important issues of the latest COMPLETE check, as the context holds them. */
export function contextResultCard(context: AssistantContext): AssistantCard {
  return {
    kind: "RESULT",
    assessmentId: context.latestAssessment?.id ?? null,
    riskLevel: context.risk?.level ?? null,
    riskScore: context.risk?.score ?? null,
    importantIssues: context.issueCounts?.importantIssues ?? null,
    issues: (context.importantIssues ?? []).map(toCardIssue),
    findings: context.findingCounts,
  };
}

/** Result of a check just created: overall snapshot and grouped important issues. */
export function createdResultCard(created: AssessmentDetail): AssistantCard {
  const snapshot = overallSnapshot(created);
  const important = summarizeIssues(created).important;
  return {
    kind: "RESULT",
    assessmentId: created.id,
    riskLevel: snapshot?.risk_level ?? created.highest_risk_level ?? null,
    riskScore: snapshot?.score ?? created.highest_risk ?? null,
    importantIssues: important.length,
    issues: important.map(toCardIssue),
    findings: countFindings(created.findings),
  };
}

/** The most important issues first (at most MAX_LISTED_ISSUES), each with its one-line meaning. */
export function issuesCard(context: AssistantContext): AssistantCard {
  return {
    kind: "ISSUES",
    issues: (context.importantIssues ?? []).slice(0, MAX_LISTED_ISSUES).map((issue) => ({
      ...toCardIssue(issue),
      ...(issue.meaning ? { summary: issue.meaning } : {}),
    })),
    minorIssues: context.issueCounts?.minorIssues ?? 0,
    additionalFindings: context.findingCounts?.additional ?? null,
  };
}

export function issueCard(issue: AssistantIssue, withRemediation: boolean): AssistantCard {
  return {
    kind: "ISSUE",
    issue: toCardIssue(issue),
    meaning: issue.meaning,
    remediation: withRemediation ? issue.remediation : null,
    next: withRemediation
      ? "After applying the fix, choose “I fixed it” to verify it with a new check."
      : "Ask how to fix it, or open the technical details.",
  };
}

/** The issue under discussion if it is still among the latest check's important issues. */
export function selectedIssue(
  context: AssistantContext | null,
  workflow: AssistantWorkflowState,
): { issue: AssistantIssue | null; stale: boolean } {
  const id = workflow.activeFindingCheckId;
  if (!id || !context || context.issueStatus !== "AVAILABLE") return { issue: null, stale: false };
  const issue = context.importantIssues?.find((item) => item.checkId === id) ?? null;
  return { issue, stale: issue === null };
}

/** Same display title and grouping as the Security page; null for informational findings. */
function displayIssue(finding: AssessmentFinding): CardIssue | null {
  const summary = summarizeIssues({ findings: [finding], risk_snapshots: [] });
  const issue = summary.important[0] ?? summary.minor[0];
  return issue ? toCardIssue(issue) : null;
}

function uniqueIssues(findings: AssessmentFinding[]): CardIssue[] {
  const seen = new Map<string, CardIssue>();
  for (const finding of findings) {
    const issue = displayIssue(finding);
    if (issue) seen.set(`${issue.checkId}|${issue.severity}`, issue);
  }
  return [...seen.values()];
}

export type ComparisonSummary =
  | { comparable: true; card: AssistantCard; text: string }
  | { comparable: false; text: string };

/** Deterministic BEFORE/AFTER summary from the existing comparison engine. */
export function comparisonSummary(before: AssessmentDetail, after: AssessmentDetail): ComparisonSummary {
  const result = compareAssessments(before, after);
  if (!result.comparable || !result.findings) {
    return {
      comparable: false,
      text: "These two checks can't be compared directly because they weren't run the same way. The full comparison shows why.",
    };
  }
  const point = (snapshot: typeof result.risk.before): RiskPoint | null =>
    snapshot ? { score: snapshot.score, level: snapshot.risk_level } : null;
  const card: AssistantCard = {
    kind: "COMPARISON",
    before: point(result.risk.before),
    after: point(result.risk.after),
    delta: result.risk.delta,
    counts: { before: countFindings(before.findings), after: countFindings(after.findings) },
    resolved: uniqueIssues(result.findings.resolved.map((item) => item.before)),
    added: uniqueIssues(result.findings.added.map((item) => item.after)),
    remaining: uniqueIssues(result.findings.remaining.map((item) => item.after)),
    notRechecked: uniqueIssues(result.findings.unconfirmed.map((item) => item.before)),
  };
  const delta = result.risk.delta;
  const direction =
    delta === null
      ? "The risk scores can't be compared."
      : delta < 0
        ? "Your risk score went down."
        : delta > 0
          ? "Your risk score went up."
          : "Your risk score didn't change.";
  return { comparable: true, card, text: `Here's what changed since your previous check. ${direction}` };
}

export type RunReply = {
  text: string;
  card?: AssistantCard;
  actions?: AssistantActionButton[];
  tone?: "error";
  patch: Partial<AssistantWorkflowState>;
};

/** Message and workflow update after an explicitly started check finishes. */
export function runResultReply(
  kind: WorkflowRunKind,
  state: ReassessmentState,
  workflow: AssistantWorkflowState,
): RunReply {
  const done: Partial<AssistantWorkflowState> = { running: null, lastAction: kind };
  switch (state.phase) {
    case "complete": {
      const card = createdResultCard(state.created);
      const stillOpen =
        card.kind === "RESULT" && card.issues.some((issue) => issue.checkId === workflow.activeFindingCheckId);
      return {
        text: kind === "VERIFY" ? "Your verification check is complete." : "Security check complete.",
        card,
        actions:
          kind === "VERIFY"
            ? [WORKFLOW_ACTIONS.seeChanges, WORKFLOW_ACTIONS.reviewIssues, WORKFLOW_ACTIONS.summarize]
            : [WORKFLOW_ACTIONS.reviewIssues, WORKFLOW_ACTIONS.explainRisk, WORKFLOW_ACTIONS.summarize],
        patch: {
          ...done,
          activeAssessmentId: state.afterId,
          baselineAssessmentId: state.beforeId,
          latestAssessmentId: state.afterId,
          activeFindingCheckId: stillOpen ? workflow.activeFindingCheckId : null,
          stage: kind === "VERIFY" ? "COMPARE" : "REVIEW",
        },
      };
    }
    case "not_complete":
    case "failed":
      return {
        text:
          state.phase === "failed"
            ? "The new security check failed, so it has no result to show or compare."
            : "The new security check did not complete, so it has no current result to show or compare.",
        actions: [WORKFLOW_ACTIONS.summarize],
        patch: { ...done, latestAssessmentId: null, stage: "CHECK" },
      };
    case "blocked":
      return {
        text: "A security check is already running. I'll show the result when it finishes.",
        patch: { running: null },
      };
    case "error":
      return {
        text:
          state.httpStatus !== null && state.httpStatus < 500
            ? "The security check wasn't started. Only authorized targets can be checked."
            : "The security check couldn't be started. You can try again.",
        tone: "error",
        actions: [WORKFLOW_ACTIONS.openCheckForm],
        patch: { ...done, stage: "CHECK" },
      };
    default:
      return {
        text: "The security check couldn't be started. You can try again.",
        tone: "error",
        patch: { ...done },
      };
  }
}

function joinParts(parts: readonly string[]): string {
  return parts.length <= 1 ? parts.join("") : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}

/** "1 HIGH and 1 MEDIUM" / "2 LOW and 3 INFO"; only the severities that were recorded. */
export function severityBreakdown(counts: FindingCounts, group: "important" | "additional"): string {
  const parts: [number, string][] =
    group === "important"
      ? [[counts.critical, "CRITICAL"], [counts.high, "HIGH"], [counts.medium, "MEDIUM"]]
      : [[counts.low, "LOW"], [counts.info, "INFO"]];
  return joinParts(parts.filter(([n]) => n > 0).map(([n, label]) => `${n} ${label}`));
}

/** "LOW or informational", "LOW" or "informational", from the recorded lower severities. */
export function lowerSeverityKinds(counts: FindingCounts): string {
  if (counts.low && counts.info) return "LOW or informational";
  return counts.low ? "LOW" : "informational";
}

/** Important findings, naming the distinct issues when one check was recorded more than once. */
function importantPhrase(counts: FindingCounts, issues: number | null): string {
  if (issues === null || issues === counts.important) return pluralize(counts.important, "important issue");
  return `${pluralize(counts.important, "important finding")} (${pluralize(issues, "distinct issue")})`;
}

/** "I found 7 findings in your latest check: 2 important issues and 5 additional lower-severity findings." */
export function findingsOverviewText(counts: FindingCounts, importantIssues: number | null): string {
  const total = pluralize(counts.total, "finding");
  if (counts.total === 0) return "Your latest check recorded no findings.";
  if (counts.important === 0) {
    return `I found ${total} in your latest check. No high-priority issues were found — ${
      counts.total === 1 ? "it is" : "all are"
    } ${lowerSeverityKinds(counts)} (${severityBreakdown(counts, "additional")}).`;
  }
  if (counts.additional === 0) {
    return `I found ${total} in your latest check: ${importantPhrase(counts, importantIssues)}. No additional lower-severity findings.`;
  }
  return `I found ${total} in your latest check: ${importantPhrase(counts, importantIssues)} and ${pluralize(
    counts.additional,
    "additional lower-severity finding",
  )}.`;
}

/** "How many issues?" / "Are there only two vulnerabilities?": totals by group, from the recorded findings. */
export function findingCountLines(counts: FindingCounts, importantIssues: number | null): string[] {
  if (counts.total === 0) {
    return ["Your latest check recorded no findings.", "That covers only the checks run on your authorized target."];
  }
  return [
    `Your latest check produced ${pluralize(counts.total, "finding")} in total:`,
    counts.important
      ? `• ${importantPhrase(counts, importantIssues)} (${severityBreakdown(counts, "important")})`
      : "• No high-priority issues were found",
    counts.additional
      ? `• ${pluralize(counts.additional, "additional lower-severity finding")} (${severityBreakdown(counts, "additional")})`
      : "• No additional lower-severity findings",
  ];
}

export function issueCountText(context: AssistantContext): string {
  const important = context.issueCounts?.importantIssues ?? 0;
  const counts = context.findingCounts;
  if (counts) {
    const overview = findingsOverviewText(counts, context.issueCounts?.importantIssues ?? null);
    if (important === 0) {
      return counts.total ? overview : `${overview}\nThat covers only the checks run on your authorized target.`;
    }
    const choose =
      important === 1
        ? "Choose the important issue to see why it matters and how to fix it."
        : important > MAX_LISTED_ISSUES
          ? `Showing the most important ${MAX_LISTED_ISSUES} first — choose one to see why it matters and how to fix it.`
          : "Choose an important issue to see why it matters and how to fix it.";
    return `${overview}\n${choose}`;
  }
  if (important === 0) {
    const minor = context.issueCounts?.minorIssues ?? 0;
    return minor
      ? `Your latest check found no important security issues. It recorded ${pluralize(minor, "minor issue")}.`
      : "Your latest check found no important security issues. There's nothing important to fix right now.";
  }
  if (important === 1) {
    return "Your latest check found 1 important security issue. Choose it to see why it matters and how to fix it.";
  }
  return important > MAX_LISTED_ISSUES
    ? `Your latest check found ${important} important security issues. Showing the most important ${MAX_LISTED_ISSUES} first — choose one to see why it matters and how to fix it.`
    : `Your latest check found ${important} important security issues. Choose one to see why it matters and how to fix it.`;
}
