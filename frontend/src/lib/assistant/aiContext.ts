/**
 * The facts a future AI explanation may use, derived from AssistantContext
 * only. No IDs, ports, evidence, raw backend JSON or device telemetry.
 * Nothing here calls a model.
 */
import type { AssessmentStatus } from "../../api/types";
import type { AssessmentAvailability, AssistantContext } from "./context";

export const ASSISTANT_AI_CONTRACT = "assistant-context/v1";

export const ASSISTANT_AI_RULES: readonly string[] = [
  "Use only the supplied assessment facts.",
  "Do not invent CVEs.",
  "Do not invent vulnerabilities.",
  "Do not invent devices or services.",
  "Do not calculate a new risk score.",
  "Do not claim the target is secure.",
  "Do not claim remediation is complete unless verification data says so.",
  "State when information is unavailable.",
];

export type AssistantAIIssue = {
  severity: string;
  title: string;
  meaning: string | null;
  remediation: string | null;
  occurrences: number;
};

export type AssistantAIContext = {
  contract: typeof ASSISTANT_AI_CONTRACT;
  rules: string[];
  availability: AssessmentAvailability;
  scope: { target: string } | null;
  assessment: {
    status: AssessmentStatus;
    startedAt: string | null;
    completedAt: string | null;
  } | null;
  risk: { level: string | null; score: number | null } | null;
  /** Important issues; null when they are not known (never "none" by default). */
  issues: AssistantAIIssue[] | null;
  issueCounts: {
    importantIssues: number;
    minorIssues: number;
    informationalFindings: number;
  } | null;
  lastError: string | null;
  limitations: string[];
};

export function buildAssistantAIContext(context: AssistantContext): AssistantAIContext {
  const latest = context.latestAssessment;
  return {
    contract: ASSISTANT_AI_CONTRACT,
    rules: [...ASSISTANT_AI_RULES],
    availability: context.availability,
    scope: context.scope ? { target: context.scope.authorizedTarget } : null,
    assessment: latest
      ? { status: latest.status, startedAt: latest.startedAt, completedAt: latest.completedAt }
      : null,
    risk: context.risk ? { level: context.risk.level, score: context.risk.score } : null,
    issues: context.importantIssues
      ? context.importantIssues.map((issue) => ({
          severity: issue.severity,
          title: issue.title,
          meaning: issue.meaning,
          remediation: issue.remediation,
          occurrences: issue.occurrenceCount,
        }))
      : null,
    issueCounts: context.issueCounts ? { ...context.issueCounts } : null,
    lastError: context.lastError,
    limitations: [...context.limitations],
  };
}
