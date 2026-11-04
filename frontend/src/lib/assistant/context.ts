/**
 * The assistant's view of the security state, built only from assessment
 * records (GET /assessments and GET /assessments/{id}). Values are copied as
 * returned; anything the backend did not provide stays null. Evidence,
 * metadata and per-finding details beyond the simple issue are not included.
 */
import type {
  AssessmentDetail,
  AssessmentRiskLevel,
  AssessmentStatus,
  AssessmentSummary,
} from "../../api/types";
import { countFindings, selectLatestAssessment, summarizeIssues, type FindingCounts } from "../securityHome";
import { redactRuntimeText, redactSecrets } from "./redact";

export type AssessmentAvailability =
  | "NO_ASSESSMENT"
  | "ASSESSMENT_AVAILABLE"
  | "ASSESSMENT_INCOMPLETE"
  | "ASSESSMENT_FAILED"
  | "ASSESSMENT_RUNNING";

export type AssistantAssessment = {
  id: string;
  target: string;
  status: AssessmentStatus;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string | null;
  findingCount: number | null;
};

export type AssistantIssue = {
  checkId: string;
  severity: string;
  title: string;
  /** Plain-language meaning from the UX-1 mapping; null for unmapped checks. */
  meaning: string | null;
  remediation: string | null;
  /** Ports recorded on the findings; empty when none was recorded. */
  ports: number[];
  occurrenceCount: number;
};

/** Whether the latest complete assessment's issues are known. */
export type IssueStatus = "AVAILABLE" | "LOADING" | "UNAVAILABLE" | "NOT_APPLICABLE";

export type AssistantRisk = {
  score: number | null;
  level: AssessmentRiskLevel | null;
};

export type AssistantCapabilities = {
  canCheck: boolean;
  canExplain: boolean;
  canFix: boolean;
  canVerify: boolean;
  canSummarize: boolean;
};

export type AssistantContext = {
  availability: AssessmentAvailability;
  latestAssessment: AssistantAssessment | null;
  issueStatus: IssueStatus;
  /** Important (CRITICAL/HIGH/MEDIUM) issues; null while not known. */
  importantIssues: AssistantIssue[] | null;
  issueCounts: {
    importantIssues: number;
    minorIssues: number;
    informationalFindings: number;
  } | null;
  /** Every recorded finding of the latest complete check by severity; null while not known. */
  findingCounts: FindingCounts | null;
  /** Overall risk of the latest assessment, only when it is COMPLETE. */
  risk: AssistantRisk | null;
  lastError: string | null;
  scope: {
    authorizedTarget: string;
    environment?: {
      devices: { deviceId: string; ip: string }[];
      infrastructure?: { assetId: string; ip: string; assetType: string }[];
      assetsCount?: number;
    };
  } | null;
  /** Latest COMPLETE assessment, the BEFORE side of a verification. */
  verificationBaseline: {
    assessmentId: string;
    target: string;
    completedAt: string | null;
  } | null;
  capabilities: AssistantCapabilities;
  limitations: string[];
};

/** Load state of GET /assessments/{id} for the latest COMPLETE assessment. */
export type LatestDetailState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; detail: Pick<AssessmentDetail, "id" | "findings" | "risk_snapshots"> };

const NO_ISSUE_FACTS = { importantIssues: null, issueCounts: null, findingCounts: null } as const;

export const CONTEXT_LIMITATIONS = {
  noAssessment: "No security check has been run, so there are no results to describe.",
  incomplete:
    "The latest security check only partially completed, so it has no current risk rating.",
  failed: "The latest security check failed, so it has no current risk rating or results.",
  running: "The latest security check has not finished, so its results are not available yet.",
  noRisk: "No overall risk was recorded for the latest check.",
  noRiskLevel: "The overall risk level was not recorded for the latest check.",
  noRiskScore: "The overall risk score was not recorded for the latest check.",
  issuesLoading: "Issue details for the latest check are still loading.",
  issuesUnavailable: "Issue details for the latest check could not be loaded.",
  scopeOnly:
    "Results cover only the checks configured for the authorized target; other devices and services were not assessed.",
  noEvidence: "Technical evidence is not included.",
  verification:
    "Whether an issue has been fixed is known only after a new check is compared with this one.",
} as const;

const AVAILABILITY: Record<AssessmentStatus, AssessmentAvailability> = {
  COMPLETE: "ASSESSMENT_AVAILABLE",
  INCOMPLETE: "ASSESSMENT_INCOMPLETE",
  FAILED: "ASSESSMENT_FAILED",
  RUNNING: "ASSESSMENT_RUNNING",
};

function text(value: string | null | undefined): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function count(value: number | null | undefined): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function toAssessment(item: AssessmentSummary): AssistantAssessment {
  return {
    id: item.id,
    target: item.target,
    status: item.status,
    startedAt: text(item.started_at),
    completedAt: text(item.completed_at),
    createdAt: text(item.created_at),
    findingCount: count(item.finding_count),
  };
}

export function latestCompleteAssessment(
  items: readonly AssessmentSummary[],
): AssessmentSummary | null {
  return selectLatestAssessment(items.filter((item) => item.status === "COMPLETE"));
}

type IssueFacts = Pick<AssistantContext, "issueStatus" | "importantIssues" | "issueCounts" | "findingCounts">;

function issueFacts(latestId: string, detail: LatestDetailState | null): IssueFacts {
  if (detail?.status === "error") {
    return { issueStatus: "UNAVAILABLE", ...NO_ISSUE_FACTS };
  }
  if (detail?.status !== "ready" || detail.detail.id !== latestId) {
    return { issueStatus: "LOADING", ...NO_ISSUE_FACTS };
  }
  const summary = summarizeIssues(detail.detail);
  return {
    issueStatus: "AVAILABLE",
    importantIssues: summary.important.map((issue) => ({
      checkId: issue.checkId,
      severity: issue.severity,
      title: redactSecrets(issue.title),
      meaning: issue.summary,
      remediation: issue.remediation === null ? null : redactSecrets(issue.remediation),
      ports: [...issue.ports],
      occurrenceCount: issue.occurrences,
    })),
    issueCounts: {
      importantIssues: summary.important.length,
      minorIssues: summary.minor.length,
      informationalFindings: summary.observationCount,
    },
    findingCounts: countFindings(detail.detail.findings),
  };
}

function riskOf(item: AssessmentSummary): AssistantRisk | null {
  const score = count(item.highest_risk);
  const level = item.highest_risk_level ?? null;
  return score === null && level === null ? null : { score, level };
}

/**
 * @param assessments  GET /assessments as returned.
 * @param latestDetail GET /assessments/{id} for the latest assessment when it is COMPLETE.
 */
export function buildAssistantContext(
  assessments: readonly AssessmentSummary[],
  latestDetail: LatestDetailState | null = null,
): AssistantContext {
  const latest = selectLatestAssessment(assessments);
  const baseline = latestCompleteAssessment(assessments);
  const verificationBaseline = baseline
    ? {
        assessmentId: baseline.id,
        target: baseline.target,
        completedAt: text(baseline.completed_at),
      }
    : null;

  if (!latest) {
    return {
      availability: "NO_ASSESSMENT",
      latestAssessment: null,
      issueStatus: "NOT_APPLICABLE",
      ...NO_ISSUE_FACTS,
      risk: null,
      lastError: null,
      scope: null,
      verificationBaseline: null,
      capabilities: {
        canCheck: true,
        canExplain: false,
        canFix: false,
        canVerify: false,
        canSummarize: false,
      },
      limitations: [CONTEXT_LIMITATIONS.noAssessment],
    };
  }

  const availability = AVAILABILITY[latest.status] ?? "ASSESSMENT_RUNNING";
  const complete = availability === "ASSESSMENT_AVAILABLE";
  const issues: IssueFacts = complete
    ? issueFacts(latest.id, latestDetail)
    : { issueStatus: "NOT_APPLICABLE", ...NO_ISSUE_FACTS };
  const risk = complete ? riskOf(latest) : null;
  const errorText =
    availability === "ASSESSMENT_INCOMPLETE" || availability === "ASSESSMENT_FAILED"
      ? text(latest.error_summary)
      : null;

  const limitations: string[] = [];
  if (availability === "ASSESSMENT_INCOMPLETE") limitations.push(CONTEXT_LIMITATIONS.incomplete);
  if (availability === "ASSESSMENT_FAILED") limitations.push(CONTEXT_LIMITATIONS.failed);
  if (availability === "ASSESSMENT_RUNNING") limitations.push(CONTEXT_LIMITATIONS.running);
  if (complete) {
    if (!risk) limitations.push(CONTEXT_LIMITATIONS.noRisk);
    else if (risk.level === null) limitations.push(CONTEXT_LIMITATIONS.noRiskLevel);
    else if (risk.score === null) limitations.push(CONTEXT_LIMITATIONS.noRiskScore);
    if (issues.issueStatus === "LOADING") limitations.push(CONTEXT_LIMITATIONS.issuesLoading);
    if (issues.issueStatus === "UNAVAILABLE") limitations.push(CONTEXT_LIMITATIONS.issuesUnavailable);
  }
  limitations.push(CONTEXT_LIMITATIONS.scopeOnly, CONTEXT_LIMITATIONS.noEvidence);
  if (complete) limitations.push(CONTEXT_LIMITATIONS.verification);

  return {
    availability,
    latestAssessment: toAssessment(latest),
    ...issues,
    risk,
    lastError: errorText === null ? null : redactRuntimeText(errorText),
    scope: {
      authorizedTarget: latest.target,
      ...(latest.target === "AUTHORIZED_IOT" || latest.assessment_type === "ENVIRONMENT"
        ? {
            environment: {
              devices: (((latest.metadata?.posture as Record<string, unknown> | undefined)?.device_summaries as { device_id: string; ip_address: string }[] | undefined) ?? []).map((d) => ({
                deviceId: d.device_id,
                ip: d.ip_address,
              })),
              infrastructure: (((latest.metadata?.posture as Record<string, unknown> | undefined)?.infrastructure_summaries as { asset_id: string; ip_address: string; asset_type?: string }[] | undefined) ?? []).map((i) => ({
                assetId: i.asset_id,
                ip: i.ip_address,
                assetType: i.asset_type ?? "MQTT_BROKER",
              })),
              assetsCount: ((latest.metadata?.posture as Record<string, unknown> | undefined)?.assets_assessed as number | undefined),
            },
          }
        : {}),
    },
    verificationBaseline,
    capabilities: {
      canCheck: true,
      canExplain: complete,
      canFix: complete && (issues.importantIssues?.length ?? 0) > 0,
      canVerify: verificationBaseline !== null,
      canSummarize: true,
    },
    limitations,
  };
}
