/**
 * Evidence -> finding -> risk factor -> overall risk, assembled only by joining
 * recorded IDs: finding.evidence_reference, snapshot.finding_ref and the
 * backend's risk_trace. Scores, contributions and comparison outcomes are
 * displayed as recorded; nothing here scores, weights or decides an outcome.
 */
import type {
  AssessmentDetail,
  AssessmentEvidence,
  AssessmentFinding,
  AssessmentSummary,
  RiskSnapshot,
  RiskTraceFactor,
} from "../api/types";
import { provenanceOf, type Provenance } from "../components/assessments/detailFormat";
import {
  COVERAGE_EVALUATED,
  findingSnapshot,
  overallSnapshot,
  readCoverage,
  type AssessmentComparisonResult,
} from "./assessmentComparison";
import { formatFactorLabel } from "./format";
import { issueGroup, summarizeIssues } from "./securityHome";

export const EVIDENCE_NOT_AVAILABLE = "Evidence not available for this finding.";
export const GROUND_TRUTH_NOT_CONFIGURED = "Ground-truth evaluation dataset is not configured.";
export const NO_VERIFICATION_COMPARISON = "No verification comparison is available yet.";
export const RUN_VERIFICATION_HINT =
  "Run a new security check after remediation to compare the results.";

export type TraceFactor = {
  factor: string;
  label: string;
  /** Recorded contribution_to_100, normalized_value and weight; null when absent. */
  contribution: number | null;
  normalizedValue: number | null;
  weight: number | null;
  /** Recorded context_inputs[factor].source. */
  source: string | null;
  provenance: Provenance | null;
  /** Recorded derivation or limitation text for this input. */
  note: string | null;
};

export type TraceEvidence =
  | { kind: "linked"; record: AssessmentEvidence }
  | { kind: "not_available" };

export type FindingTrace = {
  finding: AssessmentFinding;
  evidence: TraceEvidence;
  /** The finding's own snapshot; INFO findings are not scored by the backend. */
  findingRisk: RiskSnapshot | null;
  /** Snapshot the factor values were read from (own snapshot, else overall). */
  factorSnapshot: "finding" | "overall" | null;
  factorLinks: "recorded" | "not_recorded";
  linkedFactors: TraceFactor[];
  otherFactors: TraceFactor[];
  /** Backend says this finding's snapshot is the one copied to the overall risk. */
  setsOverall: boolean;
};

export type AssessmentTrace = {
  overall: RiskSnapshot | null;
  traceRecorded: boolean;
  findings: FindingTrace[];
  modelLimitations: string[];
};

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function severityIndex(severity: string): number {
  const index = SEVERITY_ORDER.indexOf(severity.toUpperCase());
  return index === -1 ? SEVERITY_ORDER.length : index;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function recordedNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function recordedText(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

export function traceFactor(snapshot: RiskSnapshot, factor: string): TraceFactor {
  const contribution = snapshot.factor_contributions?.[factor];
  const input = snapshot.context_inputs?.[factor];
  const source = isRecord(input) ? recordedText(input.source) : null;
  return {
    factor,
    label: formatFactorLabel(factor),
    contribution: isRecord(contribution) ? recordedNumber(contribution.contribution_to_100) : null,
    normalizedValue: isRecord(contribution) ? recordedNumber(contribution.normalized_value) : null,
    weight: isRecord(contribution) ? recordedNumber(contribution.weight) : null,
    source,
    provenance: provenanceOf(source),
    note: isRecord(input) ? recordedText(input.derivation) ?? recordedText(input.limitation) : null,
  };
}

function byRecordedContribution(a: TraceFactor, b: TraceFactor): number {
  return (b.contribution ?? -1) - (a.contribution ?? -1) || a.label.localeCompare(b.label);
}

function factorsLinkedTo(factors: RiskTraceFactor[], findingId: string): Set<string> {
  return new Set(
    factors.filter((item) => item.finding_refs.includes(findingId)).map((item) => item.factor),
  );
}

function modelLimitations(snapshot: RiskSnapshot | null): string[] {
  const value = snapshot?.context_inputs?.model_limitations;
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export function buildAssessmentTrace(detail: AssessmentDetail): AssessmentTrace {
  const overall = overallSnapshot(detail);
  const trace = detail.risk_trace ?? null;
  const evidenceById = new Map(detail.evidence.map((item) => [item.id, item]));

  const findings = [...detail.findings]
    .sort(
      (a, b) =>
        severityIndex(a.severity) - severityIndex(b.severity) ||
        a.finding_id.localeCompare(b.finding_id) ||
        (a.port ?? -1) - (b.port ?? -1),
    )
    .map((finding): FindingTrace => {
      const record = finding.evidence_reference
        ? evidenceById.get(finding.evidence_reference)
        : undefined;
      const own = findingSnapshot(detail, finding);
      const source = own ?? overall;
      const linkedKeys = trace ? factorsLinkedTo(trace.factors, finding.id) : new Set<string>();
      const factorKeys = source ? Object.keys(source.factor_contributions ?? {}) : [];
      const factors = source ? factorKeys.map((key) => traceFactor(source, key)) : [];
      return {
        finding,
        evidence: record ? { kind: "linked", record } : { kind: "not_available" },
        findingRisk: own,
        factorSnapshot: own ? "finding" : overall ? "overall" : null,
        factorLinks: trace ? "recorded" : "not_recorded",
        linkedFactors: factors.filter((f) => linkedKeys.has(f.factor)).sort(byRecordedContribution),
        otherFactors: factors.filter((f) => !linkedKeys.has(f.factor)).sort(byRecordedContribution),
        setsOverall: Boolean(trace?.overall_finding_refs.includes(finding.id)),
      };
    });

  return {
    overall,
    traceRecorded: trace !== null,
    findings,
    modelLimitations: modelLimitations(overall),
  };
}

// ---------------------------------------------------------------------------
// Evaluation summary (counts of recorded rows only)
// ---------------------------------------------------------------------------

export type EvaluationSummary = {
  coverage:
    | { recorded: false }
    | { recorded: true; evaluated: number; entries: number };
  evidenceCount: number;
  findingCount: number;
  risk: { snapshot: RiskSnapshot; contributors: TraceFactor[] } | null;
  findings: { important: number; minor: number; informational: number };
  /** Grouped by check, as in the Assistant and Security views. */
  importantIssues: number;
};

export function buildEvaluationSummary(detail: AssessmentDetail): EvaluationSummary {
  const coverage = readCoverage(detail);
  const overall = overallSnapshot(detail);
  const counts = { important: 0, minor: 0, informational: 0 };
  for (const finding of detail.findings) {
    const group = issueGroup(finding.severity);
    if (group === "important") counts.important += 1;
    else if (group === "minor") counts.minor += 1;
    else counts.informational += 1;
  }
  return {
    coverage: coverage.recorded
      ? {
          recorded: true,
          evaluated: [...coverage.entries.values()].filter((s) => s === COVERAGE_EVALUATED).length,
          entries: coverage.entries.size,
        }
      : { recorded: false },
    evidenceCount: detail.evidence.length,
    findingCount: detail.findings.length,
    risk: overall
      ? {
          snapshot: overall,
          contributors: Object.keys(overall.factor_contributions ?? {})
            .map((key) => traceFactor(overall, key))
            .sort(byRecordedContribution),
        }
      : null,
    findings: counts,
    importantIssues: summarizeIssues(detail).important.length,
  };
}

// ---------------------------------------------------------------------------
// Before / after (renders compareAssessments output only)
// ---------------------------------------------------------------------------

/** Most recent earlier COMPLETE check of the same target; the baseline. */
export function selectBaseline(
  history: readonly AssessmentSummary[],
  current: Pick<AssessmentSummary, "id" | "target" | "started_at">,
): AssessmentSummary | null {
  const start = Date.parse(current.started_at);
  if (Number.isNaN(start)) return null;
  const earlier = history.filter(
    (item) =>
      item.id !== current.id &&
      item.status === "COMPLETE" &&
      item.target === current.target &&
      Date.parse(item.started_at) < start,
  );
  if (!earlier.length) return null;
  return earlier.reduce((best, item) =>
    Date.parse(item.started_at) > Date.parse(best.started_at) ? item : best,
  );
}

export type VerificationSide = {
  detail: AssessmentDetail;
  risk: RiskSnapshot | null;
  importantIssues: number;
};

export type VerificationView =
  | {
      kind: "compared";
      baseline: VerificationSide;
      verification: VerificationSide;
      /** compareRisk delta; null when risk could not be compared. */
      riskDelta: number | null;
      riskUnavailable: "missing" | "version_mismatch" | null;
      resolved: AssessmentFinding[];
      added: AssessmentFinding[];
      unchanged: AssessmentFinding[];
      notConfirmed: AssessmentFinding[];
      warnings: string[];
    }
  | { kind: "not_comparable"; reasons: string[] };

function side(detail: AssessmentDetail, risk: RiskSnapshot | null): VerificationSide {
  return { detail, risk, importantIssues: summarizeIssues(detail).important.length };
}

export function verificationView(result: AssessmentComparisonResult): VerificationView {
  if (!result.comparable || !result.findings) {
    return {
      kind: "not_comparable",
      reasons: result.issues.filter((i) => i.level === "blocking").map((i) => i.message),
    };
  }
  return {
    kind: "compared",
    baseline: side(result.before, result.risk.before),
    verification: side(result.after, result.risk.after),
    riskDelta: result.risk.delta,
    riskUnavailable: result.risk.unavailableReason,
    resolved: result.findings.resolved.map((item) => item.before),
    added: result.findings.added.map((item) => item.after),
    unchanged: result.findings.remaining.map((item) => item.after),
    notConfirmed: result.findings.unconfirmed.map((item) => item.before),
    warnings: result.issues.filter((i) => i.level === "warning").map((i) => i.message),
  };
}
