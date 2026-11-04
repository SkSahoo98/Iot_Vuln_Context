import { useState } from "react";
import type { AssessmentStatus, AssessmentSummary, EnvironmentPosture } from "../../api/types";
import { formatGeneratedAt, severityTone } from "../../lib/format";
import { resolveAssetIdentity } from "../../lib/assets";
import { StatusBadge } from "../common/StatusBadge";
import { formatNumber } from "./detailFormat";

interface AssessmentListProps {
  assessments: AssessmentSummary[];
  selectedAssessmentId: string | null;
  onSelect: (assessmentId: string) => void;
}

export function statusTone(
  status: AssessmentStatus,
): "ok" | "info" | "warn" | "danger" | "neutral" {
  switch (status) {
    case "COMPLETE":
      return "ok";
    case "RUNNING":
      return "info";
    case "INCOMPLETE":
      return "warn";
    case "FAILED":
      return "danger";
    default:
      return "neutral";
  }
}

const STATUS_TEXT: Record<AssessmentStatus, string> = {
  COMPLETE: "Complete",
  RUNNING: "Not finished",
  INCOMPLETE: "Partial check",
  FAILED: "Failed",
};

const LEVEL_TONE: Record<ReturnType<typeof severityTone>, string> = {
  danger: "text-[var(--danger)]",
  warn: "text-[var(--warn)]",
  ok: "text-[var(--ok)]",
  default: "text-[var(--text)]",
};

function RiskLine({ assessment }: { assessment: AssessmentSummary }) {
  if (assessment.status !== "COMPLETE") {
    return <span className="text-[var(--muted)]">No risk rating for this check</span>;
  }
  if (assessment.highest_risk_level === null && assessment.highest_risk === null) {
    return <span className="text-[var(--muted)]">No overall risk recorded</span>;
  }
  return (
    <span>
      {assessment.highest_risk_level ? (
        <span
          className={`font-semibold ${LEVEL_TONE[severityTone(assessment.highest_risk_level)]}`}
        >
          {assessment.highest_risk_level}
        </span>
      ) : null}
      {assessment.highest_risk_level && assessment.highest_risk !== null ? " · " : null}
      {assessment.highest_risk !== null ? (
        <span className="mono text-[var(--text)]">
          {formatNumber(assessment.highest_risk)}/100
        </span>
      ) : null}
    </span>
  );
}

interface GroupedRun {
  parent: AssessmentSummary;
  isEnvironment: boolean;
  children: Array<{
    asset_id: string;
    ip_address: string;
    assessment_id?: string;
    status: string;
    highest_risk?: number | null;
    highest_risk_level?: string | null;
    finding_count: number;
  }>;
}

/**
 * Groups related assessment runs using actual backend parent-child metadata (batch_id).
 * Standalone assessments without an environment batch remain independent entries.
 */
function groupAssessments(assessments: AssessmentSummary[]): GroupedRun[] {
  const envRuns = assessments.filter(
    (a) =>
      a.target === "AUTHORIZED_IOT" ||
      a.assessment_type === "ENVIRONMENT" ||
      (a.metadata as Record<string, unknown> | undefined)?.scope === "AUTHORIZED_IOT",
  );

  const claimedChildIds = new Set<string>();
  const groups: GroupedRun[] = [];

  for (const env of envRuns) {
    const meta = env.metadata as Record<string, unknown> | undefined;
    const batchId = (meta?.batch_id as string | undefined) || env.id;
    const posture = meta?.posture as EnvironmentPosture | undefined;

    // Collect child summaries from posture or metadata asset_runs
    const assetSummaries =
      posture?.asset_summaries ||
      (meta?.asset_runs as Array<{
        asset_id: string;
        ip_address: string;
        assessment_id?: string;
        status: string;
        highest_risk?: number | null;
        highest_risk_level?: string | null;
        finding_count?: number;
        findings_count?: number;
      }>) ||
      [];

    const children = assetSummaries.map((s) => {
      if (s.assessment_id) claimedChildIds.add(s.assessment_id);
      return {
        asset_id: s.asset_id,
        ip_address: s.ip_address,
        assessment_id: s.assessment_id,
        status: s.status ?? "UNKNOWN",
        highest_risk: s.highest_risk ?? null,
        highest_risk_level: s.highest_risk_level ?? null,
        finding_count: s.finding_count ?? s.findings_count ?? 0,
      };
    });

    // Also look up child assessment items in assessments list sharing this batch_id
    assessments.forEach((candidate) => {
      if (candidate.id === env.id) return;
      const cMeta = candidate.metadata as Record<string, unknown> | undefined;
      if (cMeta?.batch_id === batchId) {
        claimedChildIds.add(candidate.id);
        if (!children.some((c) => c.assessment_id === candidate.id || c.ip_address === candidate.target)) {
          children.push({
            asset_id: (cMeta.asset_id as string | undefined) ?? candidate.target,
            ip_address: candidate.target,
            assessment_id: candidate.id,
            status: candidate.status,
            highest_risk: candidate.highest_risk,
            highest_risk_level: candidate.highest_risk_level,
            finding_count: candidate.finding_count,
          });
        }
      }
    });

    groups.push({
      parent: env,
      isEnvironment: true,
      children,
    });
  }

  // Standalone runs not claimed as children of an environment batch
  for (const item of assessments) {
    if (envRuns.some((e) => e.id === item.id)) continue;
    if (claimedChildIds.has(item.id)) continue;

    groups.push({
      parent: item,
      isEnvironment: false,
      children: [],
    });
  }

  return groups;
}

export function AssessmentList({
  assessments,
  selectedAssessmentId,
  onSelect,
}: AssessmentListProps) {
  const [expandedBatches, setExpandedBatches] = useState<Record<string, boolean>>({});
  const groups = groupAssessments(assessments);

  function toggleExpand(batchId: string, event: React.MouseEvent) {
    event.stopPropagation();
    setExpandedBatches((prev) => ({ ...prev, [batchId]: !prev[batchId] }));
  }

  return (
    <ul className="grid gap-3 lg:grid-cols-2">
      {groups.map(({ parent: assessment, isEnvironment, children }) => {
        const selected = assessment.id === selectedAssessmentId;
        const when = formatGeneratedAt(assessment.started_at) ?? "Time not recorded";
        const identity = resolveAssetIdentity(assessment.target);
        const displayName = isEnvironment ? "My IoT Environment" : identity.displayName;
        const isExpanded = !!expandedBatches[assessment.id];

        return (
          <li key={assessment.id} className="min-w-0">
            <div
              className={`flex w-full min-w-0 flex-col gap-2 rounded-2xl border px-4 py-4 text-left transition-colors ${
                selected
                  ? "border-[var(--accent)]/50 bg-[var(--accent)]/[0.07]"
                  : "border-white/[0.07] bg-white/[0.025] hover:border-white/15 hover:bg-white/[0.04]"
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[11px] font-medium uppercase tracking-[0.12em] text-[var(--muted)]">
                  Security check
                </span>
                {assessment.status !== "COMPLETE" ? (
                  <StatusBadge
                    label={STATUS_TEXT[assessment.status] ?? assessment.status}
                    tone={statusTone(assessment.status)}
                  />
                ) : (
                  <StatusBadge label="Completed" tone="ok" />
                )}
              </div>

              <div>
                <span className="text-sm font-semibold text-[var(--text)]">
                  {displayName}
                </span>
                <div className="flex flex-wrap items-center gap-x-2 text-xs text-[var(--muted)]">
                  <span>{when}</span>
                  <span>•</span>
                  <span className="mono break-all text-xs text-[var(--muted)]">
                    {assessment.target}
                  </span>
                </div>
              </div>

              <div className="text-sm">
                <RiskLine assessment={assessment} />
              </div>

              <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--muted)]">
                <span>
                  {assessment.finding_count}{" "}
                  {assessment.finding_count === 1 ? "finding" : "findings"}
                </span>
                {isEnvironment && children.length > 0 ? (
                  <>
                    <span>•</span>
                    <span>{children.length} assets assessed</span>
                  </>
                ) : null}
              </div>

              {/* Expandable breakdown for Environment runs */}
              {isEnvironment && children.length > 0 ? (
                <div className="mt-2 border-t border-white/[0.06] pt-2">
                  <button
                    type="button"
                    onClick={(e) => toggleExpand(assessment.id, e)}
                    className="flex w-full items-center justify-between py-1 text-xs font-medium text-[var(--accent)] hover:underline"
                  >
                    <span>
                      {isExpanded ? "Hide" : "Show"} asset breakdown ({children.length})
                    </span>
                    <span className="mono text-[10px] text-[var(--muted)]">
                      {isExpanded ? "▲" : "▼"}
                    </span>
                  </button>

                  {isExpanded ? (
                    <div className="mt-2 space-y-1.5 rounded-xl border border-white/[0.05] bg-black/20 p-2.5">
                      {children.map((child) => {
                        const childId = resolveAssetIdentity(child.ip_address || child.asset_id);
                        return (
                          <div
                            key={child.asset_id + child.ip_address}
                            className="flex flex-col gap-1 rounded-lg border border-white/[0.04] bg-white/[0.015] p-2 sm:flex-row sm:items-center sm:justify-between text-xs"
                          >
                            <div>
                              <div className="font-medium text-[var(--text)]">
                                {childId.displayName}
                              </div>
                              <div className="mono text-[11px] text-[var(--muted)]">
                                {child.ip_address}
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <span
                                className={
                                  child.finding_count > 0
                                    ? "font-semibold text-[var(--danger)]"
                                    : "text-[var(--muted)]"
                                }
                              >
                                {child.finding_count}{" "}
                                {child.finding_count === 1 ? "finding" : "findings"}
                              </span>
                              {child.assessment_id ? (
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    onSelect(child.assessment_id!);
                                  }}
                                  className="btn-soft rounded px-2 py-0.5 text-[11px] text-[var(--accent)] hover:bg-[var(--accent-soft)]"
                                >
                                  View asset
                                </button>
                              ) : null}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  ) : null}
                </div>
              ) : null}

              <div className="mt-2 pt-1 border-t border-white/[0.04] flex items-center justify-between">
                <button
                  type="button"
                  onClick={() => onSelect(assessment.id)}
                  aria-pressed={selected}
                  className={`btn-soft inline-flex items-center rounded-lg px-3 py-1.5 text-xs font-semibold ${
                    selected
                      ? "bg-[var(--accent-soft)] text-[var(--accent)]"
                      : "text-[var(--accent)] hover:bg-[var(--accent)]/10"
                  }`}
                >
                  {selected ? "Showing details below" : "View details"}
                </button>
              </div>
            </div>
          </li>
        );
      })}
    </ul>
  );
}
