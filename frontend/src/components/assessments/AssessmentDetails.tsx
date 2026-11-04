import { useCallback, useState, type ReactNode } from "react";
import { fetchAssessment } from "../../api/assessments";
import type {
  AssessmentDetail,
  AssessmentSummary,
  EnvironmentPosture,
} from "../../api/types";
import { useAsyncData } from "../../hooks/useAsyncData";
import { formatFactorLabel, formatGeneratedAt, severityTone } from "../../lib/format";
import { resolveAssetIdentity } from "../../lib/assets";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { KpiCard } from "../common/KpiCard";
import { LoadingState } from "../common/LoadingState";
import { SeverityBadge } from "../common/SeverityBadge";
import { StatusBadge } from "../common/StatusBadge";
import { AssessmentEvidenceList } from "./AssessmentEvidenceList";
import { AssessmentFindingList } from "./AssessmentFindingList";
import { statusTone } from "./AssessmentList";
import { AssessmentRiskView } from "./AssessmentRiskView";
import { AssessmentTrace } from "./AssessmentTrace";
import { EvaluationSummary } from "./EvaluationSummary";
import { ReassessmentPanel } from "./ReassessmentPanel";
import { VerificationEvaluation, useVerification } from "./VerificationEvaluation";
import type { ReassessmentPair } from "./reassessment";
import {
  REDACTED,
  formatJsonValue,
  formatNumber,
  isComplexValue,
  isSensitiveKey,
  redactSensitive,
} from "./detailFormat";

type Props = {
  assessmentId: string;
  /** Assessment list used to find the baseline; null while it loads. */
  history?: readonly AssessmentSummary[] | null;
  onReassessmentCreated?: (created: AssessmentDetail) => void;
  onReassessmentComplete?: (pair: ReassessmentPair) => void;
  onOpenAssessment?: (assessmentId: string) => void;
  onOpenComparison?: (pair: ReassessmentPair) => void;
  onOpenResearch?: () => void;
};

type SectionProps = {
  id?: string;
  title: string;
  description?: string;
  count?: number;
  children: ReactNode;
};

export function DetailSection({
  id,
  title,
  description,
  count,
  children,
}: SectionProps) {
  return (
    <section id={id} className="scroll-mt-24 space-y-3">
      <div>
        <h3 className="font-display text-base font-semibold">
          {title}
          {count === undefined ? null : (
            <span className="mono ml-2 text-sm font-normal text-[var(--muted)]">
              ({count})
            </span>
          )}
        </h3>
        {description ? (
          <p className="mt-1 text-sm text-[var(--muted)]">{description}</p>
        ) : null}
      </div>
      {children}
    </section>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 justify-between gap-3 rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2">
      <dt className="shrink-0 text-[var(--muted)]">{label}</dt>
      <dd className="min-w-0 break-words text-right">{children}</dd>
    </div>
  );
}

function AssessmentOverview({ detail }: { detail: AssessmentDetail }) {
  const level = detail.highest_risk_level;
  const failed = detail.status === "FAILED";
  const identity = resolveAssetIdentity(detail.target);
  const posture = detail.metadata?.posture as EnvironmentPosture | undefined;
  const infraCount =
    posture?.infrastructure_assessed ?? (posture?.infrastructure_summaries?.length ?? 0);
  const assetCount =
    posture?.assets_assessed ?? (posture?.devices_assessed ? posture.devices_assessed + infraCount : 1);

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-4">
        <KpiCard
          label="Overall Risk"
          value={
            detail.highest_risk === null ? "—" : formatNumber(detail.highest_risk)
          }
          secondary={level ?? "No risk recorded"}
          tone={severityTone(level)}
          stagger={1}
        />
        <KpiCard
          label="Assessed Assets"
          value={String(assetCount)}
          secondary={posture ? `${posture.devices_assessed} devices, ${infraCount} infra` : "Single Target"}
          stagger={2}
        />
        <KpiCard
          label="Vulnerabilities"
          value={String(detail.finding_count)}
          secondary="Deterministic findings"
          stagger={3}
        />
        <KpiCard
          label="Evidence"
          value={String(detail.evidence_count)}
          secondary="Observed records"
          stagger={4}
        />
      </div>

      <dl className="grid gap-2 text-sm sm:grid-cols-2">
        <Field label="Asset / Scope">
          <div className="flex flex-col items-end">
            <span className="font-medium text-[var(--text)]">{identity.displayName}</span>
            <span className="mono text-xs text-[var(--muted)]">{detail.target}</span>
          </div>
        </Field>
        <Field label="Assessment Type">
          {formatFactorLabel(detail.assessment_type)}
        </Field>
        <Field label="Status">
          <StatusBadge label={detail.status} tone={statusTone(detail.status)} />
        </Field>
        <Field label="Risk Level">
          {level ? (
            <SeverityBadge severity={level} />
          ) : (
            <span className="text-[var(--muted)]">Not recorded</span>
          )}
        </Field>
        <Field label="Started">
          <span className="mono">
            {formatGeneratedAt(detail.started_at) ?? "Not recorded"}
          </span>
        </Field>
        <Field label="Completed">
          <span className="mono">
            {detail.completed_at
              ? formatGeneratedAt(detail.completed_at) ?? "Not recorded"
              : detail.status === "RUNNING"
                ? "In progress"
                : "Not recorded"}
          </span>
        </Field>
        <Field label="Assessment ID">
          <span className="mono text-xs">{detail.id}</span>
        </Field>
      </dl>

      {detail.status !== "COMPLETE" ? (
        <div
          className={`rounded-xl border px-4 py-3 text-sm ${
            failed
              ? "border-[var(--danger)]/35 bg-[var(--danger)]/10 text-[var(--danger)]"
              : "border-[var(--warn)]/35 bg-[var(--warn)]/10 text-[var(--warn)]"
          }`}
        >
          <p className="font-medium">
            Assessment status: {detail.status}. Only the evidence, findings and
            risk data the backend recorded are shown below.
          </p>
          {detail.error_summary ? (
            <p className="mt-1 text-[var(--text)]/90">{detail.error_summary}</p>
          ) : null}
        </div>
      ) : detail.error_summary ? (
        <p className="text-sm text-[var(--muted)]">{detail.error_summary}</p>
      ) : null}
    </div>
  );
}

function AssetBreakdownSection({
  posture,
  onOpenAssessment,
}: {
  posture: EnvironmentPosture;
  onOpenAssessment?: (id: string) => void;
}) {
  const assetSummaries = posture.asset_summaries || [];
  if (assetSummaries.length === 0) return null;

  return (
    <section className="space-y-3">
      <div>
        <h3 className="font-display text-base font-semibold">
          Asset Assessment Breakdown
          <span className="mono ml-2 text-sm font-normal text-[var(--muted)]">
            ({assetSummaries.length} assets)
          </span>
        </h3>
        <p className="mt-1 text-sm text-[var(--muted)]">
          Independent security evaluation results for each physical device and infrastructure component.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        {assetSummaries.map((asset) => {
          const identity = resolveAssetIdentity(asset.ip_address || asset.asset_id);
          const findingsCount = asset.finding_count ?? asset.findings_count ?? 0;
          const status = asset.status ?? "UNKNOWN";
          const isComplete = status === "COMPLETE";

          return (
            <div
              key={asset.asset_id + asset.ip_address}
              className="flex flex-col justify-between rounded-2xl border border-white/[0.07] bg-white/[0.02] p-4 transition-colors hover:border-white/15"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
                    {identity.categoryLabel}
                  </span>
                  <StatusBadge
                    label={status === "COMPLETE" ? "Complete" : status}
                    tone={statusTone(status as any)}
                  />
                </div>

                <div>
                  <h4 className="text-sm font-semibold text-[var(--text)]">
                    {identity.displayName}
                  </h4>
                  <p className="mono text-xs text-[var(--muted)]">{asset.ip_address}</p>
                </div>

                <div className="pt-2">
                  {findingsCount > 0 ? (
                    <div className="text-xs font-semibold text-[var(--danger)]">
                      {findingsCount} {findingsCount === 1 ? "vulnerability" : "vulnerabilities"} detected
                    </div>
                  ) : isComplete ? (
                    <div className="text-xs text-emerald-400">
                      No findings detected
                      <p className="mt-0.5 text-[10px] text-[var(--muted)] leading-tight">
                        (Under evaluated checks; does not guarantee complete security)
                      </p>
                    </div>
                  ) : (
                    <div className="text-xs text-[var(--warn)]">
                      Assessment incomplete
                    </div>
                  )}
                </div>

                {asset.highest_risk_level ? (
                  <div className="flex items-center gap-2 pt-1 text-xs">
                    <span className="text-[var(--muted)]">Risk:</span>
                    <SeverityBadge severity={asset.highest_risk_level} />
                    {asset.highest_risk !== null && asset.highest_risk !== undefined ? (
                      <span className="mono text-[var(--text)]">
                        {formatNumber(asset.highest_risk)}/100
                      </span>
                    ) : null}
                  </div>
                ) : null}
              </div>

              {asset.assessment_id && onOpenAssessment ? (
                <div className="mt-3 border-t border-white/[0.05] pt-2">
                  <button
                    type="button"
                    onClick={() => onOpenAssessment(asset.assessment_id!)}
                    className="btn-soft text-xs text-[var(--accent)] hover:underline"
                  >
                    View asset details →
                  </button>
                </div>
              ) : null}
            </div>
          );
        })}
      </div>
    </section>
  );
}

function AssessmentMetadataView({ detail }: { detail: AssessmentDetail }) {
  const entries = Object.entries(detail.metadata ?? {});
  if (entries.length === 0) {
    return <EmptyState message="No metadata recorded for this assessment." />;
  }

  return (
    <dl className="grid gap-2 text-sm sm:grid-cols-2">
      {entries.map(([key, value]) => (
        <div
          key={key}
          className="min-w-0 rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2"
        >
          <dt className="text-[var(--muted)]">{formatFactorLabel(key)}</dt>
          <dd className="mono mt-0.5 break-words text-[var(--text)]">
            {isSensitiveKey(key) ? (
              REDACTED
            ) : isComplexValue(value) ? (
              <pre className="mono max-h-48 overflow-auto text-xs">
                {JSON.stringify(redactSensitive(value), null, 2)}
              </pre>
            ) : (
              formatJsonValue(value)
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function AssessmentDetails(props: Props) {
  const { assessmentId } = props;
  const loadDetail = useCallback(
    () => fetchAssessment(assessmentId),
    [assessmentId],
  );
  const detail = useAsyncData(loadDetail, 0);

  if (detail.loading && !detail.data) {
    return <LoadingState message="Loading assessment details..." />;
  }
  if (detail.error) {
    return <ErrorState message={detail.error} onRetry={detail.reload} />;
  }
  if (!detail.data) return null;

  return <AssessmentDetailBody {...props} data={detail.data} />;
}

function AssessmentDetailBody({
  data,
  history = null,
  onReassessmentCreated,
  onReassessmentComplete,
  onOpenAssessment,
  onOpenComparison,
  onOpenResearch,
}: Props & { data: AssessmentDetail }) {
  const verification = useVerification(data, history);
  const [verifyRequest, setVerifyRequest] = useState(0);
  const posture = data.metadata?.posture as EnvironmentPosture | undefined;

  function runVerification() {
    setVerifyRequest((value) => value + 1);
    document
      .getElementById("assessment-reassessment")
      ?.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Section A: Assessment Overview */}
      <DetailSection
        title="Assessment Overview"
        description="Results recorded by the backend assessment engine. Values are displayed exactly as returned."
      >
        <AssessmentOverview detail={data} />
        <ReassessmentPanel
          key={data.id}
          assessment={data}
          onCreated={onReassessmentCreated}
          onComplete={onReassessmentComplete}
          onOpenAssessment={onOpenAssessment}
          requestToken={verifyRequest}
        />
      </DetailSection>

      {/* Section B: Asset Assessment Breakdown (for Environment Assessments) */}
      {posture ? (
        <AssetBreakdownSection
          posture={posture}
          onOpenAssessment={onOpenAssessment}
        />
      ) : null}

      {/* Section C: Security Findings */}
      <DetailSection
        id="assessment-findings"
        title="Security Findings"
        count={data.findings.length}
        description="Deterministic findings derived from observed evidence. Each finding shows the affected asset, evidence, risk impact and remediation."
      >
        {data.findings.length ? (
          <AssessmentFindingList
            findings={data.findings}
            evidence={data.evidence}
            snapshots={data.risk_snapshots}
          />
        ) : (
          <EmptyState message="No findings recorded for this assessment." />
        )}
      </DetailSection>

      {/* Section D: Before-and-After Comparison & Verification */}
      <DetailSection
        id="assessment-verification"
        title="Before and After Comparison"
        description="This check compared with the previous completed check of the same target, using the deterministic comparison."
      >
        <VerificationEvaluation
          detail={data}
          state={verification.state}
          onRetry={verification.retry}
          onRunVerification={runVerification}
          onOpenComparison={onOpenComparison}
        />
      </DetailSection>

      <DetailSection
        id="assessment-evaluation"
        title="Evaluation Summary"
        description="What this check recorded, counted from its stored records. No accuracy figures are estimated."
      >
        <EvaluationSummary
          detail={data}
          verification={verification.state}
          onOpenResearch={onOpenResearch}
        />
      </DetailSection>

      {/* Advanced Technical Details Collapsible Accordion */}
      <details className="group rounded-2xl border border-white/[0.08] bg-white/[0.02] p-4 transition-all">
        <summary className="flex cursor-pointer items-center justify-between font-display text-base font-semibold text-[var(--text)] select-none">
          <div className="flex items-center gap-2">
            <span>Advanced Technical Details</span>
            <span className="rounded bg-white/[0.06] px-2 py-0.5 text-xs font-normal text-[var(--muted)]">
              Probes, Traces & Raw JSON
            </span>
          </div>
          <span className="mono text-xs text-[var(--muted)] group-open:rotate-180 transition-transform">
            ▼
          </span>
        </summary>

        <div className="mt-4 space-y-6 border-t border-white/[0.06] pt-4">
          <DetailSection
            id="assessment-trace"
            title="Security Trace Graph"
            count={data.findings.length}
            description="How each finding leads to the risk result: observed evidence, severity, risk factor, contribution and overall risk."
          >
            <AssessmentTrace detail={data} />
          </DetailSection>

          <DetailSection
            id="assessment-risk"
            title="Risk Factor Calculation & Snapshots"
            count={data.risk_snapshots.length}
            description="Risk snapshots calculated by the backend risk engine. Values displayed without modification."
          >
            <AssessmentRiskView snapshots={data.risk_snapshots} findings={data.findings} />
          </DetailSection>

          <DetailSection
            id="assessment-evidence"
            title="Raw Evidence Records"
            count={data.evidence.length}
            description="Observed evidence produced by network and protocol probes."
          >
            {data.evidence.length ? (
              <AssessmentEvidenceList evidence={data.evidence} />
            ) : (
              <EmptyState message="No evidence recorded for this assessment." />
            )}
          </DetailSection>

          <DetailSection
            title="Assessment Configuration & Metadata"
            description="Engine configuration recorded by the backend for this run."
          >
            <AssessmentMetadataView detail={data} />
          </DetailSection>
        </div>
      </details>
    </div>
  );
}
