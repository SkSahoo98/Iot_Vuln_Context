import { useMemo, type ReactNode } from "react";
import type {
  AssessmentDetail,
  AssessmentEvidence,
  AssessmentFinding,
  RiskSnapshot,
} from "../../api/types";
import type {
  AssessmentComparisonResult as ComparisonData,
  CoverageIndex,
  CoverageLookup,
  EvidenceRow,
  NewFinding,
  RemainingFinding,
  ResolvedFinding,
  RiskComparison,
  UnconfirmedFinding,
  UnconfirmedReason,
} from "../../lib/assessmentComparison";
import {
  formatConfidence,
  formatFactorLabel,
  formatGeneratedAt,
} from "../../lib/format";
import { resolveAssetIdentity } from "../../lib/assets";
import { EmptyState } from "../common/EmptyState";
import { KpiCard } from "../common/KpiCard";
import { SeverityBadge } from "../common/SeverityBadge";
import { StatusBadge } from "../common/StatusBadge";
import { DetailSection, Field } from "./AssessmentDetails";
import { ObservationFields } from "./AssessmentEvidenceList";
import { RiskImpact } from "./AssessmentFindingList";
import { formatNumber, formatTargetPort } from "./detailFormat";

type Props = {
  comparison: ComparisonData;
};

type EvidenceLookup = Map<string, AssessmentEvidence>;

const STATIC_LIMITATIONS = [
  "Evidence is shown side-by-side; observation differences are not interpreted as security conclusions.",
  "A risk score difference is not proof that a specific change caused it; shared context factors can differ between runs.",
  "A finding is only shown as resolved when the AFTER assessment evaluated the same check for the same target and port and did not report it.",
];

const UNCONFIRMED_LABEL: Record<UnconfirmedReason, string> = {
  NOT_EVALUATED: "Not evaluated",
  NOT_APPLICABLE: "Not applicable",
  COVERAGE_NOT_RECORDED: "Coverage not recorded",
  NO_COVERAGE_ENTRY: "No coverage entry",
  UNRECOGNIZED_STATUS: "Unrecognized coverage",
};

function SubHeading({ children }: { children: ReactNode }) {
  return (
    <p className="text-[11px] font-medium uppercase tracking-[0.1em] text-[var(--muted)]">
      {children}
    </p>
  );
}

function formatDelta(delta: number): string {
  return delta > 0 ? `+${formatNumber(delta)}` : formatNumber(delta);
}

function deltaSentence(delta: number): string {
  if (delta < 0) {
    return `Risk score decreased by ${formatNumber(-delta)} points between assessments.`;
  }
  if (delta > 0) {
    return `Risk score increased by ${formatNumber(delta)} points between assessments.`;
  }
  return "Risk score is the same in both assessments.";
}

function confidenceText(value: number | null): string {
  return value === null ? "Not recorded" : formatConfidence(value);
}

function describeCoverage(lookup: CoverageLookup): string {
  if (lookup.kind === "not_recorded") return "Coverage not recorded";
  if (lookup.kind === "no_entry") return "No coverage entry for this check and port";
  return lookup.scope === "scan_wide"
    ? `${lookup.status} (scan-wide entry covering this port)`
    : lookup.status;
}

function coverageSummary(index: CoverageIndex): string {
  if (!index.recorded) return "Not recorded";
  const invalid = index.invalidEntries
    ? `, ${index.invalidEntries} unreadable`
    : "";
  return `Recorded (${index.entryCount} entries${invalid})`;
}

function useEvidenceLookup(detail: AssessmentDetail): EvidenceLookup {
  return useMemo(
    () => new Map(detail.evidence.map((item) => [item.id, item])),
    [detail.evidence],
  );
}

// ---------------------------------------------------------------------------
// Shared pieces
// ---------------------------------------------------------------------------

function EvidencePeek({
  evidence,
  label,
}: {
  evidence: AssessmentEvidence;
  label: string;
}) {
  return (
    <div className="min-w-0 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <SubHeading>{label}</SubHeading>
          <p className="mono mt-1 break-all text-sm font-semibold text-[var(--text)]">
            {evidence.check_type}
          </p>
          <p className="mt-0.5 break-words text-xs text-[var(--muted)]">
            {"Source "}
            <span className="mono">{evidence.evidence_source}</span>
            {" · "}
            <span className="mono">{formatTargetPort(evidence.target, evidence.port)}</span>
            {" · "}
            {formatGeneratedAt(evidence.observed_at) ?? "Time not recorded"}
          </p>
        </div>
        <StatusBadge label={evidence.result} tone="info" />
      </div>
      <details className="mt-2">
        <summary className="cursor-pointer text-xs font-medium text-[var(--muted)] hover:text-[var(--text)]">
          Observation
        </summary>
        <ObservationFields observation={evidence.observation} hideEmpty />
      </details>
    </div>
  );
}

function LinkedEvidenceFor({
  finding,
  lookup,
  label,
}: {
  finding: AssessmentFinding;
  lookup: EvidenceLookup;
  label: string;
}) {
  const reference = finding.evidence_reference;
  if (!reference) {
    return (
      <p className="text-sm text-[var(--muted)]">
        {label}: evidence reference not available.
      </p>
    );
  }
  const item = lookup.get(reference);
  if (!item) {
    return (
      <p className="break-all text-sm text-[var(--warn)]">
        {label}: referenced evidence could not be resolved.
      </p>
    );
  }
  return <EvidencePeek evidence={item} label={label} />;
}

function RiskSide({
  label,
  snapshot,
}: {
  label: string;
  snapshot: RiskSnapshot | null;
}) {
  return (
    <div className="min-w-0 space-y-1.5">
      <SubHeading>{label}</SubHeading>
      {snapshot ? (
        <RiskImpact snapshot={snapshot} />
      ) : (
        <p className="text-sm text-[var(--muted)]">No risk snapshot recorded.</p>
      )}
    </div>
  );
}

function FindingRiskComparison({ risk }: { risk: RiskComparison }) {
  return (
    <div className="space-y-2">
      <div className="grid gap-3 md:grid-cols-2">
        <RiskSide label="Before risk" snapshot={risk.before} />
        <RiskSide label="After risk" snapshot={risk.after} />
      </div>
      <p className="text-xs text-[var(--muted)]">
        {risk.delta !== null ? (
          <>
            {"Delta (AFTER − BEFORE): "}
            <span className="mono text-[var(--text)]">{formatDelta(risk.delta)}</span>
          </>
        ) : risk.unavailableReason === "version_mismatch" ? (
          "No comparable risk snapshot: risk score versions differ."
        ) : (
          "No comparable risk snapshot."
        )}
      </p>
    </div>
  );
}

function Remediation({ text }: { text: string | null }) {
  return (
    <div className="space-y-1.5">
      <SubHeading>Remediation · from assessment engine</SubHeading>
      <div className="rounded-xl border border-[var(--accent)]/25 bg-[var(--accent)]/[0.06] px-3.5 py-3">
        <p className="text-sm text-[var(--text)]">
          {text ?? (
            <span className="text-[var(--muted)]">
              No remediation recorded for this finding.
            </span>
          )}
        </p>
      </div>
    </div>
  );
}

function FindingHeader({
  finding,
  badge,
}: {
  finding: AssessmentFinding;
  badge: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0 flex-1">
        <h4 className="font-display text-sm font-semibold leading-snug sm:text-base">
          {finding.title}
        </h4>
        <p className="mt-1 break-words text-xs text-[var(--muted)]">
          <span className="mono">{finding.finding_id}</span>
          {" · "}
          {finding.category}
          {" · "}
          <span className="mono">{formatTargetPort(finding.target, finding.port)}</span>
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-2">{badge}</div>
    </div>
  );
}

function ListOrEmpty<T>({
  items,
  empty,
  render,
}: {
  items: T[];
  empty: string;
  render: (item: T) => ReactNode;
}) {
  if (!items.length) return <EmptyState message={empty} />;
  return <ul className="space-y-3">{items.map(render)}</ul>;
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

function ComparisonStatus({ comparison }: Props) {
  const { before, after, comparable, issues } = comparison;
  const blocking = issues.filter((issue) => issue.level === "blocking");
  const warnings = issues.length - blocking.length;

  return (
    <div className="surface-panel space-y-4 rounded-2xl p-4">
      <div className="flex flex-wrap items-center gap-3">
        <StatusBadge
          label={comparable ? "Comparable" : "Not comparable"}
          tone={comparable ? "ok" : "danger"}
        />
        {comparable && warnings > 0 ? (
          <p className="text-xs text-[var(--warn)]">
            {warnings} limitation{warnings === 1 ? "" : "s"} apply; see Comparison
            limitations below.
          </p>
        ) : null}
      </div>

      {blocking.length ? (
        <ul className="space-y-2 rounded-xl border border-[var(--danger)]/35 bg-[var(--danger)]/10 px-4 py-3 text-sm text-[var(--danger)]">
          {blocking.map((issue) => (
            <li key={issue.message}>{issue.message}</li>
          ))}
        </ul>
      ) : null}

      <div className="grid gap-3 md:grid-cols-2">
        {[
          { label: "Before", detail: before, coverage: comparison.beforeCoverage },
          { label: "After", detail: after, coverage: comparison.afterCoverage },
        ].map(({ label, detail, coverage }) => (
          <div key={label} className="min-w-0 space-y-2">
            <SubHeading>{label} assessment</SubHeading>
            <dl className="grid gap-2 text-sm">
              <Field label="Assessment ID">
                <span className="mono text-xs">{detail.id}</span>
              </Field>
              <Field label="Target">
                <span className="font-semibold text-xs text-[var(--text)]">
                  {resolveAssetIdentity(detail.target).displayName}
                </span>
                <span className="mono ml-2 text-xs text-[var(--muted)]">({detail.target})</span>
              </Field>
              <Field label="Assessment type">
                {formatFactorLabel(detail.assessment_type)}
              </Field>
              <Field label="Status">
                <StatusBadge
                  label={detail.status}
                  tone={detail.status === "COMPLETE" ? "ok" : "warn"}
                />
              </Field>
              <Field label="Started">
                <span className="mono">
                  {formatGeneratedAt(detail.started_at) ?? "Not recorded"}
                </span>
              </Field>
              <Field label="Check catalog">
                <span className="mono">
                  {typeof detail.metadata?.check_catalog_version === "string"
                    ? detail.metadata.check_catalog_version
                    : "Not recorded"}
                </span>
              </Field>
              <Field label="Coverage">{coverageSummary(coverage)}</Field>
            </dl>
          </div>
        ))}
      </div>
    </div>
  );
}

function OverallRiskSide({
  label,
  snapshot,
}: {
  label: string;
  snapshot: RiskSnapshot | null;
}) {
  return (
    <div className="surface-panel min-w-0 rounded-2xl p-4">
      <SubHeading>{label}</SubHeading>
      {snapshot ? (
        <div className="mt-2 space-y-2">
          <p className="flex flex-wrap items-baseline gap-2">
            <span className="mono text-3xl font-semibold">
              {formatNumber(snapshot.score)}
            </span>
            <span className="text-sm text-[var(--muted)]">/ 100</span>
            <SeverityBadge severity={snapshot.risk_level} />
          </p>
          <p className="text-xs text-[var(--muted)]">
            {"Score version "}
            <span className="mono">{snapshot.score_version}</span>
          </p>
        </div>
      ) : (
        <p className="mt-2 text-sm text-[var(--muted)]">
          No overall risk score recorded.
        </p>
      )}
    </div>
  );
}

function OverallRisk({ risk }: { risk: RiskComparison }) {
  return (
    <div className="space-y-3">
      <div className="grid gap-3 md:grid-cols-2">
        <OverallRiskSide label="Before" snapshot={risk.before} />
        <OverallRiskSide label="After" snapshot={risk.after} />
      </div>
      <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] px-4 py-3 text-sm">
        {risk.delta !== null ? (
          <>
            <p>
              {"Delta (AFTER − BEFORE): "}
              <span className="mono font-semibold">{formatDelta(risk.delta)}</span>
            </p>
            <p className="mt-1 text-[var(--muted)]">{deltaSentence(risk.delta)}</p>
          </>
        ) : risk.unavailableReason === "version_mismatch" ? (
          <p className="text-[var(--warn)]">
            Cannot compare risk scores: risk score versions differ.
          </p>
        ) : (
          <p className="text-[var(--muted)]">No comparable risk score.</p>
        )}
      </div>
    </div>
  );
}

function RemainingCard({
  item,
  beforeEvidence,
  afterEvidence,
}: {
  item: RemainingFinding;
  beforeEvidence: EvidenceLookup;
  afterEvidence: EvidenceLookup;
}) {
  const { before, after } = item;
  const descriptionDiffers = (before.description ?? "") !== (after.description ?? "");

  return (
    <li className="surface-panel min-w-0 space-y-4 rounded-2xl p-4">
      <FindingHeader
        finding={after}
        badge={<StatusBadge label="Remaining" tone="warn" />}
      />

      <dl className="grid gap-2 text-sm sm:grid-cols-2">
        <Field label="Before severity">
          <SeverityBadge severity={before.severity} />
        </Field>
        <Field label="After severity">
          <SeverityBadge severity={after.severity} />
        </Field>
        <Field label="Before confidence">
          <span className="mono">{confidenceText(before.confidence)}</span>
        </Field>
        <Field label="After confidence">
          <span className="mono">{confidenceText(after.confidence)}</span>
        </Field>
      </dl>

      <div className="space-y-2">
        <SubHeading>Before description</SubHeading>
        <p className="text-sm text-[var(--text)]/90">
          {before.description ?? "No description recorded."}
        </p>
        {descriptionDiffers ? (
          <>
            <SubHeading>After description</SubHeading>
            <p className="text-sm text-[var(--text)]/90">
              {after.description ?? "No description recorded."}
            </p>
          </>
        ) : null}
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <LinkedEvidenceFor finding={before} lookup={beforeEvidence} label="Before evidence" />
        <LinkedEvidenceFor finding={after} lookup={afterEvidence} label="After evidence" />
      </div>

      <FindingRiskComparison risk={item.risk} />
      <Remediation text={after.remediation} />
    </li>
  );
}

function NewCard({
  item,
  afterEvidence,
}: {
  item: NewFinding;
  afterEvidence: EvidenceLookup;
}) {
  const { after } = item;
  return (
    <li className="surface-panel min-w-0 space-y-4 rounded-2xl p-4">
      <FindingHeader
        finding={after}
        badge={
          <>
            <StatusBadge label="New" tone="danger" />
            <SeverityBadge severity={after.severity} />
          </>
        }
      />
      <dl className="grid gap-2 text-sm sm:grid-cols-2">
        <Field label="Confidence">
          <span className="mono">{confidenceText(after.confidence)}</span>
        </Field>
        <Field label="Before coverage">
          <span className="mono text-xs">{describeCoverage(item.beforeCoverage)}</span>
        </Field>
      </dl>
      <p className="text-sm text-[var(--text)]/90">
        {after.description ?? "No description recorded."}
      </p>
      <LinkedEvidenceFor finding={after} lookup={afterEvidence} label="After evidence" />
      <RiskSide label="After risk" snapshot={item.risk} />
      <Remediation text={after.remediation} />
    </li>
  );
}

function ResolvedCard({
  item,
  beforeEvidence,
}: {
  item: ResolvedFinding;
  beforeEvidence: EvidenceLookup;
}) {
  const { before } = item;
  return (
    <li className="surface-panel min-w-0 space-y-4 rounded-2xl p-4">
      <FindingHeader
        finding={before}
        badge={<StatusBadge label="Resolved" tone="ok" />}
      />
      <dl className="grid gap-2 text-sm sm:grid-cols-2">
        <Field label="Before severity">
          <SeverityBadge severity={before.severity} />
        </Field>
        <Field label="After coverage">
          <span className="mono text-xs">{describeCoverage(item.coverage)}</span>
        </Field>
      </dl>
      <div className="rounded-xl border border-[var(--ok)]/30 bg-[var(--ok)]/[0.07] px-3.5 py-3 text-sm">
        <SubHeading>Resolution basis</SubHeading>
        <p className="mt-1 text-[var(--text)]">
          Finding was not reported in the AFTER assessment and the check was
          evaluated.
        </p>
      </div>
      <LinkedEvidenceFor finding={before} lookup={beforeEvidence} label="Before evidence" />
    </li>
  );
}

function unconfirmedExplanation(item: UnconfirmedFinding): string {
  switch (item.reason) {
    case "NOT_EVALUATED":
      return "Not reported in the AFTER assessment, but the AFTER assessment did not evaluate this check for this target and port.";
    case "NOT_APPLICABLE":
      return "Not reported in the AFTER assessment, where this check was recorded as not applicable (its precondition was not observed). This is not a resolution.";
    case "COVERAGE_NOT_RECORDED":
      return "Not reported in the AFTER assessment. Coverage was not recorded for the AFTER assessment, so resolution cannot be confirmed.";
    case "NO_COVERAGE_ENTRY":
      return "Not reported in the AFTER assessment. AFTER coverage has no entry for this check and port, so resolution cannot be confirmed.";
    case "UNRECOGNIZED_STATUS":
      return `Not reported in the AFTER assessment. AFTER coverage status "${item.coverage.kind === "entry" ? item.coverage.status : ""}" is not recognized, so resolution cannot be confirmed.`;
  }
}

function UnconfirmedCard({
  item,
  beforeEvidence,
}: {
  item: UnconfirmedFinding;
  beforeEvidence: EvidenceLookup;
}) {
  const { before } = item;
  return (
    <li className="surface-panel min-w-0 space-y-4 rounded-2xl p-4">
      <FindingHeader
        finding={before}
        badge={
          <>
            <StatusBadge label={UNCONFIRMED_LABEL[item.reason]} tone="warn" />
            <StatusBadge label="Resolution not confirmed" tone="neutral" />
          </>
        }
      />
      <dl className="grid gap-2 text-sm sm:grid-cols-2">
        <Field label="Before severity">
          <SeverityBadge severity={before.severity} />
        </Field>
        <Field label="After coverage">
          <span className="mono text-xs">{describeCoverage(item.coverage)}</span>
        </Field>
      </dl>
      <p className="rounded-xl border border-[var(--warn)]/30 bg-[var(--warn)]/[0.07] px-3.5 py-3 text-sm text-[var(--text)]">
        {unconfirmedExplanation(item)}
      </p>
      <LinkedEvidenceFor finding={before} lookup={beforeEvidence} label="Before evidence" />
      <RiskSide label="Before risk" snapshot={item.risk} />
      <Remediation text={before.remediation} />
    </li>
  );
}

function EvidenceSide({
  label,
  items,
}: {
  label: string;
  items: AssessmentEvidence[];
}) {
  return (
    <div className="min-w-0 space-y-2">
      <SubHeading>{label}</SubHeading>
      {items.length ? (
        items.map((item) => (
          <div
            key={item.id}
            className="min-w-0 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="break-words text-xs text-[var(--muted)]">
                {"Source "}
                <span className="mono">{item.evidence_source}</span>
                {" · "}
                {formatGeneratedAt(item.observed_at) ?? "Time not recorded"}
              </p>
              <StatusBadge label={item.result} tone="info" />
            </div>
            <ObservationFields observation={item.observation} hideEmpty />
          </div>
        ))
      ) : (
        <p className="text-sm text-[var(--muted)]">Not recorded in this assessment.</p>
      )}
    </div>
  );
}

function presenceLabel(row: EvidenceRow): string {
  if (row.before.length && row.after.length) return "Recorded in both";
  return row.before.length ? "Before only" : "After only";
}

function resultsText(items: AssessmentEvidence[]): string {
  return items.length ? items.map((item) => item.result).join(", ") : "—";
}

function EvidenceComparison({ rows }: { rows: EvidenceRow[] }) {
  return (
    <ListOrEmpty
      items={rows}
      empty="No evidence recorded in either assessment."
      render={(row) => (
        <li key={row.key}>
          <details className="surface-panel min-w-0 rounded-2xl">
            <summary className="flex cursor-pointer flex-wrap items-center justify-between gap-2 px-4 py-3">
              <span className="min-w-0">
                <span className="mono break-all text-sm font-semibold text-[var(--text)]">
                  {row.checkType}
                </span>
                <span className="mono ml-2 text-xs text-[var(--muted)]">
                  {formatTargetPort(row.target, row.port)}
                </span>
              </span>
              <span className="flex flex-wrap items-center gap-2 text-xs text-[var(--muted)]">
                <span>
                  {"Before "}
                  <span className="mono text-[var(--text)]">{resultsText(row.before)}</span>
                  {" · After "}
                  <span className="mono text-[var(--text)]">{resultsText(row.after)}</span>
                </span>
                <StatusBadge label={presenceLabel(row)} tone="neutral" />
              </span>
            </summary>
            <div className="grid gap-3 border-t border-white/[0.06] p-4 md:grid-cols-2">
              <EvidenceSide label="Before observation" items={row.before} />
              <EvidenceSide label="After observation" items={row.after} />
            </div>
          </details>
        </li>
      )}
    />
  );
}

function Limitations({ comparison }: Props) {
  const warnings = comparison.issues
    .filter((issue) => issue.level === "warning")
    .map((issue) => issue.message);
  return (
    <ul className="list-disc space-y-1.5 rounded-xl border border-[var(--warn)]/25 bg-[var(--warn)]/[0.06] py-3 pl-8 pr-4 text-sm text-[var(--text)]/90">
      {[...warnings, ...STATIC_LIMITATIONS].map((message) => (
        <li key={message}>{message}</li>
      ))}
    </ul>
  );
}

// ---------------------------------------------------------------------------

export function AssessmentComparisonResult({ comparison }: Props) {
  const beforeEvidence = useEvidenceLookup(comparison.before);
  const afterEvidence = useEvidenceLookup(comparison.after);
  const { findings, evidence } = comparison;

  return (
    <div className="space-y-6 animate-fade-in">
      <DetailSection
        title="Comparison status"
        description="Checked from the metadata, status and risk score versions recorded by the backend for both assessments."
      >
        <ComparisonStatus comparison={comparison} />
      </DetailSection>

      {comparison.comparable && findings && evidence ? (
        <>
          <DetailSection
            title="Risk comparison"
            description="Overall risk snapshots recorded by the backend. Values are not recalculated."
          >
            <OverallRisk risk={comparison.risk} />
          </DetailSection>

          <DetailSection
            title="Finding summary"
            description="Findings are matched by finding ID, target and port."
          >
            <div className="grid gap-3 grid-cols-2 lg:grid-cols-4">
              <KpiCard label="Remaining" value={String(findings.remaining.length)} tone="warn" stagger={1} />
              <KpiCard label="New" value={String(findings.added.length)} tone="danger" stagger={2} />
              <KpiCard label="Resolved" value={String(findings.resolved.length)} tone="ok" stagger={3} />
              <KpiCard label="Not confirmed" value={String(findings.unconfirmed.length)} stagger={4} />
            </div>
          </DetailSection>

          <DetailSection
            title="Remaining findings"
            count={findings.remaining.length}
            description="Reported in both assessments. Severity and confidence are shown as recorded; differences are not interpreted."
          >
            <ListOrEmpty
              items={findings.remaining}
              empty="No finding was reported in both assessments."
              render={(item) => (
                <RemainingCard
                  key={item.key}
                  item={item}
                  beforeEvidence={beforeEvidence}
                  afterEvidence={afterEvidence}
                />
              )}
            />
          </DetailSection>

          <DetailSection
            title="New findings"
            count={findings.added.length}
            description="Reported in the AFTER assessment only."
          >
            <ListOrEmpty
              items={findings.added}
              empty="No finding was reported only in the AFTER assessment."
              render={(item) => (
                <NewCard key={item.key} item={item} afterEvidence={afterEvidence} />
              )}
            />
          </DetailSection>

          <DetailSection
            title="Resolved findings"
            count={findings.resolved.length}
            description="Reported in BEFORE, not reported in AFTER, and AFTER coverage shows the check was evaluated for the same target and port."
          >
            <ListOrEmpty
              items={findings.resolved}
              empty="No finding can be confirmed as resolved."
              render={(item) => (
                <ResolvedCard key={item.key} item={item} beforeEvidence={beforeEvidence} />
              )}
            />
          </DetailSection>

          <DetailSection
            title="Resolution not confirmed"
            count={findings.unconfirmed.length}
            description="Reported in BEFORE and not reported in AFTER, but AFTER coverage does not confirm the check was evaluated."
          >
            <ListOrEmpty
              items={findings.unconfirmed}
              empty="No unconfirmed BEFORE-only findings."
              render={(item) => (
                <UnconfirmedCard key={item.key} item={item} beforeEvidence={beforeEvidence} />
              )}
            />
          </DetailSection>

          <DetailSection
            title="Evidence comparison"
            count={evidence.length}
            description="Evidence grouped by check type, target and port. Expand a row to see the before and after observations side by side."
          >
            <EvidenceComparison rows={evidence} />
          </DetailSection>
        </>
      ) : null}

      <DetailSection title="Comparison limitations">
        <Limitations comparison={comparison} />
      </DetailSection>
    </div>
  );
}
