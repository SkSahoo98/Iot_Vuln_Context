import { useId, useState, type ReactNode } from "react";
import type {
  AssessmentEvidence,
  AssessmentFinding,
  RiskSnapshot,
} from "../../api/types";
import { formatConfidence, formatGeneratedAt } from "../../lib/format";
import { resolveAssetIdentity } from "../../lib/assets";
import { SeverityBadge } from "../common/SeverityBadge";
import { StatusBadge } from "../common/StatusBadge";
import { ObservationFields, evidenceAnchorId } from "./AssessmentEvidenceList";
import {
  formatNumber,
  formatTargetPort,
  recordedRemediation,
} from "./detailFormat";

type Props = {
  findings: AssessmentFinding[];
  evidence: AssessmentEvidence[];
  snapshots: RiskSnapshot[];
};

const EVIDENCE_OPEN_BY_DEFAULT = new Set(["HIGH", "CRITICAL"]);

const SEVERITY_ORDER: string[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function locateEvidence(evidenceId: string) {
  const element = document.getElementById(evidenceAnchorId(evidenceId));
  element?.scrollIntoView({ behavior: "smooth", block: "start" });
  element?.focus({ preventScroll: true });
}

function StepHeading({ children }: { children: ReactNode }) {
  return (
    <p className="text-[11px] font-medium uppercase tracking-[0.1em] text-[var(--muted)]">
      {children}
    </p>
  );
}

function LinkedEvidence({
  item,
  defaultOpen,
}: {
  item: AssessmentEvidence;
  defaultOpen: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const panelId = useId();
  const identity = resolveAssetIdentity(item.target);

  return (
    <div className="min-w-0 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="mono break-all text-sm font-semibold text-[var(--text)]">
            {item.check_type}
          </p>
          <p className="mt-0.5 break-words text-xs text-[var(--muted)]">
            <span>Asset: </span>
            <span className="font-medium text-[var(--text)]">{identity.displayName}</span>
            {" · Source "}
            <span className="mono">{item.evidence_source}</span>
            {" · "}
            <span className="mono">{formatTargetPort(item.target, item.port)}</span>
          </p>
        </div>
        <StatusBadge label={item.result} tone="info" />
      </div>

      <div className="mt-2.5 flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
          aria-controls={panelId}
          className="btn-soft rounded-full border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-3 py-1 text-xs font-medium text-[var(--accent)] hover:bg-[var(--accent)]/20"
        >
          {open ? "Hide evidence" : "View evidence"}
        </button>
        <button
          type="button"
          onClick={() => locateEvidence(item.id)}
          aria-label={`Locate ${item.check_type} evidence in the evidence list`}
          className="btn-soft rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs font-medium text-[var(--muted)] hover:text-[var(--text)]"
        >
          Locate in evidence list
        </button>
      </div>

      <div id={panelId} hidden={!open}>
        <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2">
          <div className="flex min-w-0 justify-between gap-3 rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2">
            <dt className="shrink-0 text-[var(--muted)]">Observed</dt>
            <dd className="mono min-w-0 break-all text-right">
              {formatGeneratedAt(item.observed_at) ?? "Not recorded"}
            </dd>
          </div>
          <div className="flex min-w-0 justify-between gap-3 rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2">
            <dt className="shrink-0 text-[var(--muted)]">Evidence ID</dt>
            <dd className="mono min-w-0 break-all text-right text-xs">{item.id}</dd>
          </div>
        </dl>
        <ObservationFields observation={item.observation} hideEmpty />
      </div>
    </div>
  );
}

export function RiskImpact({ snapshot }: { snapshot: RiskSnapshot }) {
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-x-4 gap-y-2 rounded-xl border border-white/[0.06] bg-white/[0.02] px-3 py-2.5">
      <p className="flex items-baseline gap-1.5">
        <span className="mono text-xl font-semibold">
          {formatNumber(snapshot.score)}
        </span>
        <span className="text-xs text-[var(--muted)]">/ 100</span>
      </p>
      <SeverityBadge severity={snapshot.risk_level} />
      <p className="min-w-0 break-words text-xs text-[var(--muted)]">
        {"Base severity "}
        <span className="mono">{snapshot.base_severity ?? "Not recorded"}</span>
        {" · Context score "}
        <span className="mono">{formatNumber(snapshot.context_score)}</span>
        {" · "}
        <span className="mono">{snapshot.score_version}</span>
      </p>
    </div>
  );
}

function FindingCard({
  finding,
  evidenceById,
  snapshots,
}: {
  finding: AssessmentFinding;
  evidenceById: Map<string, AssessmentEvidence>;
  snapshots: RiskSnapshot[];
}) {
  const reference = finding.evidence_reference;
  const linked = reference ? evidenceById.get(reference) : undefined;
  const findingSnapshots = snapshots.filter(
    (snapshot) => snapshot.finding_ref === finding.id,
  );
  const assetIdentity = resolveAssetIdentity(finding.target, { port: finding.port });

  return (
    <article className="surface-panel min-w-0 rounded-2xl p-4 transition-colors">
      {/* Header: Title + Severity */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <span className="font-semibold text-sm text-[var(--text)]">
              {finding.title}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-x-2 text-xs text-[var(--muted)]">
            <span className="font-medium text-sky-400">{assetIdentity.displayName}</span>
            <span>•</span>
            <span className="mono">{formatTargetPort(finding.target, finding.port)}</span>
            <span>•</span>
            <span>{finding.category}</span>
            <span>•</span>
            <StatusBadge label={finding.status} tone="info" />
          </div>
        </div>
        <SeverityBadge severity={finding.severity} />
      </div>

      {/* Description */}
      {finding.description ? (
        <div className="mt-3 rounded-xl border border-white/[0.05] bg-white/[0.015] p-3 text-xs leading-relaxed text-[var(--text)]/90">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)] mb-1">
            Vulnerability Summary
          </p>
          <p>{finding.description}</p>
        </div>
      ) : null}

      {/* Remediation — always visible */}
      <RemediationGuidance finding={finding} />

      {/* Evidence & Risk Traceability Section */}
      <section
        aria-label={`Investigation for ${finding.finding_id}`}
        className="mt-4 min-w-0 space-y-4 border-l-2 border-white/[0.08] pl-3 sm:pl-4"
      >
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[var(--text)]/80">
            Why this finding exists
          </p>
          <p className="mt-0.5 text-xs text-[var(--muted)]">
            Evidence and risk recorded deterministically by the assessment engine.
          </p>
        </div>

        <div className="space-y-2">
          <StepHeading>Evidence supporting this finding</StepHeading>
          {!reference ? (
            <p className="text-sm text-[var(--muted)]">
              Evidence reference not available.
            </p>
          ) : linked ? (
            <LinkedEvidence
              item={linked}
              defaultOpen={EVIDENCE_OPEN_BY_DEFAULT.has(finding.severity)}
            />
          ) : (
            <p className="break-all text-sm text-[var(--warn)]">
              Referenced evidence could not be resolved.{" "}
              <span className="mono text-xs text-[var(--muted)]">{reference}</span>
            </p>
          )}
        </div>

        <div className="space-y-2">
          <StepHeading>Risk impact</StepHeading>
          {findingSnapshots.length ? (
            findingSnapshots.map((snapshot) => (
              <RiskImpact key={snapshot.id} snapshot={snapshot} />
            ))
          ) : (
            <p className="text-sm text-[var(--muted)]">
              Risk impact not available for this finding.
            </p>
          )}
        </div>
      </section>

      {/* Advanced Technical Details — collapsible */}
      <details className="mt-3 rounded-xl border border-white/[0.05] bg-black/20 p-2.5 text-xs text-[var(--muted)]">
        <summary className="cursor-pointer font-medium text-[var(--muted)] hover:text-[var(--text)]">
          Advanced Technical Details
        </summary>
        <div className="mt-2 space-y-1 mono text-[11px] pt-2 border-t border-white/[0.05]">
          <p>Finding ID: {finding.finding_id}</p>
          <p>Database Record ID: {finding.id}</p>
          <p>Finding Type: {finding.finding_type}</p>
          <p>Category: {finding.category}</p>
          <p>Confidence: {finding.confidence === null ? "Not recorded" : formatConfidence(finding.confidence)}</p>
          {finding.evidence_reference ? <p>Evidence Ref: {finding.evidence_reference}</p> : null}
          <p>Created: {formatGeneratedAt(finding.created_at) ?? "Not recorded"}</p>
        </div>
      </details>
    </article>
  );
}

function RemediationGuidance({ finding }: { finding: AssessmentFinding }) {
  const remediation = recordedRemediation(finding.remediation);
  const [checked, setChecked] = useState(false);
  const checklistId = useId();

  return (
    <div
      aria-label={`Remediation guidance for ${finding.finding_id}`}
      className="mt-4 rounded-xl border border-[var(--accent)]/30 bg-[var(--accent)]/[0.04] p-3.5"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className="text-xs font-semibold uppercase tracking-[0.1em] text-[var(--accent)]">
          Recommended Remediation
        </p>
        <p className="text-[11px] text-[var(--muted)]">
          Recorded by the assessment engine
        </p>
      </div>
      {remediation ? (
        <>
          <p className="mt-2 whitespace-pre-wrap text-sm text-[var(--text)]">
            {remediation}
          </p>
          <div className="mt-3 flex items-start gap-2 border-t border-white/[0.06] pt-2.5">
            <input
              id={checklistId}
              type="checkbox"
              checked={checked}
              onChange={(e) => setChecked(e.target.checked)}
              className="mt-0.5 h-3.5 w-3.5 rounded border-white/20 bg-white/5 text-[var(--accent)]"
            />
            <label
              htmlFor={checklistId}
              className="text-xs text-[var(--muted)] select-none cursor-pointer"
            >
              Local checklist — not recorded or verified
            </label>
          </div>
        </>
      ) : (
        <p className="mt-2 text-sm text-[var(--muted)]">No remediation recorded.</p>
      )}
    </div>
  );
}

export function AssessmentFindingList({ findings, evidence, snapshots }: Props) {
  const evidenceById = new Map<string, AssessmentEvidence>(
    evidence.map((item) => [item.id, item]),
  );

  // Group findings by severity
  const groupedBySeverity: Record<string, AssessmentFinding[]> = {};
  for (const sev of SEVERITY_ORDER) {
    groupedBySeverity[sev] = [];
  }
  for (const f of findings) {
    const sev = f.severity?.toUpperCase() || "INFO";
    if (!groupedBySeverity[sev]) groupedBySeverity[sev] = [];
    groupedBySeverity[sev].push(f);
  }

  const activeSeverities = SEVERITY_ORDER.filter(
    (sev) => (groupedBySeverity[sev]?.length ?? 0) > 0,
  );

  return (
    <div className="space-y-6">
      {activeSeverities.map((sev) => {
        const list = groupedBySeverity[sev];
        return (
          <div key={sev} className="space-y-3">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={sev} />
              <span className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
                ({list.length} {list.length === 1 ? "vulnerability" : "vulnerabilities"})
              </span>
            </div>
            <div className="space-y-3">
              {list.map((finding) => (
                <FindingCard
                  key={finding.id}
                  finding={finding}
                  evidenceById={evidenceById}
                  snapshots={snapshots}
                />
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
