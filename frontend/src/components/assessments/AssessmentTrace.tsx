import type { ReactNode } from "react";
import type { AssessmentDetail, RiskSnapshot } from "../../api/types";
import { formatGeneratedAt } from "../../lib/format";
import {
  EVIDENCE_NOT_AVAILABLE,
  buildAssessmentTrace,
  type FindingTrace,
  type TraceFactor,
} from "../../lib/traceability";
import { EmptyState } from "../common/EmptyState";
import { SeverityBadge } from "../common/SeverityBadge";
import { StatusBadge } from "../common/StatusBadge";
import { formatNumber, formatTargetPort } from "./detailFormat";

function Step({ label, last, children }: { label: string; last?: boolean; children: ReactNode }) {
  return (
    <li className="relative pl-6">
      {last ? null : (
        <span aria-hidden className="absolute left-[5px] top-4 h-[calc(100%-0.25rem)] w-px bg-white/10" />
      )}
      <span
        aria-hidden
        className="absolute left-0 top-1.5 h-[11px] w-[11px] rounded-full border border-[var(--accent)]/50 bg-[var(--accent-soft)]"
      />
      <p className="text-[11px] font-medium uppercase tracking-[0.1em] text-[var(--muted)]">{label}</p>
      <div className="mt-1 min-w-0 space-y-1 break-words pb-4 text-sm">{children}</div>
    </li>
  );
}

function RiskValue({ snapshot }: { snapshot: RiskSnapshot }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <span className="mono text-base font-semibold">{formatNumber(snapshot.score)}</span>
      <SeverityBadge severity={snapshot.risk_level} />
    </span>
  );
}

export function FactorLine({ factor }: { factor: TraceFactor }) {
  return (
    <div data-trace-factor={factor.factor} className="rounded-xl border border-white/[0.06] bg-white/[0.02] px-3 py-2">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <span className="font-medium">{factor.label}</span>
        <span className="mono text-sm">
          {factor.contribution === null ? "Not recorded" : `+${formatNumber(factor.contribution)} points`}
        </span>
      </div>
      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[var(--muted)]">
        <span>
          Normalized value{" "}
          <span className="mono text-[var(--text)]">{formatNumber(factor.normalizedValue)}</span>
        </span>
        <span className="inline-flex items-center gap-1.5">
          Basis
          {factor.provenance ? (
            <StatusBadge label={factor.provenance.label} tone={factor.provenance.tone} />
          ) : null}
          <span className="mono">{factor.source ?? "Not recorded"}</span>
        </span>
      </div>
      {factor.note ? <p className="mt-1 text-xs text-[var(--muted)]">{factor.note}</p> : null}
    </div>
  );
}

function FindingChain({ item, overall }: { item: FindingTrace; overall: RiskSnapshot | null }) {
  const { finding, evidence } = item;
  return (
    <ol className="mt-3">
      <Step label="Finding">
        <p>
          <span className="mono text-xs text-[var(--muted)]">{finding.finding_id}</span>{" "}
          {finding.title}
        </p>
        <p className="text-xs text-[var(--muted)]">
          Recorded by the deterministic assessment engine on{" "}
          <span className="mono">{formatTargetPort(finding.target, finding.port)}</span>.
        </p>
      </Step>

      <Step label="Observed evidence">
        {evidence.kind === "linked" ? (
          <div data-trace-evidence={evidence.record.id} className="space-y-0.5">
            <p>
              <span className="mono">{evidence.record.check_type}</span>
              {" · "}
              <span className="mono">{evidence.record.result}</span>
            </p>
            <p className="text-xs text-[var(--muted)]">
              Source <span className="mono">{evidence.record.evidence_source}</span>
              {" · "}
              <span className="mono">
                {formatTargetPort(evidence.record.target, evidence.record.port)}
              </span>
              {" · "}
              {formatGeneratedAt(evidence.record.observed_at) ?? "Time not recorded"}
            </p>
          </div>
        ) : (
          <p data-trace-evidence="none" className="text-[var(--muted)]">
            {EVIDENCE_NOT_AVAILABLE}
          </p>
        )}
      </Step>

      <Step label="Severity">
        <p className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <span className="text-xs text-[var(--muted)]">Set by the check's deterministic rule.</span>
        </p>
      </Step>

      <Step label="Risk factor">
        {item.factorLinks === "not_recorded" ? (
          <p className="text-[var(--muted)]">Risk factor links are not recorded for this check.</p>
        ) : item.linkedFactors.length ? (
          <div className="space-y-2">
            {item.linkedFactors.map((factor) => (
              <FactorLine key={factor.factor} factor={factor} />
            ))}
          </div>
        ) : (
          <p className="text-[var(--muted)]">
            The backend risk rules do not link this finding to a specific risk factor.
          </p>
        )}
        {item.otherFactors.length ? (
          <details className="group mt-2">
            <summary className="flex min-h-11 cursor-pointer list-none items-center gap-2 text-xs font-medium text-[var(--accent)]">
              <span aria-hidden className="transition-transform group-open:rotate-90">›</span>
              Other factors in this risk result ({item.otherFactors.length})
            </summary>
            <div className="mt-1 space-y-2">
              {item.otherFactors.map((factor) => (
                <FactorLine key={factor.factor} factor={factor} />
              ))}
            </div>
          </details>
        ) : null}
        {item.factorSnapshot === "overall" ? (
          <p className="text-xs text-[var(--muted)]">
            Factor values are from this check's overall risk result.
          </p>
        ) : null}
      </Step>

      <Step label="Finding risk">
        {item.findingRisk ? (
          <>
            <RiskValue snapshot={item.findingRisk} />
            <p className="text-xs text-[var(--muted)]">
              Recorded snapshot · base severity{" "}
              <span className="mono">{item.findingRisk.base_severity ?? "Not recorded"}</span> · context
              score <span className="mono">{formatNumber(item.findingRisk.context_score)}</span>
            </p>
          </>
        ) : (
          <p className="text-[var(--muted)]">No risk snapshot is recorded for this finding.</p>
        )}
      </Step>

      <Step label="Overall risk" last>
        {overall ? (
          <>
            <RiskValue snapshot={overall} />
            <p className="text-xs text-[var(--muted)]">
              {item.setsOverall
                ? "This finding's risk is the overall risk: the backend uses the highest finding risk."
                : "The backend uses the highest finding risk in this check as the overall risk."}{" "}
              <span className="mono">{overall.score_version}</span>
            </p>
          </>
        ) : (
          <p className="text-[var(--muted)]">No overall risk was recorded for this check.</p>
        )}
      </Step>
    </ol>
  );
}

export function AssessmentTrace({ detail }: { detail: AssessmentDetail }) {
  const trace = buildAssessmentTrace(detail);
  if (!trace.findings.length) {
    return <EmptyState message="No findings recorded for this assessment, so there is nothing to trace." />;
  }
  return (
    <div className="space-y-2">
      {trace.findings.map((item, index) => (
        <details
          key={item.finding.id}
          data-trace-finding={item.finding.finding_id}
          open={index === 0}
          className="group rounded-2xl border border-white/[0.06] bg-white/[0.02] px-4"
        >
          <summary className="flex min-h-11 cursor-pointer list-none flex-wrap items-center gap-x-3 gap-y-1 py-2.5">
            <span aria-hidden className="text-[var(--muted)] transition-transform group-open:rotate-90">›</span>
            <SeverityBadge severity={item.finding.severity} />
            <span className="min-w-0 flex-1 break-words text-sm font-medium">{item.finding.title}</span>
            <span className="mono w-full pl-5 text-xs text-[var(--muted)] sm:w-auto sm:pl-0">
              {item.finding.finding_id}
              {item.finding.port === null ? "" : ` :${item.finding.port}`}
            </span>
          </summary>
          <FindingChain item={item} overall={trace.overall} />
        </details>
      ))}
      {trace.modelLimitations.length ? (
        <div className="rounded-xl border border-white/[0.06] px-3 py-2 text-xs text-[var(--muted)]">
          <p className="font-medium">Recorded risk limitations</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-4">
            {trace.modelLimitations.map((text) => (
              <li key={text}>{text}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
