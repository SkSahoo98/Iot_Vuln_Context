import type { AssessmentFinding, RiskSnapshot } from "../../api/types";
import { formatFactorLabel, formatGeneratedAt } from "../../lib/format";
import { EmptyState } from "../common/EmptyState";
import { SeverityBadge } from "../common/SeverityBadge";
import { StatusBadge } from "../common/StatusBadge";
import {
  formatJsonValue,
  formatNumber,
  formatTargetPort,
  isPlainObject,
  provenanceOf,
} from "./detailFormat";

type Props = {
  snapshots: RiskSnapshot[];
  findings: AssessmentFinding[];
};

const MODEL_LIMITATIONS_KEY = "model_limitations";

function SnapshotSummary({ snapshot }: { snapshot: RiskSnapshot }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div>
        <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-[var(--muted)]">
          Risk score
        </p>
        <p className="mt-1 flex items-baseline gap-2">
          <span className="mono text-3xl font-semibold">
            {formatNumber(snapshot.score)}
          </span>
          <span className="text-sm text-[var(--muted)]">/ 100</span>
        </p>
      </div>
      <dl className="grid min-w-0 flex-1 gap-2 text-sm sm:grid-cols-2">
        <div className="flex justify-between gap-3 rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2">
          <dt className="text-[var(--muted)]">Risk level</dt>
          <dd>
            <SeverityBadge severity={snapshot.risk_level} />
          </dd>
        </div>
        <div className="flex justify-between gap-3 rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2">
          <dt className="text-[var(--muted)]">Base severity</dt>
          <dd>
            {snapshot.base_severity ? (
              <SeverityBadge severity={snapshot.base_severity} />
            ) : (
              <span className="text-[var(--muted)]">Not recorded</span>
            )}
          </dd>
        </div>
        <div className="flex justify-between gap-3 rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2">
          <dt className="text-[var(--muted)]">Context score</dt>
          <dd className="mono">{formatNumber(snapshot.context_score)}</dd>
        </div>
        <div className="flex justify-between gap-3 rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2">
          <dt className="text-[var(--muted)]">Score version</dt>
          <dd className="mono">{snapshot.score_version}</dd>
        </div>
        <div className="flex justify-between gap-3 rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2 sm:col-span-2">
          <dt className="text-[var(--muted)]">Recorded</dt>
          <dd className="mono">
            {formatGeneratedAt(snapshot.created_at) ?? "Not recorded"}
          </dd>
        </div>
      </dl>
    </div>
  );
}

function FactorTable({ snapshot }: { snapshot: RiskSnapshot }) {
  const contributions = snapshot.factor_contributions ?? {};
  const context = snapshot.context_inputs ?? {};
  const factorKeys = [
    ...Object.keys(contributions),
    ...Object.keys(context).filter(
      (key) =>
        key !== MODEL_LIMITATIONS_KEY &&
        !(key in contributions) &&
        isPlainObject(context[key]),
    ),
  ];

  if (factorKeys.length === 0) {
    return (
      <p className="text-sm text-[var(--muted)]">
        No factor contributions recorded for this snapshot.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-white/[0.06]">
      <table className="min-w-[860px] w-full text-left text-sm">
        <thead className="border-b border-white/[0.06] text-[var(--muted)]">
          <tr>
            <th className="px-3 py-2.5 text-[11px] font-medium uppercase tracking-[0.1em]">Factor</th>
            <th className="px-3 py-2.5 text-[11px] font-medium uppercase tracking-[0.1em]">Weight</th>
            <th className="px-3 py-2.5 text-[11px] font-medium uppercase tracking-[0.1em]">Normalized value</th>
            <th className="px-3 py-2.5 text-[11px] font-medium uppercase tracking-[0.1em]">Contribution / 100</th>
            <th className="px-3 py-2.5 text-[11px] font-medium uppercase tracking-[0.1em]">Context input</th>
            <th className="px-3 py-2.5 text-[11px] font-medium uppercase tracking-[0.1em]">Provenance</th>
            <th className="px-3 py-2.5 text-[11px] font-medium uppercase tracking-[0.1em]">Notes</th>
          </tr>
        </thead>
        <tbody>
          {factorKeys.map((key) => {
            const row: unknown = contributions[key];
            const rawInput = context[key];
            const factor: Record<string, unknown> = isPlainObject(row) ? row : {};
            const input: Record<string, unknown> = isPlainObject(rawInput)
              ? rawInput
              : {};
            const provenance = provenanceOf(input.source);
            const notes = [input.derivation, input.limitation].filter(
              (value): value is string =>
                typeof value === "string" && value.length > 0,
            );

            return (
              <tr key={key} className="border-t border-white/[0.04] align-top">
                <td className="px-3 py-2.5 font-medium">{formatFactorLabel(key)}</td>
                <td className="px-3 py-2.5 mono">{formatNumber(factor.weight)}</td>
                <td className="px-3 py-2.5 mono">
                  {formatNumber(factor.normalized_value)}
                </td>
                <td className="px-3 py-2.5 mono">
                  {formatNumber(factor.contribution_to_100)}
                </td>
                <td className="px-3 py-2.5 mono">
                  {"value" in input ? formatJsonValue(input.value) : "Not recorded"}
                </td>
                <td className="px-3 py-2.5">
                  {typeof input.source === "string" ? (
                    <div className="space-y-1">
                      {provenance ? (
                        <StatusBadge label={provenance.label} tone={provenance.tone} />
                      ) : null}
                      <p className="mono text-xs text-[var(--muted)]">{input.source}</p>
                    </div>
                  ) : (
                    <span className="text-[var(--muted)]">Not recorded</span>
                  )}
                </td>
                <td className="px-3 py-2.5 text-xs text-[var(--muted)]">
                  {notes.length ? notes.join(" · ") : "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function ModelLimitations({ snapshot }: { snapshot: RiskSnapshot }) {
  const value = snapshot.context_inputs?.[MODEL_LIMITATIONS_KEY];
  const limitations = Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
  if (!limitations.length) return null;

  return (
    <div className="rounded-xl border border-[var(--warn)]/25 bg-[var(--warn)]/[0.06] px-3.5 py-3">
      <p className="text-[11px] font-medium uppercase tracking-[0.1em] text-[var(--warn)]">
        Model limitations · reported by backend
      </p>
      <ul className="mt-1.5 list-disc space-y-1 pl-5 text-sm text-[var(--text)]/90">
        {limitations.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

export function AssessmentRiskView({ snapshots, findings }: Props) {
  if (snapshots.length === 0) {
    return <EmptyState message="No risk snapshots recorded for this assessment." />;
  }

  const overall = snapshots.find((snapshot) => snapshot.finding_ref === null);
  const perFinding = snapshots.filter((snapshot) => snapshot.finding_ref !== null);
  const findingById = new Map(findings.map((finding) => [finding.id, finding]));

  return (
    <div className="space-y-4">
      {overall ? (
        <div className="surface-panel space-y-4 rounded-2xl p-4">
          <h4 className="font-display text-sm font-semibold sm:text-base">
            Overall assessment risk
          </h4>
          <SnapshotSummary snapshot={overall} />
          <FactorTable snapshot={overall} />
          <ModelLimitations snapshot={overall} />
        </div>
      ) : (
        <p className="text-sm text-[var(--muted)]">
          No overall risk snapshot was recorded for this assessment.
        </p>
      )}

      {perFinding.length ? (
        <div className="space-y-3">
          <h4 className="font-display text-sm font-semibold sm:text-base">
            Per-finding risk snapshots
          </h4>
          <ul className="space-y-3">
            {perFinding.map((snapshot) => {
              const finding = snapshot.finding_ref
                ? findingById.get(snapshot.finding_ref)
                : undefined;

              return (
                <li key={snapshot.id} className="surface-panel space-y-4 rounded-2xl p-4">
                  <p className="text-sm">
                    {finding ? (
                      <>
                        <span className="font-medium">{finding.title}</span>
                        <span className="text-[var(--muted)]">
                          {" · "}
                          <span className="mono">{finding.finding_id}</span>
                          {" · "}
                          <span className="mono">
                            {formatTargetPort(finding.target, finding.port)}
                          </span>
                        </span>
                      </>
                    ) : (
                      <span className="mono text-[var(--muted)]">
                        Finding {snapshot.finding_ref}
                      </span>
                    )}
                  </p>
                  <SnapshotSummary snapshot={snapshot} />
                  <details className="rounded-xl border border-white/[0.06] bg-white/[0.02]">
                    <summary className="cursor-pointer px-3 py-2 text-xs font-medium text-[var(--muted)] hover:text-[var(--text)]">
                      Factor contributions and provenance
                    </summary>
                    <div className="space-y-3 border-t border-white/[0.06] p-3">
                      <FactorTable snapshot={snapshot} />
                      <ModelLimitations snapshot={snapshot} />
                    </div>
                  </details>
                </li>
              );
            })}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
