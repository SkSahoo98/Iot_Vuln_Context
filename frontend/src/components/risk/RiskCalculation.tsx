import { useState } from "react";
import type { RiskItem } from "../../api/types";
import { formatFactorLabel, severityBadgeClass } from "../../lib/format";
import { contextContributionPoints } from "../../lib/riskPresentation";

type Props = {
  item: RiskItem;
};

export function RiskCalculation({ item }: Props) {
  const [open, setOpen] = useState(false);
  const contextPoints = contextContributionPoints(item);

  return (
    <div className="surface-panel rounded-2xl">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="flex w-full items-center justify-between px-4 py-3.5 text-left text-sm"
        aria-expanded={open}
      >
        <span className="font-medium">Technical calculation details</span>
        <span className="text-[var(--muted)]">{open ? "Hide" : "Show"}</span>
      </button>

      {open ? (
        <div className="space-y-4 border-t border-white/[0.06] px-4 py-4">
          <p className="text-sm text-[var(--muted)]">
            How is this score calculated? Base severity contributes half of the
            score scale; IoT context contributes the remainder. The AI model
            does not calculate or change these values.
          </p>

          <dl className="grid gap-2 text-sm sm:grid-cols-2">
            <div className="flex justify-between gap-3 rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2">
              <dt className="text-[var(--muted)]">Base Severity Contribution</dt>
              <dd className="mono">{item.base_severity_contribution}</dd>
            </div>
            <div className="flex justify-between gap-3 rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2">
              <dt className="text-[var(--muted)]">Context contribution</dt>
              <dd className="mono">{contextPoints} points</dd>
            </div>
            <div className="flex justify-between gap-3 rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2 sm:col-span-2">
              <dt className="text-[var(--muted)]">Context score</dt>
              <dd className="mono">{item.context_score.toFixed(2)}</dd>
            </div>
            <div className="flex justify-between gap-3 rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2 sm:col-span-2">
              <dt className="text-[var(--muted)]">Calculation Method</dt>
              <dd className="mono text-right text-xs sm:text-sm">
                {item.calculation_method}
              </dd>
            </div>
            <div className="flex justify-between gap-3 rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2 sm:col-span-2">
              <dt className="text-[var(--muted)]">Score Version</dt>
              <dd className="mono">{item.score_version}</dd>
            </div>
          </dl>

          <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
            <p className="mb-2 text-xs text-[var(--muted)]">
              Final authoritative score
            </p>
            <p className="mono text-2xl font-semibold">{item.score}</p>
            <span
              className={`mt-1 inline-flex rounded border px-2 py-0.5 text-xs ${severityBadgeClass(
                item.risk_level,
              )}`}
            >
              {item.risk_level}
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="text-[var(--muted)]">
                <tr>
                  <th className="py-2 pr-3 font-medium">Factor</th>
                  <th className="py-2 pr-3 font-medium">Weight</th>
                  <th className="py-2 pr-3 font-medium">Value</th>
                  <th className="py-2 font-medium">Contribution</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(item.factor_contributions).map(([key, row]) => (
                  <tr key={key} className="border-t border-white/[0.05]">
                    <td className="py-2 pr-3">{formatFactorLabel(key)}</td>
                    <td className="py-2 pr-3 mono">
                      {(row.weight * 100).toFixed(0)}%
                    </td>
                    <td className="py-2 pr-3 mono">{row.normalized_value}</td>
                    <td className="py-2 mono">{row.contribution_to_100}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </div>
  );
}
