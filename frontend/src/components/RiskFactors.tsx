import type { RiskItem } from "../api/types";
import { presentRiskFactor } from "../lib/riskPresentation";

type Props = {
  item: RiskItem;
};

export function RiskFactors({ item }: Props) {
  const entries = Object.entries(item.factors);

  return (
    <div className="space-y-4">
      <div>
        <p className="text-[11px] tracking-[0.12em] text-[var(--muted)] uppercase">
          Why is the risk elevated?
        </p>
        <p className="mt-1 text-sm text-[var(--muted)]">
          These factors adjust the vulnerability&apos;s risk according to the
          IoT environment.
        </p>
      </div>

      <div className="space-y-3">
        {entries.map(([key, value]) => {
          const contribution = item.factor_contributions[key];
          const presentation = presentRiskFactor(key, value, item.evidence);
          const barPct = Math.max(0, Math.min(100, value * 100));

          return (
            <div
              key={key}
              className="rounded-xl border border-white/[0.06] bg-white/[0.02] px-3.5 py-3"
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="text-sm font-medium">{presentation.label}</p>
                  <p
                    className={`mt-0.5 text-sm ${
                      presentation.state === "Needs attention"
                        ? "text-[var(--warn)]"
                        : "text-[var(--text)]"
                    }`}
                  >
                    {presentation.state}
                  </p>
                  <p className="mt-0.5 text-sm text-[var(--muted)]">
                    {presentation.detail}
                  </p>
                </div>
                {contribution ? (
                  <p className="mono shrink-0 text-sm font-medium text-[var(--text)]">
                    +{contribution.contribution_to_100.toFixed(1)}
                  </p>
                ) : null}
              </div>

              <div
                className="mt-2.5 h-1.5 overflow-hidden rounded-full bg-[var(--bg-elevated)]"
                aria-hidden
              >
                <div
                  className="h-full rounded-full bg-[var(--danger)]/70"
                  style={{ width: `${barPct}%` }}
                />
              </div>

              <p className="mt-2 text-[11px] text-[var(--muted)]">
                Internal value:{" "}
                <span className="mono">{value.toFixed(2)}</span>
                {contribution ? (
                  <>
                    {" · "}
                    Risk contribution:{" "}
                    <span className="mono">
                      +{contribution.contribution_to_100.toFixed(1)}
                    </span>
                  </>
                ) : null}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
