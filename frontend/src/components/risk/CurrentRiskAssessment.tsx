import type { RiskItem } from "../../api/types";
import { formatFindingTypeLabel } from "../../lib/format";
import { formatFindingPlainExplanation } from "../../lib/riskPresentation";
import { SeverityBadge } from "../common/SeverityBadge";

type Props = {
  items: RiskItem[];
  selectedFindingType: string | null;
  onSelect: (findingType: string) => void;
};

export function CurrentRiskAssessment({
  items,
  selectedFindingType,
  onSelect,
}: Props) {
  return (
    <section className="space-y-3" aria-labelledby="current-risk-heading">
      <div>
        <h2
          id="current-risk-heading"
          className="font-display text-base font-semibold"
        >
          Current Risk Assessment
        </h2>
        <p className="mt-1 text-sm text-[var(--muted)]">
          Problems found — context-aware risk for each evidence-backed finding.
        </p>
      </div>

      <div className="grid gap-3">
        {items.map((item) => {
          const selected = selectedFindingType === item.finding_type;
          const hasEvidence = Object.keys(item.evidence ?? {}).length > 0;

          return (
            <article
              key={item.finding_type}
              className={`surface-panel rounded-2xl p-4 transition duration-200 ${
                selected
                  ? "border-[var(--accent)]/50 ring-1 ring-[var(--accent)]/25"
                  : ""
              }`}
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <h3 className="font-display text-sm font-semibold leading-snug sm:text-base">
                    {formatFindingTypeLabel(item.finding_type)}
                  </h3>
                  <p className="mt-1.5 text-sm text-[var(--muted)]">
                    {formatFindingPlainExplanation(item.finding_type)}
                  </p>
                </div>
                <SeverityBadge severity={item.risk_level} />
              </div>

              <div className="mt-3 flex flex-wrap items-baseline gap-2">
                <span className="text-sm text-[var(--muted)]">Risk score</span>
                <span className="mono text-xl font-semibold">{item.score}</span>
                <span className="text-sm text-[var(--muted)]">/ 100</span>
              </div>

              <p className="mt-2 text-xs text-[var(--muted)]">
                {hasEvidence
                  ? "Evidence-backed finding"
                  : "Finding assessed by risk engine"}
                {selected ? " · Showing details below" : ""}
              </p>

              <button
                type="button"
                onClick={() => onSelect(item.finding_type)}
                aria-pressed={selected}
                className="btn-soft mt-4 rounded-full border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-3.5 py-1.5 text-xs font-medium text-[var(--accent)] hover:bg-[var(--accent)]/20"
              >
                {selected
                  ? "Viewing detailed risk information"
                  : "View detailed risk information"}
              </button>
            </article>
          );
        })}
      </div>
    </section>
  );
}
