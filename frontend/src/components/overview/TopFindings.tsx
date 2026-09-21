import type { Finding, RiskItem } from "../../api/types";
import { SeverityBadge } from "../common/SeverityBadge";

type Props = {
  findings: Finding[];
  riskItems: RiskItem[];
  onViewAll: () => void;
  onOpenFinding: (findingType: string) => void;
};

export function TopFindings({
  findings,
  riskItems,
  onViewAll,
  onOpenFinding,
}: Props) {
  const top = findings.slice(0, 2);

  return (
    <div className="surface-panel rounded-2xl p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <p className="font-display text-sm font-semibold">Top findings</p>
        <button
          type="button"
          onClick={onViewAll}
          className="btn-soft text-xs text-[var(--accent)] hover:underline"
        >
          View all findings →
        </button>
      </div>
      <div className="space-y-2">
        {top.map((finding, index) => {
          const risk = riskItems.find(
            (item) => item.finding_type === finding.finding_type,
          );
          return (
            <button
              key={finding.finding_type}
              type="button"
              onClick={() => onOpenFinding(finding.finding_type)}
              className={`flex w-full items-start justify-between gap-3 rounded-xl border border-[var(--border)] bg-[var(--bg-elevated)]/80 px-3 py-3 text-left transition duration-200 hover:-translate-y-0.5 hover:border-[var(--accent)]/40 hover:bg-[var(--bg-panel-hover)] animate-rise-in stagger-${index + 1}`}
            >
              <div>
                <div className="mb-1">
                  <SeverityBadge severity={finding.severity} />
                </div>
                <p className="text-sm font-medium">{finding.title}</p>
              </div>
              <p className="shrink-0 mono text-sm text-[var(--muted)]">
                {risk ? `Risk ${risk.score}` : "Risk —"}
              </p>
            </button>
          );
        })}
      </div>
    </div>
  );
}
