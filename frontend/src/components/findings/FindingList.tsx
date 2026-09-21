import type { Finding, RiskItem } from "../../api/types";
import { evidenceDisplay } from "../../lib/format";
import { SeverityBadge } from "../common/SeverityBadge";

type Props = {
  findings: Finding[];
  riskItems: RiskItem[];
  selectedFindingType: string | null;
  onSelect: (findingType: string) => void;
};

export function FindingList({
  findings,
  riskItems,
  selectedFindingType,
  onSelect,
}: Props) {
  return (
    <div className="space-y-3">
      {findings.map((finding, index) => {
        const risk = riskItems.find(
          (item) => item.finding_type === finding.finding_type,
        );
        const selected = selectedFindingType === finding.finding_type;
        const service = evidenceDisplay(finding.evidence, "service");

        return (
          <article
            key={finding.finding_type}
            className={`surface-panel relative overflow-hidden rounded-2xl p-4 transition duration-300 animate-rise-in stagger-${Math.min(index + 1, 4)} ${
              selected
                ? "border-[var(--accent)]/50 shadow-[0_0_36px_rgba(62,196,240,0.12)] ring-1 ring-[var(--accent)]/25"
                : "hover:border-[var(--accent)]/30"
            }`}
          >
            {selected ? (
              <div
                className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-[var(--accent)]/70 to-transparent"
                aria-hidden
              />
            ) : null}

            <div className="flex items-start gap-4">
              <div className="min-w-0 flex-1">
                <SeverityBadge severity={finding.severity} />
                <h3 className="font-display mt-2 text-base font-semibold leading-snug">
                  {finding.title}
                </h3>
                <p className="mt-1 text-sm leading-relaxed text-[var(--muted)]">
                  {finding.description}
                </p>
                <p className="mt-2 text-xs text-[var(--muted)]">
                  Service:{" "}
                  <span className="mono text-[var(--text)]">{service}</span>
                  {" · "}
                  <span className="mono">{finding.finding_type}</span>
                </p>
              </div>

              <div className="glass-inset w-[4.75rem] shrink-0 rounded-2xl px-2.5 py-2.5 text-center sm:w-[5.25rem]">
                <p className="text-[10px] text-[var(--muted)] uppercase tracking-[0.12em]">
                  Risk
                </p>
                <p className="mono mt-0.5 text-lg font-semibold leading-none">
                  {risk ? risk.score : "—"}
                </p>
                <p className="mt-1 text-[11px] leading-none text-[var(--muted)]">
                  {risk?.risk_level ?? ""}
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={() => onSelect(finding.finding_type)}
              className="btn-soft mt-4 rounded-full border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-3.5 py-1.5 text-xs font-medium text-[var(--accent)] hover:bg-[var(--accent)]/20"
            >
              View details
            </button>
          </article>
        );
      })}
    </div>
  );
}
