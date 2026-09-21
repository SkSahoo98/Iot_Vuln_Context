import { SeverityBadge } from "../common/SeverityBadge";

type Props = {
  highestScore: number | null;
  highestLevel: string | null;
  scoreVersion: string | null;
  findingsAssessed: number;
};

export function RiskOverview({
  highestScore,
  highestLevel,
  scoreVersion,
  findingsAssessed,
}: Props) {
  return (
    <section className="surface-panel rounded-2xl p-5 sm:p-6" aria-labelledby="overall-risk-heading">
      <p
        id="overall-risk-heading"
        className="text-[11px] font-medium tracking-[0.14em] text-[var(--muted)] uppercase"
      >
        Overall IoT Security Risk
      </p>
      <div className="mt-2 flex flex-wrap items-baseline gap-2">
        <p className="mono text-5xl font-semibold text-[var(--danger)]">
          {highestScore ?? "—"}
        </p>
        <p className="text-lg text-[var(--muted)]">/ 100</p>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <SeverityBadge severity={highestLevel} />
        <span className="mono text-xs text-[var(--muted)]">
          {scoreVersion ?? "—"}
        </span>
      </div>
      <p className="mt-3 text-sm text-[var(--text)]">
        {findingsAssessed > 0
          ? `${findingsAssessed} evidence-backed security finding${
              findingsAssessed === 1 ? "" : "s"
            } require attention.`
          : "No evidence-backed security findings require attention."}
      </p>
      <p className="mt-1.5 text-sm text-[var(--muted)]">
        Higher scores indicate greater contextual risk.
      </p>
    </section>
  );
}
