type Props = {
  findingsCount: number;
  highestLevel: string | null;
  highestScore: number | null;
};

export function SecuritySummary({
  findingsCount,
  highestLevel,
  highestScore,
}: Props) {
  const isHigh =
    (highestLevel || "").toUpperCase() === "HIGH" ||
    (highestLevel || "").toUpperCase() === "CRITICAL";

  return (
    <div className="surface-panel relative overflow-hidden rounded-2xl p-5 animate-rise-in stagger-5">
      <div
        className={`pointer-events-none absolute -right-8 -top-10 h-36 w-36 rounded-full blur-3xl ${
          isHigh ? "bg-[var(--danger)]/20" : "bg-[var(--accent)]/15"
        }`}
        aria-hidden
      />
      <p className="text-[11px] font-medium tracking-[0.14em] text-[var(--muted)] uppercase">
        Security Status
      </p>
      <p
        className={`font-display mt-2 text-3xl font-semibold tracking-tight ${
          isHigh ? "text-[var(--danger)]" : "text-[var(--text)]"
        }`}
      >
        {highestLevel
          ? `${highestLevel} RISK`
          : findingsCount === 0
            ? "No findings"
            : "Status unavailable"}
      </p>
      <p className="mt-2 max-w-2xl text-sm text-[var(--muted)]">
        {findingsCount > 0
          ? `${findingsCount} security finding${findingsCount === 1 ? "" : "s"} require attention.`
          : "No security findings are currently reported."}
        {highestScore != null ? ` Highest dynamic risk: ${highestScore}.` : ""}
      </p>
    </div>
  );
}
