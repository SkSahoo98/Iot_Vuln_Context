const STAGES = [
  "Device",
  "Telemetry",
  "Evidence",
  "Finding",
  "Risk",
  "AI Analysis",
] as const;

export function SecurityPipeline() {
  return (
    <div className="surface-panel rounded-2xl p-4 animate-rise-in stagger-5">
      <p className="mb-3 text-[11px] font-medium tracking-[0.14em] text-[var(--muted)] uppercase">
        Security pipeline
      </p>
      <ol className="flex flex-wrap items-center gap-2 text-xs sm:text-sm">
        {STAGES.map((stage, index) => (
          <li
            key={stage}
            className="flex items-center gap-2 animate-rise-in"
            style={{ animationDelay: `${80 + index * 50}ms` }}
          >
            <span className="rounded-lg border border-[var(--border)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-[var(--text)] shadow-sm transition duration-200 hover:border-[var(--accent)]/40 hover:text-[var(--accent)]">
              {stage}
            </span>
            {index < STAGES.length - 1 ? (
              <span className="text-[var(--muted)]" aria-hidden>
                →
              </span>
            ) : null}
          </li>
        ))}
      </ol>
      <p className="mt-3 text-xs text-[var(--muted)]">
        Verified device data is collected, assessed for security findings, scored
        using IoT context, and interpreted by AI. AI does not discover
        vulnerabilities.
      </p>
    </div>
  );
}
