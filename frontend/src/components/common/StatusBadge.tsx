type Props = {
  label: string;
  tone?: "ok" | "warn" | "danger" | "info" | "neutral";
};

const toneClass = {
  ok: "border-[var(--ok)]/35 bg-[var(--ok)]/10 text-[var(--ok)]",
  warn: "border-[var(--warn)]/35 bg-[var(--warn)]/10 text-[var(--warn)]",
  danger: "border-[var(--danger)]/35 bg-[var(--danger)]/10 text-[var(--danger)]",
  info: "border-[var(--accent)]/35 bg-[var(--accent)]/10 text-[var(--accent)]",
  neutral: "border-white/10 bg-white/[0.04] text-[var(--muted)]",
};

export function StatusBadge({ label, tone = "neutral" }: Props) {
  return (
    <span
      className={`premium-badge inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium tracking-wide ${toneClass[tone]}`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${
          tone === "ok"
            ? "bg-[var(--ok)]"
            : tone === "warn"
              ? "bg-[var(--warn)]"
              : tone === "danger"
                ? "bg-[var(--danger)]"
                : tone === "info"
                  ? "bg-[var(--accent)]"
                  : "bg-[var(--muted)]"
        }`}
        aria-hidden
      />
      {label}
    </span>
  );
}
