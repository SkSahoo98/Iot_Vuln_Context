type Props = {
  label: string;
  value: string;
  secondary?: string;
  tone?: "default" | "ok" | "warn" | "danger";
  stagger?: 1 | 2 | 3 | 4;
};

const toneClass = {
  default: "text-[var(--text)]",
  ok: "text-[var(--ok)]",
  warn: "text-[var(--warn)]",
  danger: "text-[var(--danger)]",
};

const toneBar = {
  default: "from-[var(--accent)]/60 via-[var(--accent)]/20 to-transparent",
  ok: "from-[var(--ok)]/60 via-[var(--ok)]/20 to-transparent",
  warn: "from-[var(--warn)]/60 via-[var(--warn)]/20 to-transparent",
  danger: "from-[var(--danger)]/60 via-[var(--danger)]/20 to-transparent",
};

const toneGlow = {
  default: "rgba(62, 196, 240, 0.12)",
  ok: "rgba(52, 211, 153, 0.12)",
  warn: "rgba(245, 176, 65, 0.12)",
  danger: "rgba(251, 113, 133, 0.12)",
};

export function KpiCard({
  label,
  value,
  secondary,
  tone = "default",
  stagger = 1,
}: Props) {
  return (
    <div
      className={`surface-panel surface-interactive relative overflow-hidden rounded-2xl px-4 py-4 animate-rise-in stagger-${stagger}`}
      style={{
        boxShadow: `var(--shadow-panel), 0 0 40px ${toneGlow[tone]}`,
      }}
    >
      <div
        className={`pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r ${toneBar[tone]}`}
        aria-hidden
      />
      <div
        className="pointer-events-none absolute -right-6 -top-8 h-24 w-24 rounded-full opacity-40 blur-2xl"
        style={{ background: toneGlow[tone] }}
        aria-hidden
      />
      <p className="relative text-[11px] font-medium tracking-[0.12em] text-[var(--muted)] uppercase">
        {label}
      </p>
      <p
        className={`relative mt-2 font-display text-3xl font-semibold mono ${toneClass[tone]}`}
      >
        {value}
      </p>
      {secondary ? (
        <p className={`relative mt-0.5 text-sm font-medium ${toneClass[tone]}`}>
          {secondary}
        </p>
      ) : null}
    </div>
  );
}
