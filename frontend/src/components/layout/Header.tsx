import type { AppSection, PrimarySection } from "../../lib/navigation";
import { TopNav } from "./PrimaryNav";

type Props = {
  section: AppSection;
  apiOnline: boolean | null;
  onNavigate: (section: PrimarySection) => void;
  onOpenStatus: () => void;
  onRefresh: () => void;
  /** Matches the wider Assistant workspace. */
  wide?: boolean;
  isReadOnly?: boolean;
  modeLabel?: string;
};

export function Header({
  section,
  apiOnline,
  onNavigate,
  onOpenStatus,
  onRefresh,
  wide = false,
  isReadOnly = false,
  modeLabel,
}: Props) {
  const statusLabel =
    apiOnline === null
      ? "Checking…"
      : apiOnline
        ? "System Operational"
        : "System Issues";
  const statusTone =
    apiOnline === null
      ? "bg-[var(--muted)]"
      : apiOnline
        ? "bg-[var(--ok)]"
        : "bg-[var(--danger)]";

  const displayModeLabel =
    modeLabel ?? (isReadOnly ? "Cloud Read-Only" : "Active Laboratory Mode");

  return (
    <header className="sticky top-0 z-30 border-b border-white/[0.06] bg-[var(--bg)]/70 backdrop-blur-2xl">
      <div className={`mx-auto flex ${wide ? "max-w-7xl" : "max-w-6xl"} items-center gap-3 px-4 py-2.5`}>
        <div className="flex min-w-0 items-center gap-2.5">
          <span
            className="brand-mark flex h-9 w-9 shrink-0 items-center justify-center text-[11px] font-bold tracking-wide text-[var(--accent)]"
            aria-hidden
          >
            IoT
          </span>
          <span className="hidden truncate text-sm font-semibold tracking-tight text-[var(--text)] min-[400px]:inline">
            IoT Security
          </span>
        </div>

        <div className="min-w-0 flex-1 md:flex md:justify-center">
          <TopNav section={section} onNavigate={onNavigate} />
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {/* Environment Mode Pill */}
          <span
            className={`mono hidden items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium sm:inline-flex ${
              isReadOnly
                ? "border-sky-500/30 bg-sky-500/10 text-sky-400"
                : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
            }`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                isReadOnly ? "bg-sky-400" : "bg-emerald-400"
              }`}
            />
            {displayModeLabel}
          </span>

          <button
            type="button"
            onClick={onOpenStatus}
            className="btn-soft glass-chip inline-flex min-h-11 items-center gap-2 px-3.5 text-xs"
            aria-label="Open system status"
          >
            <span className={`h-2 w-2 rounded-full ${statusTone}`} />
            <span className="hidden lg:inline">{statusLabel}</span>
            <span className="lg:hidden">Status</span>
          </button>
          <button
            type="button"
            onClick={onRefresh}
            className="btn-soft glass-chip inline-flex min-h-11 items-center px-3.5 text-xs text-[var(--muted)] hover:text-[var(--text)]"
            aria-label="Refresh data"
          >
            Refresh
          </button>
        </div>
      </div>
    </header>
  );
}
