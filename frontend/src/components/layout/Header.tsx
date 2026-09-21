import type { AppSection } from "../../lib/navigation";
import { SECTION_META } from "../../lib/navigation";

type Props = {
  section: AppSection;
  apiOnline: boolean | null;
  onOpenStatus: () => void;
  onRefresh: () => void;
};

export function Header({ section, apiOnline, onOpenStatus, onRefresh }: Props) {
  const meta = SECTION_META[section];
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

  return (
    <header className="sticky top-0 z-30 border-b border-white/[0.06] bg-[var(--bg)]/55 backdrop-blur-2xl">
      <div className="mx-auto flex max-w-6xl items-start justify-between gap-4 px-4 py-4">
        <div className="min-w-0">
          <div className="flex items-center gap-3">
            <span
              className="brand-mark flex h-10 w-10 items-center justify-center text-[11px] font-bold tracking-wide text-[var(--accent)]"
              aria-hidden
            >
              IoT
            </span>
            <div className="min-w-0">
              <p className="truncate text-[11px] tracking-[0.16em] text-[var(--muted)] uppercase">
                IoT Security Framework
              </p>
              <h1
                key={section}
                className="font-display truncate text-lg font-semibold sm:text-xl animate-title-swap"
              >
                {meta.title}
              </h1>
            </div>
          </div>
          <p
            key={`${section}-sub`}
            className="mt-1.5 max-w-xl text-sm text-[var(--muted)] animate-title-swap"
          >
            {meta.subtitle}
          </p>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <button
            type="button"
            onClick={onOpenStatus}
            className="btn-soft glass-chip inline-flex items-center gap-2 px-3.5 py-2 text-xs"
            aria-label="Open system status"
          >
            <span
              className={`h-2 w-2 rounded-full ${statusTone} ${
                apiOnline ? "status-pulse" : ""
              }`}
            />
            <span className="hidden sm:inline">{statusLabel}</span>
            <span className="sm:hidden">Status</span>
          </button>
          <button
            type="button"
            onClick={onRefresh}
            className="btn-soft glass-chip px-3.5 py-2 text-xs text-[var(--muted)] hover:text-[var(--text)]"
            aria-label="Refresh data"
          >
            Refresh
          </button>
        </div>
      </div>
    </header>
  );
}
