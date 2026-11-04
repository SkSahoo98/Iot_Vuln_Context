import {
  PRIMARY_SECTIONS,
  primarySectionOf,
  type AppSection,
  type PrimarySection,
} from "../../lib/navigation";
import { PRIMARY_ICONS, PRIMARY_LABELS } from "./PrimaryNav";

type Props = {
  active: AppSection;
  onNavigate: (section: PrimarySection) => void;
};

/** Mobile navigation; replaced by the header navigation from the md breakpoint. */
export function BottomDock({ active, onNavigate }: Props) {
  const current = primarySectionOf(active);
  const activeIndex = Math.max(0, PRIMARY_SECTIONS.indexOf(current));

  return (
    <nav
      aria-label="Primary"
      className="pointer-events-none fixed inset-x-0 bottom-0 z-40 flex justify-center px-4 pb-[max(0.75rem,env(safe-area-inset-bottom))] md:hidden"
    >
      <div className="ios-dock pointer-events-auto w-full max-w-sm">
        <div className="ios-dock__shell relative flex items-stretch gap-0 p-1.5">
          <span
            className="ios-dock__indicator"
            style={{
              width: `calc((100% - 0.75rem) / ${PRIMARY_SECTIONS.length})`,
              transform: `translateX(${activeIndex * 100}%)`,
            }}
            aria-hidden
          />

          {PRIMARY_SECTIONS.map((id) => {
            const isActive = id === current;
            return (
              <button
                key={id}
                type="button"
                onClick={() => onNavigate(id)}
                aria-current={isActive ? "page" : undefined}
                className={`ios-dock__item relative z-10 flex min-h-[3.35rem] min-w-0 flex-1 flex-col items-center justify-center rounded-[1.15rem] px-1 py-1.5 ${
                  isActive ? "text-[var(--accent)]" : "text-[var(--muted)]"
                }`}
              >
                <span className={`ios-dock__icon ${isActive ? "is-active" : ""}`}>
                  {PRIMARY_ICONS[id]}
                </span>
                <span className="mt-0.5 truncate text-[11px] font-medium tracking-wide">
                  {PRIMARY_LABELS[id]}
                </span>
              </button>
            );
          })}
        </div>
      </div>
    </nav>
  );
}
