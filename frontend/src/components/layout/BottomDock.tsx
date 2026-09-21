import { useEffect, useState } from "react";
import type { AppSection } from "../../lib/navigation";

type Props = {
  active: AppSection;
  onNavigate: (section: AppSection) => void;
};

const ITEMS: {
  id: AppSection;
  label: string;
  icon: (active: boolean) => React.ReactNode;
}[] = [
  {
    id: "overview",
    label: "Overview",
    icon: (active) => (
      <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" aria-hidden>
        <path
          d="M4 10.5 12 4l8 6.5V20a1 1 0 0 1-1 1h-5v-6H10v6H5a1 1 0 0 1-1-1v-9.5Z"
          stroke="currentColor"
          strokeWidth={active ? 2 : 1.7}
          strokeLinejoin="round"
        />
      </svg>
    ),
  },
  {
    id: "devices",
    label: "Devices",
    icon: (active) => (
      <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" aria-hidden>
        <rect
          x="6"
          y="3"
          width="12"
          height="18"
          rx="2.5"
          stroke="currentColor"
          strokeWidth={active ? 2 : 1.7}
        />
        <path
          d="M10 17h4"
          stroke="currentColor"
          strokeWidth={active ? 2 : 1.7}
          strokeLinecap="round"
        />
      </svg>
    ),
  },
  {
    id: "findings",
    label: "Findings",
    icon: (active) => (
      <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" aria-hidden>
        <path
          d="M12 3.5 20 19H4L12 3.5Z"
          stroke="currentColor"
          strokeWidth={active ? 2 : 1.7}
          strokeLinejoin="round"
        />
        <path
          d="M12 10v4.5M12 17.5h.01"
          stroke="currentColor"
          strokeWidth={active ? 2 : 1.7}
          strokeLinecap="round"
        />
      </svg>
    ),
  },
  {
    id: "risk",
    label: "Risk",
    icon: (active) => (
      <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" aria-hidden>
        <circle
          cx="12"
          cy="12"
          r="8"
          stroke="currentColor"
          strokeWidth={active ? 2 : 1.7}
        />
        <circle
          cx="12"
          cy="12"
          r="3.5"
          stroke="currentColor"
          strokeWidth={active ? 2 : 1.7}
        />
        <path
          d="M12 4v2.5M12 17.5V20M4 12h2.5M17.5 12H20"
          stroke="currentColor"
          strokeWidth={active ? 2 : 1.7}
          strokeLinecap="round"
        />
      </svg>
    ),
  },
  {
    id: "ai",
    label: "AI",
    icon: (active) => (
      <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" aria-hidden>
        <path
          d="M12 3.5 13.8 9.2 19.5 11 13.8 12.8 12 18.5 10.2 12.8 4.5 11 10.2 9.2 12 3.5Z"
          stroke="currentColor"
          strokeWidth={active ? 2 : 1.7}
          strokeLinejoin="round"
        />
      </svg>
    ),
  },
];

export function BottomDock({ active, onNavigate }: Props) {
  const activeIndex = Math.max(
    0,
    ITEMS.findIndex((item) => item.id === active),
  );
  const [popId, setPopId] = useState<AppSection | null>(null);

  useEffect(() => {
    setPopId(active);
    const id = window.setTimeout(() => setPopId(null), 420);
    return () => window.clearTimeout(id);
  }, [active]);

  return (
    <nav
      aria-label="Primary"
      className="pointer-events-none fixed inset-x-0 bottom-0 z-40 flex justify-center px-4 pb-[max(0.75rem,env(safe-area-inset-bottom))] sm:pb-5"
    >
      <div className="ios-dock pointer-events-auto w-full max-w-md">
        <div className="ios-dock__shell relative flex items-stretch gap-0 p-1.5">
          <span
            className="ios-dock__indicator"
            style={{
              width: `calc((100% - 0.75rem) / ${ITEMS.length})`,
              transform: `translateX(${activeIndex * 100}%)`,
            }}
            aria-hidden
          />

          {ITEMS.map((item) => {
            const isActive = active === item.id;
            const isPopping = popId === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onNavigate(item.id)}
                aria-current={isActive ? "page" : undefined}
                aria-label={item.label}
                className={`ios-dock__item relative z-10 flex min-h-[3.35rem] flex-1 flex-col items-center justify-center rounded-[1.15rem] px-1 py-1.5 ${
                  isActive ? "text-[var(--accent)]" : "text-[var(--muted)]"
                }`}
              >
                <span
                  className={`ios-dock__icon ${isActive ? "is-active" : ""} ${
                    isPopping ? "is-pop" : ""
                  }`}
                >
                  {item.icon(isActive)}
                </span>
                <span
                  className={`mt-0.5 text-[10px] font-medium tracking-wide transition-all duration-300 sm:text-[11px] ${
                    isActive
                      ? "translate-y-0 opacity-100"
                      : "translate-y-0.5 opacity-70"
                  }`}
                >
                  {item.label}
                </span>
              </button>
            );
          })}
        </div>
      </div>
    </nav>
  );
}
