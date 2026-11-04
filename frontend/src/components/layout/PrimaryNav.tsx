import type { ReactNode } from "react";
import {
  PRIMARY_SECTIONS,
  primarySectionOf,
  type AppSection,
  type PrimarySection,
} from "../../lib/navigation";

export const PRIMARY_LABELS: Record<PrimarySection, string> = {
  assistant: "Assistant",
  security: "Security",
  history: "History",
  more: "More",
};

function Icon({ children }: { children: ReactNode }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className="h-5 w-5"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      {children}
    </svg>
  );
}

export const PRIMARY_ICONS: Record<PrimarySection, ReactNode> = {
  assistant: (
    <Icon>
      <path d="M5 5.5h14a1.5 1.5 0 0 1 1.5 1.5v8.5A1.5 1.5 0 0 1 19 17h-7l-4.5 3.5V17H5a1.5 1.5 0 0 1-1.5-1.5V7A1.5 1.5 0 0 1 5 5.5Z" />
      <path d="M8.5 10.5h7M8.5 13.5h4" />
    </Icon>
  ),
  security: (
    <Icon>
      <path d="M12 3.5 19 6v5.5c0 4.2-2.9 7.6-7 9-4.1-1.4-7-4.8-7-9V6l7-2.5Z" />
      <path d="m9 12 2 2 4-4" />
    </Icon>
  ),
  history: (
    <Icon>
      <path d="M4 12a8 8 0 1 0 2.3-5.6" />
      <path d="M4 4.5v3.8h3.8" />
      <path d="M12 8v4.5l3 1.8" />
    </Icon>
  ),
  more: (
    <Icon>
      <circle cx="6" cy="12" r="1.3" />
      <circle cx="12" cy="12" r="1.3" />
      <circle cx="18" cy="12" r="1.3" />
    </Icon>
  ),
};

type Props = {
  section: AppSection;
  onNavigate: (section: PrimarySection) => void;
};

/** Desktop / tablet navigation shown in the header from the md breakpoint. */
export function TopNav({ section, onNavigate }: Props) {
  const active = primarySectionOf(section);
  return (
    <nav aria-label="Primary" className="hidden min-w-0 md:block">
      <ul className="flex items-center gap-1 rounded-full border border-white/[0.08] bg-white/[0.03] p-1">
        {PRIMARY_SECTIONS.map((id) => {
          const isActive = id === active;
          return (
            <li key={id}>
              <button
                type="button"
                onClick={() => onNavigate(id)}
                aria-current={isActive ? "page" : undefined}
                className={`btn-soft inline-flex min-h-11 items-center gap-2 rounded-full px-4 text-sm font-medium ${
                  isActive
                    ? "bg-[var(--accent-soft)] text-[var(--accent)]"
                    : "text-[var(--muted)] hover:text-[var(--text)]"
                }`}
              >
                {PRIMARY_ICONS[id]}
                {PRIMARY_LABELS[id]}
              </button>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
