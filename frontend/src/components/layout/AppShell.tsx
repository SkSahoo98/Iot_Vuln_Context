import type { ReactNode } from "react";
import {
  SECTION_META,
  isSecondarySection,
  type AppSection,
  type PrimarySection,
} from "../../lib/navigation";
import { BottomDock } from "./BottomDock";
import { Header } from "./Header";

type Props = {
  section: AppSection;
  apiOnline: boolean | null;
  onNavigate: (section: PrimarySection) => void;
  onOpenStatus: () => void;
  onRefresh: () => void;
  children: ReactNode;
  isReadOnly?: boolean;
  modeLabel?: string;
};

export function AppShell({
  section,
  apiOnline,
  onNavigate,
  onOpenStatus,
  onRefresh,
  children,
  isReadOnly,
  modeLabel,
}: Props) {
  const meta = SECTION_META[section];
  /** The Assistant is a fixed-height workspace on desktop, so it gets more width and less bottom space. */
  const workspace = section === "assistant";

  return (
    <div className="app-atmosphere overflow-x-clip">
      <Header
        section={section}
        apiOnline={apiOnline}
        onNavigate={onNavigate}
        onOpenStatus={onOpenStatus}
        onRefresh={onRefresh}
        wide={workspace}
        isReadOnly={isReadOnly}
        modeLabel={modeLabel}
      />
      <main
        className={`mx-auto px-4 pb-[calc(var(--dock-h)+2.75rem)] pt-5 ${
          workspace ? "max-w-7xl md:pb-5" : "max-w-6xl md:pb-12"
        }`}
      >
        <div key={section} className="animate-page-enter">
          <div className={`${workspace ? "mb-4" : "mb-5"} min-w-0`}>
            {isSecondarySection(section) ? (
              <button
                type="button"
                onClick={() => onNavigate("more")}
                className="btn-soft -ml-2 mb-1 inline-flex min-h-11 items-center gap-1 rounded-full px-2 text-sm text-[var(--muted)] hover:text-[var(--text)]"
              >
                <span aria-hidden>‹</span> More
              </button>
            ) : null}
            <h1 className="font-display break-words text-xl font-semibold sm:text-2xl">
              {meta.title}
            </h1>
            <p className="mt-1 hidden max-w-xl text-sm text-[var(--muted)] sm:block">
              {meta.subtitle}
            </p>
          </div>
          {children}
        </div>
      </main>
      <BottomDock active={section} onNavigate={onNavigate} />
    </div>
  );
}
