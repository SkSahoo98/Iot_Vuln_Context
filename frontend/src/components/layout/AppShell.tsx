import type { AppSection } from "../../lib/navigation";
import { BottomDock } from "./BottomDock";
import { Header } from "./Header";

type Props = {
  section: AppSection;
  apiOnline: boolean | null;
  onNavigate: (section: AppSection) => void;
  onOpenStatus: () => void;
  onRefresh: () => void;
  children: React.ReactNode;
};

export function AppShell({
  section,
  apiOnline,
  onNavigate,
  onOpenStatus,
  onRefresh,
  children,
}: Props) {
  return (
    <div className="app-atmosphere">
      <Header
        section={section}
        apiOnline={apiOnline}
        onOpenStatus={onOpenStatus}
        onRefresh={onRefresh}
      />
      <main className="mx-auto max-w-6xl px-4 pb-[calc(var(--dock-h)+2.75rem)] pt-5">
        <div key={section} className="animate-page-enter">
          {children}
        </div>
      </main>
      <BottomDock active={section} onNavigate={onNavigate} />
    </div>
  );
}
