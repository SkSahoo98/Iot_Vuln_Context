import type { SecondarySection } from "../../lib/navigation";

type Entry = {
  label: string;
  description: string;
  action: { kind: "section"; section: SecondarySection } | { kind: "status" };
};

type Group = { title: string; note?: string; entries: Entry[] };

export const MORE_GROUPS: readonly Group[] = [
  {
    title: "Workspace",
    entries: [
      {
        label: "Devices",
        description: "Registered IoT devices and their latest sensor telemetry.",
        action: { kind: "section", section: "devices" },
      },
    ],
  },
  {
    title: "Advanced & legacy views",
    note: "Earlier technical pages. Current security results are in Security and History.",
    entries: [
      {
        label: "Technical findings",
        description: "Findings view from the earlier telemetry pipeline.",
        action: { kind: "section", section: "findings" },
      },
      {
        label: "Risk & research",
        description: "Risk model breakdown and the context-aware risk experiment.",
        action: { kind: "section", section: "risk" },
      },
      {
        label: "AI analysis (legacy)",
        description: "Earlier AI explanation view for legacy findings.",
        action: { kind: "section", section: "ai" },
      },
    ],
  },
  {
    title: "System",
    entries: [
      {
        label: "System status",
        description: "Backend, MQTT, AI and risk-model availability.",
        action: { kind: "status" },
      },
    ],
  },
];

type Props = {
  onNavigate: (section: SecondarySection) => void;
  onOpenStatus: () => void;
};

export function MorePage({ onNavigate, onOpenStatus }: Props) {
  return (
    <div className="mx-auto max-w-3xl space-y-7">
      {MORE_GROUPS.map((group) => (
        <section key={group.title} aria-label={group.title} className="space-y-2.5">
          <div>
            <h2 className="text-[11px] font-medium uppercase tracking-[0.14em] text-[var(--muted)]">
              {group.title}
            </h2>
            {group.note ? (
              <p className="mt-1 text-xs text-[var(--muted)]">{group.note}</p>
            ) : null}
          </div>
          <ul className="divide-y divide-white/[0.06] overflow-hidden rounded-2xl border border-white/[0.07] bg-white/[0.02]">
            {group.entries.map((entry) => (
              <li key={entry.label}>
                <button
                  type="button"
                  onClick={() =>
                    entry.action.kind === "section"
                      ? onNavigate(entry.action.section)
                      : onOpenStatus()
                  }
                  className="btn-soft flex min-h-14 w-full min-w-0 items-center justify-between gap-3 px-4 py-3 text-left hover:bg-white/[0.04]"
                >
                  <span className="min-w-0">
                    <span className="block text-[15px] font-medium text-[var(--text)]">
                      {entry.label}
                    </span>
                    <span className="mt-0.5 block break-words text-xs text-[var(--muted)]">
                      {entry.description}
                    </span>
                  </span>
                  <span className="shrink-0 text-[var(--muted)]" aria-hidden>
                    ›
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}
