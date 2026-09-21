import type { Finding } from "../../api/types";

type Props = {
  findings: Finding[];
  selectedFindingType: string | null;
  onSelect: (findingType: string) => void;
};

export function AIFindingSelector({
  findings,
  selectedFindingType,
  onSelect,
}: Props) {
  return (
    <div>
      <p className="mb-2 text-sm font-medium">Select finding</p>
      <div className="flex flex-col gap-2 sm:flex-row">
        {findings.map((finding) => {
          const active = selectedFindingType === finding.finding_type;
          return (
            <button
              key={finding.finding_type}
              type="button"
              onClick={() => onSelect(finding.finding_type)}
              className={`rounded-lg border px-3 py-2 text-left text-sm transition ${
                active
                  ? "border-[var(--accent)]/50 bg-[var(--accent)]/10 text-[var(--text)]"
                  : "border-[var(--border)] bg-[var(--bg-panel)] text-[var(--muted)] hover:text-[var(--text)]"
              }`}
            >
              {finding.title}
            </button>
          );
        })}
      </div>
    </div>
  );
}
