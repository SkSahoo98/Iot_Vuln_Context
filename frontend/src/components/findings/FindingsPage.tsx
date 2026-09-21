import type { Finding, RiskItem } from "../../api/types";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { FindingList } from "./FindingList";

type Props = {
  findings: Finding[] | null;
  riskItems: RiskItem[];
  loading: boolean;
  error: string | null;
  onRetry: () => void;
  selectedFindingType: string | null;
  onSelect: (findingType: string) => void;
};

export function FindingsPage({
  findings,
  riskItems,
  loading,
  error,
  onRetry,
  selectedFindingType,
  onSelect,
}: Props) {
  if (loading && !findings) return <LoadingState />;
  if (error && !findings) {
    return <ErrorState message={error} onRetry={onRetry} />;
  }
  if (!findings || findings.length === 0) {
    return <EmptyState message="No security findings detected." />;
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <p className="text-sm text-[var(--muted)]">
        These findings come from deterministic, evidence-backed detection — not
        from the AI model.
      </p>
      <FindingList
        findings={findings}
        riskItems={riskItems}
        selectedFindingType={selectedFindingType}
        onSelect={onSelect}
      />
    </div>
  );
}
