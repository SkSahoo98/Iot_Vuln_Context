import type { Explanation, Finding, RiskItem } from "../../api/types";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { AIAnalysisPanel } from "./AIAnalysisPanel";
import { AIFindingSelector } from "./AIFindingSelector";

type Props = {
  findings: Finding[] | null;
  findingsLoading: boolean;
  findingsError: string | null;
  onRetryFindings: () => void;
  selectedFindingType: string | null;
  onSelectFinding: (findingType: string) => void;
  riskItems: RiskItem[];
  explanation: Explanation | null;
  explanationLoading: boolean;
  explanationError: string | null;
  onRegenerate: () => void;
};

export function AIAnalysisPage({
  findings,
  findingsLoading,
  findingsError,
  onRetryFindings,
  selectedFindingType,
  onSelectFinding,
  riskItems,
  explanation,
  explanationLoading,
  explanationError,
  onRegenerate,
}: Props) {
  if (findingsLoading && !findings) return <LoadingState />;
  if (findingsError && !findings) {
    return <ErrorState message={findingsError} onRetry={onRetryFindings} />;
  }
  if (!findings || findings.length === 0) {
    return <EmptyState message="No findings available for AI analysis." />;
  }

  const finding =
    findings.find((item) => item.finding_type === selectedFindingType) ??
    findings[0];
  const riskItem =
    riskItems.find((item) => item.finding_type === finding.finding_type) ??
    null;

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-panel)] p-4">
        <h2 className="text-base font-semibold">AI-Assisted Security Analysis</h2>
        <p className="mt-2 text-sm text-[var(--muted)]">
          Qwen3 interprets verified evidence. It does not discover
          vulnerabilities or recalculate risk.
        </p>
        <p className="mt-2 text-sm text-[var(--muted)]">
          AI-generated explanation based on application-verified security
          evidence. Vulnerability detection and risk scoring remain
          deterministic.
        </p>
      </div>

      <AIFindingSelector
        findings={findings}
        selectedFindingType={finding.finding_type}
        onSelect={onSelectFinding}
      />

      <AIAnalysisPanel
        finding={finding}
        riskItem={riskItem}
        explanation={explanation}
        loading={explanationLoading}
        error={explanationError}
        onRegenerate={onRegenerate}
      />
    </div>
  );
}
