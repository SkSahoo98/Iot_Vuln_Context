import { useRef } from "react";
import type { ExperimentDetail, RiskSummary } from "../../api/types";
import { formatFindingTypeLabel } from "../../lib/format";
import {
  contextContributionPoints,
  formatEvidenceFacts,
  formatFindingPlainExplanation,
} from "../../lib/riskPresentation";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { SeverityBadge } from "../common/SeverityBadge";
import { CurrentRiskAssessment } from "./CurrentRiskAssessment";
import { ResearchExperiment } from "./ResearchExperiment";
import { RiskCalculation } from "./RiskCalculation";
import { RiskFactors } from "./RiskFactors";
import { RiskOverview } from "./RiskOverview";

type Props = {
  risk: RiskSummary | null;
  riskLoading: boolean;
  riskError: string | null;
  onRetryRisk: () => void;
  selectedFindingType: string | null;
  onSelectFinding: (findingType: string) => void;
  experiment: ExperimentDetail | null;
  experimentLoading: boolean;
  experimentError: string | null;
};

export function RiskResearchPage({
  risk,
  riskLoading,
  riskError,
  onRetryRisk,
  selectedFindingType,
  onSelectFinding,
  experiment,
  experimentLoading,
  experimentError,
}: Props) {
  const detailsRef = useRef<HTMLElement | null>(null);

  if (riskLoading && !risk) return <LoadingState />;
  if (riskError && !risk) {
    return <ErrorState message={riskError} onRetry={onRetryRisk} />;
  }
  if (!risk) return <EmptyState message="No risk assessment available." />;

  const items = risk.items ?? [];
  const selectedItem =
    items.find((entry) => entry.finding_type === selectedFindingType) ??
    items[0] ??
    null;

  const activeFindingType = selectedItem?.finding_type ?? selectedFindingType;
  const evidenceFacts = selectedItem
    ? formatEvidenceFacts(selectedItem.evidence ?? {})
    : [];
  const contextPoints = selectedItem
    ? contextContributionPoints(selectedItem)
    : null;

  const handleSelect = (findingType: string) => {
    onSelectFinding(findingType);
    window.requestAnimationFrame(() => {
      detailsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* WHAT IS THE RISK? */}
      <RiskOverview
        highestScore={risk.highest_score}
        highestLevel={risk.highest_level}
        scoreVersion={risk.score_version}
        findingsAssessed={risk.findings_assessed}
      />

      {/* WHAT PROBLEMS WERE FOUND? / WHY DO THEY MATTER? */}
      {items.length === 0 ? (
        <EmptyState message="No evidence-backed findings available. Risk assessment will appear after vulnerability evidence is detected." />
      ) : (
        <CurrentRiskAssessment
          items={items}
          selectedFindingType={activeFindingType}
          onSelect={handleSelect}
        />
      )}

      {selectedItem ? (
        <section ref={detailsRef} className="space-y-3 scroll-mt-24">
          <div>
            <h2 className="font-display text-base font-semibold">
              Risk Factor Breakdown
            </h2>
            <p className="mt-1 text-sm text-[var(--muted)]">
              Selected finding:{" "}
              <span className="text-[var(--text)]">
                {formatFindingTypeLabel(selectedItem.finding_type)}
              </span>
            </p>
            <p className="mt-1 text-sm text-[var(--muted)]">
              {formatFindingPlainExplanation(selectedItem.finding_type)}
            </p>
          </div>

          <div className="surface-panel rounded-2xl p-4 sm:p-5">
            <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
              <div>
                <p className="text-[11px] tracking-[0.12em] text-[var(--muted)] uppercase">
                  Dynamic Risk Score
                </p>
                <p className="mono mt-1 text-3xl font-semibold">
                  {selectedItem.score}
                  <span className="ml-1 text-base font-normal text-[var(--muted)]">
                    / 100
                  </span>
                </p>
              </div>
              <div className="text-right">
                <p className="text-[11px] tracking-[0.12em] text-[var(--muted)] uppercase">
                  Risk Level
                </p>
                <div className="mt-1">
                  <SeverityBadge severity={selectedItem.risk_level} />
                </div>
              </div>
            </div>

            {contextPoints != null ? (
              <p className="mb-4 text-sm text-[var(--muted)]">
                Context contribution:{" "}
                <span className="mono text-[var(--text)]">
                  {contextPoints} points
                </span>
              </p>
            ) : null}

            {/* WHY IS THE RISK HIGH? */}
            <RiskFactors item={selectedItem} />

            {/* WHAT EVIDENCE SUPPORTS THE FINDING? */}
            <div className="mt-5 border-t border-white/[0.06] pt-4">
              <h3 className="text-sm font-medium">
                Why was this finding reported?
              </h3>
              <p className="mt-1 text-sm text-[var(--muted)]">
                The framework reports this finding only when supporting evidence
                is available.
              </p>
              {evidenceFacts.length > 0 ? (
                <ul className="mt-3 space-y-2 text-sm">
                  {evidenceFacts.map((fact) => (
                    <li key={fact} className="flex items-start gap-2">
                      <span
                        className="mt-0.5 text-[var(--ok)]"
                        aria-hidden
                      >
                        ✓
                      </span>
                      <span>{fact}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-3 text-sm text-[var(--muted)]">
                  No structured evidence fields were returned for this finding.
                </p>
              )}
            </div>
          </div>

          {/* HOW IS THE SCORE CALCULATED? */}
          <RiskCalculation item={selectedItem} />
        </section>
      ) : null}

      {/* WHAT DOES THE RESEARCH EXPERIMENT SHOW? */}
      <section className="space-y-3">
        {experimentLoading && !experiment ? <LoadingState /> : null}
        {experimentError && !experiment ? (
          <ErrorState message={experimentError} />
        ) : null}
        {experiment ? <ResearchExperiment experiment={experiment} /> : null}
        {!experimentLoading && !experiment && !experimentError ? (
          <EmptyState message="No research experiment recorded yet." />
        ) : null}
      </section>
    </div>
  );
}
