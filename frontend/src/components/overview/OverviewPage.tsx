import type { ExperimentDetail, Finding, RiskSummary } from "../../api/types";
import { severityTone } from "../../lib/format";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { KpiCard } from "../common/KpiCard";
import { LoadingState } from "../common/LoadingState";
import { ExperimentPreview } from "./ExperimentPreview";
import { SecurityPipeline } from "./SecurityPipeline";
import { SecuritySummary } from "./SecuritySummary";
import { TopFindings } from "./TopFindings";

type Props = {
  devicesCount: number;
  onlineCount: number;
  findings: Finding[] | null;
  findingsLoading: boolean;
  findingsError: string | null;
  onRetryFindings: () => void;
  risk: RiskSummary | null;
  riskLoading: boolean;
  riskError: string | null;
  onRetryRisk: () => void;
  experiment: ExperimentDetail | null;
  onNavigateFindings: () => void;
  onNavigateRisk: () => void;
  onOpenFinding: (findingType: string) => void;
};

export function OverviewPage({
  devicesCount,
  onlineCount,
  findings,
  findingsLoading,
  findingsError,
  onRetryFindings,
  risk,
  riskLoading,
  riskError,
  onRetryRisk,
  experiment,
  onNavigateFindings,
  onNavigateRisk,
  onOpenFinding,
}: Props) {
  const riskTone = severityTone(risk?.highest_level);

  return (
    <div className="space-y-5">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard label="Total Devices" value={String(devicesCount)} stagger={1} />
        <KpiCard
          label="Online Devices"
          value={String(onlineCount)}
          tone="ok"
          stagger={2}
        />
        <KpiCard
          label="Security Findings"
          value={String(findings?.length ?? 0)}
          tone="warn"
          stagger={3}
        />
        <KpiCard
          label="Highest Risk"
          value={
            risk?.highest_score != null ? String(risk.highest_score) : "—"
          }
          secondary={risk?.highest_level ?? undefined}
          tone={riskTone}
          stagger={4}
        />
      </div>

      {riskLoading && !risk ? <LoadingState /> : null}
      {riskError && !risk ? (
        <ErrorState message={riskError} onRetry={onRetryRisk} />
      ) : null}
      {risk ? (
        <SecuritySummary
          findingsCount={findings?.length ?? 0}
          highestLevel={risk.highest_level}
          highestScore={risk.highest_score}
        />
      ) : null}

      <SecurityPipeline />

      {findingsLoading && !findings ? <LoadingState /> : null}
      {findingsError && !findings ? (
        <ErrorState message={findingsError} onRetry={onRetryFindings} />
      ) : null}
      {findings && findings.length === 0 ? (
        <EmptyState message="No security findings detected." />
      ) : null}
      {findings && findings.length > 0 ? (
        <div className="grid gap-4 lg:grid-cols-2">
          <TopFindings
            findings={findings}
            riskItems={risk?.items ?? []}
            onViewAll={onNavigateFindings}
            onOpenFinding={onOpenFinding}
          />
          <ExperimentPreview
            experiment={experiment}
            onViewResearch={onNavigateRisk}
          />
        </div>
      ) : (
        <ExperimentPreview
          experiment={experiment}
          onViewResearch={onNavigateRisk}
        />
      )}
    </div>
  );
}
