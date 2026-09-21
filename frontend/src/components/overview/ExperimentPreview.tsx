import type { ExperimentDetail } from "../../api/types";
import { experimentMetric } from "../../lib/experiment";
import { SeverityBadge } from "../common/SeverityBadge";

type Props = {
  experiment: ExperimentDetail | null;
  onViewResearch: () => void;
};

export function ExperimentPreview({ experiment, onViewResearch }: Props) {
  if (!experiment) {
    return (
      <div className="surface-panel rounded-2xl p-4 text-sm text-[var(--muted)]">
        Research experiment not available.
      </div>
    );
  }

  const scoreA = experimentMetric(experiment, "sensor_context_risk_score");
  const scoreB = experimentMetric(experiment, "critical_context_risk_score");
  const diff = experimentMetric(experiment, "risk_score_difference");
  const params = experiment.parameters ?? {};
  const scenarioA = (params.scenario_a ?? {}) as Record<string, unknown>;
  const scenarioB = (params.scenario_b ?? {}) as Record<string, unknown>;

  return (
    <div className="surface-panel relative overflow-hidden rounded-2xl p-4">
      <div
        className="pointer-events-none absolute -bottom-10 -right-6 h-28 w-28 rounded-full bg-[var(--accent)]/10 blur-2xl"
        aria-hidden
      />
      <div className="mb-3 flex items-center justify-between gap-3">
        <p className="font-display text-sm font-semibold">Context-Aware Risk</p>
        <button
          type="button"
          onClick={onViewResearch}
          className="btn-soft text-xs text-[var(--accent)] hover:underline"
        >
          View research →
        </button>
      </div>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="mono text-base font-semibold">{scoreA}</span>
        <SeverityBadge severity={String(scenarioA.risk_level ?? "HIGH")} />
        <span className="text-[var(--muted)] transition-transform">→</span>
        <span className="mono text-base font-semibold">{scoreB}</span>
        <SeverityBadge severity={String(scenarioB.risk_level ?? "CRITICAL")} />
      </div>
      <p className="mt-3 font-display text-lg font-semibold text-[var(--accent)]">
        Δ {diff}
      </p>
      <p className="mt-1 text-xs text-[var(--muted)]">Context changes risk.</p>
    </div>
  );
}
