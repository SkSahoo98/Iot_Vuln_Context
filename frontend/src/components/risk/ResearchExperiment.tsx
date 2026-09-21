import { useState } from "react";
import type { ExperimentDetail } from "../../api/types";
import { experimentMetric } from "../../lib/experiment";
import { SeverityBadge } from "../common/SeverityBadge";

type Props = {
  experiment: ExperimentDetail;
};

export function ResearchExperiment({ experiment }: Props) {
  const [notesOpen, setNotesOpen] = useState(false);
  const params = experiment.parameters ?? {};
  const scenarioA = (params.scenario_a ?? {}) as Record<string, unknown>;
  const scenarioB = (params.scenario_b ?? {}) as Record<string, unknown>;
  const scoreA = experimentMetric(experiment, "sensor_context_risk_score");
  const scoreB = experimentMetric(experiment, "critical_context_risk_score");
  const diff = experimentMetric(experiment, "risk_score_difference");

  return (
    <div className="surface-panel space-y-4 rounded-2xl p-5">
      <div>
        <h2 className="font-display text-base font-semibold">
          Context-Aware Risk Experiment
        </h2>
        <p className="mt-1 text-sm text-[var(--muted)]">
          The experiment demonstrates that the same vulnerability can receive a
          different risk score when IoT-specific environmental conditions
          change.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
          <p className="text-xs text-[var(--muted)]">Scenario A</p>
          <p className="mt-1 text-sm font-medium">Lower-impact IoT environment</p>
          <p className="mt-2 mono text-3xl font-semibold">{scoreA}</p>
          <SeverityBadge severity={String(scenarioA.risk_level ?? "HIGH")} />
          <ul className="mt-3 space-y-1 text-xs text-[var(--muted)]">
            <li>
              device_criticality: {String(scenarioA.device_criticality ?? "—")}
            </li>
            <li>
              network_exposure: {String(scenarioA.network_exposure ?? "—")}
            </li>
            <li>
              firmware_security: {String(scenarioA.firmware_security ?? "—")}
            </li>
          </ul>
        </div>
        <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
          <p className="text-xs text-[var(--muted)]">Scenario B</p>
          <p className="mt-1 text-sm font-medium">Higher-impact IoT environment</p>
          <p className="mt-2 mono text-3xl font-semibold">{scoreB}</p>
          <SeverityBadge
            severity={String(scenarioB.risk_level ?? "CRITICAL")}
          />
          <ul className="mt-3 space-y-1 text-xs text-[var(--muted)]">
            <li>
              device_criticality: {String(scenarioB.device_criticality ?? "—")}
            </li>
            <li>
              network_exposure: {String(scenarioB.network_exposure ?? "—")}
            </li>
            <li>
              firmware_security: {String(scenarioB.firmware_security ?? "—")}
            </li>
          </ul>
        </div>
      </div>

      <div className="rounded-xl border border-[var(--accent)]/30 bg-[var(--accent)]/5 px-4 py-3">
        <p className="text-xs text-[var(--muted)]">Difference</p>
        <p className="mono text-2xl font-semibold text-[var(--accent)]">
          Δ {diff}
        </p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          Fixed vulnerability:{" "}
          <span className="mono text-[var(--text)]">
            {String(params.vulnerability ?? "MQTT_WITHOUT_TLS")}
          </span>
          {" · "}
          Base severity:{" "}
          <span className="mono text-[var(--text)]">
            {String(params.base_severity ?? "HIGH")}
          </span>
        </p>
      </div>

      <div className="rounded-xl border border-white/[0.06]">
        <button
          type="button"
          onClick={() => setNotesOpen((value) => !value)}
          className="flex w-full items-center justify-between px-4 py-3 text-left text-sm"
          aria-expanded={notesOpen}
        >
          <span className="font-medium">Methodology / Research Notes</span>
          <span className="text-[var(--muted)]">
            {notesOpen ? "Hide" : "Show"}
          </span>
        </button>
        {notesOpen ? (
          <div className="space-y-3 border-t border-white/[0.06] px-4 py-4 text-sm text-[var(--muted)]">
            <div>
              <p className="font-medium text-[var(--text)]">Objective</p>
              <p>{experiment.objective || "Not available"}</p>
            </div>
            <div>
              <p className="font-medium text-[var(--text)]">Hypothesis</p>
              <p>{experiment.hypothesis || "Not available"}</p>
            </div>
            <div>
              <p className="font-medium text-[var(--text)]">Methodology</p>
              <p>{experiment.methodology || "Not available"}</p>
            </div>
            <div>
              <p className="font-medium text-[var(--text)]">Conclusion</p>
              <p>{experiment.conclusion || "Not available"}</p>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
