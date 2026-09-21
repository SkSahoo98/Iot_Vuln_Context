import type { ExperimentDetail } from "../api/types";

export function experimentMetric(
  experiment: ExperimentDetail,
  name: string,
): string {
  const row = experiment.results.find((item) => item.metric_name === name);
  if (!row || row.metric_value === null || row.metric_value === undefined) {
    return "—";
  }
  return String(Number(row.metric_value));
}
