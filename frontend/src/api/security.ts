import { apiGet } from "./client";
import type {
  Device,
  ExperimentDetail,
  ExperimentSummary,
  Explanation,
  Finding,
  RiskSummary,
} from "./types";

export const fetchHealth = () =>
  apiGet<{ status: string; service: string }>("/api/v1/health");

export const fetchDevices = () => apiGet<Device[]>("/api/v1/devices");

export const fetchFindings = () => apiGet<Finding[]>("/api/v1/findings");

export const fetchRisk = () => apiGet<RiskSummary>("/api/v1/risk");

export const fetchExperiments = () =>
  apiGet<ExperimentSummary[]>("/api/v1/experiments");

export const fetchExperiment = (id: string) =>
  apiGet<ExperimentDetail>(`/api/v1/experiments/${id}`);

export const fetchExplanation = (
  findingType: string,
  options?: { refresh?: boolean },
) => {
  const query = options?.refresh ? "?refresh=true" : "";
  return apiGet<Explanation>(
    `/api/v1/explanations/${encodeURIComponent(findingType)}${query}`,
  );
};
