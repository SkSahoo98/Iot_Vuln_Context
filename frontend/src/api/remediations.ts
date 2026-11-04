import { apiGet, apiPost } from "./client";
import type {
  RemediationComparison,
  RemediationWorkflow,
} from "./types";

export const createRemediation = (
  baselineAssessmentId: string,
  baselineFindingId: string,
) =>
  apiPost<{ baseline_assessment_id: string; baseline_finding_id: string }, RemediationWorkflow>(
    "/api/v1/remediations",
    {
      baseline_assessment_id: baselineAssessmentId,
      baseline_finding_id: baselineFindingId,
    },
  );

export const fetchRemediations = (baselineAssessmentId?: string) => {
  const query = baselineAssessmentId
    ? `?baseline_assessment_id=${encodeURIComponent(baselineAssessmentId)}`
    : "";
  return apiGet<RemediationWorkflow[]>(`/api/v1/remediations${query}`);
};

export const fetchRemediation = (remediationId: string) =>
  apiGet<RemediationWorkflow>(`/api/v1/remediations/${encodeURIComponent(remediationId)}`);

export const confirmRemediation = (remediationId: string, notes?: string) =>
  apiPost<{ notes?: string }, RemediationWorkflow>(
    `/api/v1/remediations/${encodeURIComponent(remediationId)}/confirm`,
    { notes },
  );

export const verifyRemediation = (
  remediationId: string,
  scope: "AUTO" | "TARGET" | "ENVIRONMENT" = "AUTO",
) =>
  apiPost<{ scope: string; explicit_approval: boolean }, RemediationWorkflow>(
    `/api/v1/remediations/${encodeURIComponent(remediationId)}/verify`,
    { scope, explicit_approval: true },
  );

export const fetchRemediationComparison = (remediationId: string) =>
  apiGet<RemediationComparison>(
    `/api/v1/remediations/${encodeURIComponent(remediationId)}/comparison`,
  );

