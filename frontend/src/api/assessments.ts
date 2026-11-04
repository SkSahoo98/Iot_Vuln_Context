import { apiGet, apiPost } from "./client";
import type {
  AssessmentCreateRequest,
  AssessmentDetail,
  AssessmentSummary,
} from "./types";

export const createAssessment = (targetOrRequest: string | AssessmentCreateRequest) => {
  const payload: AssessmentCreateRequest =
    typeof targetOrRequest === "string" ? { target: targetOrRequest } : targetOrRequest;
  return apiPost<AssessmentCreateRequest, AssessmentDetail>(
    "/api/v1/assessments",
    payload,
  );
};

export const fetchAssessments = () =>
  apiGet<AssessmentSummary[]>("/api/v1/assessments");

export const fetchAssessment = (id: string) =>
  apiGet<AssessmentDetail>(
    `/api/v1/assessments/${encodeURIComponent(id)}`,
  );
