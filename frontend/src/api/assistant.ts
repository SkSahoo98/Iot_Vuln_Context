import { apiPost } from "./client";

/**
 * Minimal request: what kind of explanation, nothing else. The backend loads
 * the latest assessment, builds the context and decides what the model sees.
 * `issue` is a catalog check ID naming one recorded issue to focus on; the
 * backend looks it up in its own latest check and never trusts more than that.
 */
export type AssistantExplainRequest =
  | { intent: "EXPLAIN"; subject: "RISK" }
  | { intent: "EXPLAIN"; subject: "ISSUES"; issue?: string }
  | { intent: "FIX"; issue?: string }
  | { intent: "SUMMARY" };

export type AssistantExplainStatus =
  | "COMPLETE"
  | "NEEDS_ASSESSMENT"
  | "ASSESSMENT_INCOMPLETE"
  | "ASSESSMENT_FAILED"
  | "ASSESSMENT_RUNNING"
  | "OUT_OF_SCOPE"
  | "ISSUE_NOT_FOUND"
  | "ERROR";

export type AssistantExplainSource = "AI" | "DETERMINISTIC_FALLBACK" | "DETERMINISTIC";

/** Recorded sections the backend put into the explanation context. */
export type AssistantExplainBasis =
  | "RISK_RESULT"
  | "RISK_CONTRIBUTORS"
  | "FINDINGS"
  | "REMEDIATION"
  | "LIMITATIONS";

export type AssistantExplainResponse = {
  status: AssistantExplainStatus;
  answer?: string;
  message?: string;
  source?: AssistantExplainSource;
  basis?: AssistantExplainBasis[];
};

export const explainWithAssistant = (request: AssistantExplainRequest) =>
  apiPost<AssistantExplainRequest, AssistantExplainResponse>(
    "/api/v1/assistant/explain",
    request,
  );
