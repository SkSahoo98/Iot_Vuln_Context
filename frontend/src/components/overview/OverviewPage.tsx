import { useCallback } from "react";
import { fetchAssessment } from "../../api/assessments";
import type { AssessmentSummary } from "../../api/types";
import { useAsyncData } from "../../hooks/useAsyncData";
import { securityHomeState, summarizeIssues } from "../../lib/securityHome";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import {
  SecurityHomeView,
  type DeviceContext,
  type IssuesState,
} from "./SecurityHomeView";

type Props = {
  assessments: AssessmentSummary[] | null;
  assessmentsError: string | null;
  onRetryAssessments: () => void;
  deviceContext: DeviceContext | null;
  onCheckSecurity: (assessmentId: string | null) => void;
  onShowDetails: (assessmentId: string) => void;
};

type Actions = Pick<Props, "deviceContext" | "onCheckSecurity" | "onShowDetails">;

function CompleteHome({
  latest,
  ...actions
}: { latest: AssessmentSummary } & Actions) {
  const loadDetail = useCallback(() => fetchAssessment(latest.id), [latest.id]);
  const detail = useAsyncData(loadDetail, 0);

  const issues: IssuesState = detail.data
    ? { status: "ready", summary: summarizeIssues(detail.data) }
    : detail.error
      ? { status: "error", message: detail.error, onRetry: detail.reload }
      : { status: "loading" };

  return (
    <SecurityHomeView state={{ kind: "complete", latest }} issues={issues} {...actions} />
  );
}

export function OverviewPage({
  assessments,
  assessmentsError,
  onRetryAssessments,
  ...actions
}: Props) {
  if (assessmentsError && !assessments) {
    return (
      <ErrorState
        message={`Couldn't load your latest security assessment. ${assessmentsError}`}
        onRetry={onRetryAssessments}
      />
    );
  }
  if (!assessments) {
    return <LoadingState message="Loading your latest security assessment…" />;
  }

  const state = securityHomeState(assessments);
  if (state.kind === "complete") {
    return <CompleteHome key={state.latest.id} latest={state.latest} {...actions} />;
  }
  return <SecurityHomeView state={state} issues={null} {...actions} />;
}
