/**
 * Re-assessment workflow state. Starts a new backend assessment of the same
 * target and reports the outcome; it does not compare or interpret results.
 */
import type { AssessmentDetail, AssessmentStatus } from "../../api/types";

export type ReassessmentOriginal = {
  id: string;
  target: string;
  status: AssessmentStatus;
};

export type ReassessmentPair = { beforeId: string; afterId: string };

export type ReassessmentState =
  | { phase: "idle" }
  | { phase: "confirming" }
  | { phase: "running" }
  | { phase: "blocked" }
  | ({ phase: "complete"; created: AssessmentDetail } & ReassessmentPair)
  | { phase: "not_complete"; created: AssessmentDetail }
  | { phase: "failed"; created: AssessmentDetail }
  | { phase: "error"; message: string; httpStatus: number | null };

export function isReassessable(assessment: { status: AssessmentStatus }): boolean {
  return assessment.status === "COMPLETE";
}

// Shared by every flow in this browser tab: the backend request is synchronous
// and unguarded, so a remounted panel must not start a second active scan.
let requestInFlight = false;

export function isReassessmentInFlight(): boolean {
  return requestInFlight;
}

export function resultState(
  original: ReassessmentOriginal,
  created: AssessmentDetail,
): ReassessmentState {
  if (created.status === "COMPLETE") {
    return { phase: "complete", created, beforeId: original.id, afterId: created.id };
  }
  if (created.status === "FAILED") return { phase: "failed", created };
  return { phase: "not_complete", created };
}

export function errorState(error: unknown): ReassessmentState {
  const message =
    error instanceof Error && error.message
      ? error.message
      : "The re-assessment request did not return a result.";
  const status =
    typeof error === "object" &&
    error !== null &&
    "status" in error &&
    typeof error.status === "number" &&
    error.status > 0
      ? error.status
      : null;
  return { phase: "error", message, httpStatus: status };
}

export type ReassessmentFlow = {
  getState(): ReassessmentState;
  request(): void;
  cancel(): void;
  dismiss(): void;
  confirm(): Promise<void>;
};

export function createReassessmentFlow(options: {
  original: ReassessmentOriginal;
  run: (target: string) => Promise<AssessmentDetail>;
  onState: (state: ReassessmentState) => void;
  onCreated?: (created: AssessmentDetail) => void;
  onComplete?: (pair: ReassessmentPair) => void;
}): ReassessmentFlow {
  let state: ReassessmentState = { phase: "idle" };
  const set = (next: ReassessmentState) => {
    state = next;
    options.onState(next);
  };

  return {
    getState: () => state,

    request() {
      if (!isReassessable(options.original)) return;
      if (state.phase === "running" || state.phase === "confirming") return;
      set({ phase: "confirming" });
    },

    cancel() {
      if (state.phase === "confirming" || state.phase === "blocked") {
        set({ phase: "idle" });
      }
    },

    dismiss() {
      if (state.phase !== "running" && state.phase !== "confirming") {
        set({ phase: "idle" });
      }
    },

    async confirm() {
      if (state.phase !== "confirming") return;
      if (requestInFlight) {
        set({ phase: "blocked" });
        return;
      }
      requestInFlight = true;
      set({ phase: "running" });

      let created: AssessmentDetail;
      try {
        created = await options.run(options.original.target);
      } catch (error) {
        requestInFlight = false;
        set(errorState(error));
        return;
      }
      requestInFlight = false;

      const next = resultState(options.original, created);
      set(next);
      options.onCreated?.(created);
      if (next.phase === "complete") {
        options.onComplete?.({ beforeId: next.beforeId, afterId: next.afterId });
      }
    },
  };
}
