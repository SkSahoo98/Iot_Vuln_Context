/**
 * Intent -> workflow -> action -> destination. Resolution only describes what
 * should happen next; it never starts a check, a re-assessment, a scan or an
 * AI request. Whatever runs later goes through the existing UI workflows and
 * their confirmations.
 */
import type { NavRequest } from "../navigation";
import type { AssistantContext } from "./context";
import type { AssistantIntent, AssistantIntentResult } from "./intents";

export type AssistantWorkflow =
  | "ASSESSMENT_CREATION"
  | "LATEST_ASSESSMENT_CONTEXT"
  | "IMPORTANT_FINDINGS"
  | "REASSESSMENT_COMPARISON"
  | "ASSESSMENT_SUMMARY"
  | "CLARIFICATION";

export const INTENT_WORKFLOWS: Record<
  AssistantIntent,
  { workflow: AssistantWorkflow; description: string }
> = {
  CHECK: {
    workflow: "ASSESSMENT_CREATION",
    description: "Existing assessment form; the backend checks the target is authorized.",
  },
  EXPLAIN: {
    workflow: "LATEST_ASSESSMENT_CONTEXT",
    description: "Risk and issues recorded in the latest complete assessment.",
  },
  FIX: {
    workflow: "IMPORTANT_FINDINGS",
    description: "Important findings of the latest complete assessment and their recorded remediation.",
  },
  VERIFY: {
    workflow: "REASSESSMENT_COMPARISON",
    description: "Re-assess the latest complete assessment's target, then compare BEFORE and AFTER.",
  },
  FIXED: {
    workflow: "REASSESSMENT_COMPARISON",
    description: "The user reports a change; verifying it needs an explicitly started new check.",
  },
  COMPARE: {
    workflow: "REASSESSMENT_COMPARISON",
    description: "BEFORE/AFTER of a check run from the assistant, from the existing comparison.",
  },
  SUMMARY: {
    workflow: "ASSESSMENT_SUMMARY",
    description: "Status, risk and issue counts of the latest assessment.",
  },
  TECHNICAL: {
    workflow: "LATEST_ASSESSMENT_CONTEXT",
    description: "Ports, services, findings, evidence and risk factors recorded in the latest complete assessment.",
  },
  UNKNOWN: {
    workflow: "CLARIFICATION",
    description: "Ask the user which supported task they want.",
  },
};

export type AssistantActionType =
  | "OPEN_ASSESSMENT"
  | "OPEN_SECURITY"
  | "OPEN_FINDING"
  | "OPEN_RISK"
  | "OPEN_REASSESSMENT"
  | "SHOW_SUMMARY"
  | "ASK_CLARIFICATION";

export type AssistantAction = {
  type: AssistantActionType;
  assessmentId?: string;
  findingCheckId?: string;
  reason: string;
};

export type AssistantState = "READY" | "LOADING" | "NEEDS_ASSESSMENT" | "NEEDS_CLARIFICATION";

/** Why an intent cannot proceed; null when it can. */
export type AssistantBlocker =
  | "ASSESSMENTS_LOADING"
  | "NO_ASSESSMENT"
  | "NO_COMPLETE_ASSESSMENT"
  | "LATEST_NOT_COMPLETE"
  | "ISSUES_LOADING"
  | "ISSUES_UNAVAILABLE"
  | "NO_IMPORTANT_ISSUES"
  | "UNCLEAR_REQUEST";

export type AssistantResolution = {
  intent: AssistantIntent;
  workflow: AssistantWorkflow;
  state: AssistantState;
  action: AssistantAction;
  blocker: AssistantBlocker | null;
  /** Where the action leads in the app; null for ASK_CLARIFICATION. */
  destination: NavRequest | null;
};

export const CLARIFICATION_REASON =
  "The request didn't match a supported task. I can open a new security check, explain or help fix issues from your latest completed check, verify a fix, or summarize your last check.";

/** The single mapping from action to app destination. */
export function actionDestination(action: AssistantAction): NavRequest | null {
  switch (action.type) {
    case "OPEN_ASSESSMENT":
      return {
        section: "history",
        anchor: { id: "new-security-check", focusId: "assessment-target" },
      };
    case "OPEN_SECURITY":
    case "OPEN_FINDING":
      return { section: "security", anchor: { id: "security-issues" } };
    case "OPEN_RISK":
      return { section: "security", securityTechnical: true, anchor: { id: "assessment-risk" } };
    case "OPEN_REASSESSMENT":
      return {
        section: "history",
        assessmentId: action.assessmentId,
        anchor: { id: "assessment-reassessment" },
      };
    case "SHOW_SUMMARY":
      return { section: "security" };
    case "ASK_CLARIFICATION":
      return null;
  }
}

export type WorkflowDestinationId =
  | "open-check-form"
  | "review-issues"
  | "technical-details"
  | "open-comparison";

/** Destinations of the assistant's workflow buttons; all are existing app sections. */
export function workflowDestination(
  id: WorkflowDestinationId,
  pair: { beforeId: string; afterId: string } | null,
): NavRequest | null {
  switch (id) {
    case "open-check-form":
      return actionDestination({ type: "OPEN_ASSESSMENT", reason: "" });
    case "review-issues":
      return actionDestination({ type: "OPEN_SECURITY", reason: "" });
    case "technical-details":
      return { section: "security", securityTechnical: true, anchor: { id: "assessment-findings" } };
    case "open-comparison":
      return pair ? { section: "history", comparison: pair } : null;
  }
}

function ready(intent: AssistantIntent, action: AssistantAction): AssistantResolution {
  return {
    intent,
    workflow: INTENT_WORKFLOWS[intent].workflow,
    state: "READY",
    action,
    blocker: null,
    destination: actionDestination(action),
  };
}

function blocked(
  intent: AssistantIntent,
  blocker: AssistantBlocker,
  reason: string,
): AssistantResolution {
  const state: AssistantState =
    blocker === "UNCLEAR_REQUEST"
      ? "NEEDS_CLARIFICATION"
      : blocker === "ASSESSMENTS_LOADING" || blocker === "ISSUES_LOADING"
        ? "LOADING"
        : "NEEDS_ASSESSMENT";
  return {
    intent,
    workflow: INTENT_WORKFLOWS[intent].workflow,
    state,
    action: { type: "ASK_CLARIFICATION", reason },
    blocker,
    destination: null,
  };
}

/** Blocker and reason when the latest assessment is missing or not COMPLETE. */
function latestNotComplete(
  intent: AssistantIntent,
  context: AssistantContext,
  reasons: { none: string; incomplete: string; running: string },
): AssistantResolution {
  if (context.availability === "NO_ASSESSMENT") {
    return blocked(intent, "NO_ASSESSMENT", reasons.none);
  }
  return blocked(
    intent,
    "LATEST_NOT_COMPLETE",
    context.availability === "ASSESSMENT_RUNNING" ? reasons.running : reasons.incomplete,
  );
}

/**
 * @param context null while the assessment list has not loaded.
 */
export function resolveAssistantIntent(
  intent: AssistantIntentResult,
  context: AssistantContext | null,
): AssistantResolution {
  const name = intent.intent;

  if (name === "UNKNOWN") return blocked(name, "UNCLEAR_REQUEST", CLARIFICATION_REASON);

  if (name === "CHECK") {
    return ready(name, {
      type: "OPEN_ASSESSMENT",
      reason:
        "Opens the security check form. A check runs only after you start it, and only against authorized targets.",
    });
  }

  if (!context) {
    return blocked(name, "ASSESSMENTS_LOADING", "Your security checks are still loading.");
  }
  const latest = context.latestAssessment;

  switch (name) {
    case "TECHNICAL": {
      if (!context.capabilities.canExplain || !latest) {
        return latestNotComplete(name, context, {
          none: "No completed security assessment is available to answer from.",
          incomplete:
            "Your latest security check did not complete, so there are no current results to answer from.",
          running:
            "Your latest security check has not finished, so there are no current results to answer from yet.",
        });
      }
      return intent.subject === "RISK_FACTORS"
        ? ready(name, {
            type: "OPEN_RISK",
            assessmentId: latest.id,
            reason: "Shows the risk factors recorded by the backend for your latest completed check.",
          })
        : ready(name, {
            type: "OPEN_SECURITY",
            assessmentId: latest.id,
            reason: "Shows what your latest completed check recorded.",
          });
    }

    case "EXPLAIN": {
      if (!context.capabilities.canExplain || !latest) {
        return latestNotComplete(name, context, {
          none: "No completed security assessment is available to explain.",
          incomplete:
            "Your latest security check did not complete, so there is no current security explanation.",
          running:
            "Your latest security check has not finished, so there is no current security explanation yet.",
        });
      }
      return intent.subject === "RISK"
        ? ready(name, {
            type: "OPEN_RISK",
            assessmentId: latest.id,
            reason: "Shows the risk recorded by the backend for your latest completed check.",
          })
        : ready(name, {
            type: "OPEN_SECURITY",
            assessmentId: latest.id,
            reason: "Shows the issues recorded in your latest completed check.",
          });
    }

    case "FIX": {
      if (context.availability !== "ASSESSMENT_AVAILABLE" || !latest) {
        return latestNotComplete(name, context, {
          none: "No completed security assessment with an important issue is available to fix.",
          incomplete:
            "Your latest security check did not complete, so there are no current issues to fix.",
          running:
            "Your latest security check has not finished, so there are no current issues to fix yet.",
        });
      }
      if (context.issueStatus === "LOADING") {
        return blocked(name, "ISSUES_LOADING", "The issues from your latest check are still loading.");
      }
      if (context.issueStatus !== "AVAILABLE" || !context.importantIssues) {
        return blocked(
          name,
          "ISSUES_UNAVAILABLE",
          "The issues from your latest check could not be loaded.",
        );
      }
      const [first] = context.importantIssues;
      if (!first || !context.capabilities.canFix) {
        return blocked(
          name,
          "NO_IMPORTANT_ISSUES",
          "There is no identified important issue to remediate in your latest completed check.",
        );
      }
      return ready(name, {
        type: "OPEN_FINDING",
        assessmentId: latest.id,
        findingCheckId: first.checkId,
        reason: `Shows the recorded fix for "${first.title}" and the other important issues in your latest completed check.`,
      });
    }

    case "VERIFY":
    case "FIXED":
    case "COMPARE": {
      const baseline = context.verificationBaseline;
      if (!context.capabilities.canVerify || !baseline) {
        return blocked(
          name,
          context.availability === "NO_ASSESSMENT" ? "NO_ASSESSMENT" : "NO_COMPLETE_ASSESSMENT",
          "Verification cannot begin because no security check has completed.",
        );
      }
      return ready(name, {
        type: "OPEN_REASSESSMENT",
        assessmentId: baseline.assessmentId,
        reason: `Verification needs a new check of ${baseline.target} to compare with your last completed check. This opens the re-assessment step; nothing runs until you confirm.`,
      });
    }

    case "SUMMARY": {
      if (!context.capabilities.canSummarize || !latest) {
        return blocked(
          name,
          "NO_ASSESSMENT",
          "No security summary is available because no security check has been run.",
        );
      }
      return ready(name, {
        type: "SHOW_SUMMARY",
        assessmentId: latest.id,
        reason:
          context.availability === "ASSESSMENT_AVAILABLE"
            ? "Shows the result of your latest completed check."
            : context.availability === "ASSESSMENT_RUNNING"
              ? "Shows your latest security check. It has not finished, so no current risk is shown."
              : "Shows what happened in your latest security check. It did not complete, so no current risk is shown.",
      });
    }
  }
}
