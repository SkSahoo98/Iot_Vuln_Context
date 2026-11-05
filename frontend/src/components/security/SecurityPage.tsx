import { useState } from "react";
import type { AssessmentDetail, AssessmentSummary } from "../../api/types";
import type { NavAnchor, NavRequest } from "../../lib/navigation";
import { securityHomeState } from "../../lib/securityHome";
import { AssessmentDetails } from "../assessments/AssessmentDetails";
import { OverviewPage } from "../overview/OverviewPage";
import type { DeviceContext } from "../overview/SecurityHomeView";

type Props = {
  assessments: AssessmentSummary[] | null;
  assessmentsError: string | null;
  onRetryAssessments: () => void;
  deviceContext: DeviceContext | null;
  initialTechnicalOpen?: boolean;
  onNavigate: (request: NavRequest) => void;
  onScrollTo: (anchor: NavAnchor) => void;
  onReassessmentCreated: (created: AssessmentDetail) => void;
  isReadOnly?: boolean;
};

const TECHNICAL_ID = "security-technical";

export function SecurityPage({
  assessments,
  assessmentsError,
  onRetryAssessments,
  deviceContext,
  initialTechnicalOpen = false,
  onNavigate,
  onScrollTo,
  onReassessmentCreated,
  isReadOnly = false,
}: Props) {
  const [technicalOpen, setTechnicalOpen] = useState(initialTechnicalOpen);
  const state = assessments ? securityHomeState(assessments) : null;
  const latestId = state && state.kind !== "empty" ? state.latest.id : null;

  function checkAgain(assessmentId: string | null) {
    if (isReadOnly) {
      onNavigate({
        section: "history",
        assessmentId: assessmentId ?? undefined,
      });
      return;
    }
    if (assessmentId && state?.kind === "complete") {
      onNavigate({
        section: "history",
        assessmentId,
        anchor: { id: "assessment-reassessment" },
      });
      return;
    }
    onNavigate({
      section: "history",
      assessmentId: assessmentId ?? undefined,
      anchor: { id: "new-security-check", focusId: "assessment-target" },
    });
  }

  function showTechnicalDetails() {
    setTechnicalOpen(true);
    onScrollTo({ id: TECHNICAL_ID });
  }

  return (
    <div className="space-y-8">
      <OverviewPage
        assessments={assessments}
        assessmentsError={assessmentsError}
        onRetryAssessments={onRetryAssessments}
        deviceContext={deviceContext}
        onCheckSecurity={checkAgain}
        onShowDetails={showTechnicalDetails}
        isReadOnly={isReadOnly}
        onNavigate={onNavigate}
      />

      {latestId ? (
        <section
          id={TECHNICAL_ID}
          aria-labelledby="security-technical-heading"
          className="scroll-mt-24 space-y-4 border-t border-white/[0.06] pt-6"
        >
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <h2
                id="security-technical-heading"
                className="font-display text-base font-semibold"
              >
                Technical details
              </h2>
              <p className="mt-1 text-sm text-[var(--muted)]">
                Evidence, findings, risk factors and metadata recorded for this check.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setTechnicalOpen((value) => !value)}
              aria-expanded={technicalOpen}
              aria-controls="security-technical-panel"
              className="btn-soft inline-flex min-h-11 shrink-0 items-center justify-center rounded-full border border-white/10 bg-white/[0.04] px-5 text-sm font-medium text-[var(--text)] hover:border-[var(--accent)]/35"
            >
              {technicalOpen ? "Hide technical details" : "Show technical details"}
            </button>
          </div>
          <div id="security-technical-panel">
            {technicalOpen ? (
              <AssessmentDetails
                key={latestId}
                assessmentId={latestId}
                history={assessments}
                onReassessmentCreated={onReassessmentCreated}
                onReassessmentComplete={(pair) =>
                  onNavigate({ section: "history", comparison: pair })
                }
                onOpenAssessment={(assessmentId) =>
                  onNavigate({ section: "history", assessmentId })
                }
                onOpenComparison={(pair) => onNavigate({ section: "history", comparison: pair })}
                onOpenResearch={() => onNavigate({ section: "risk" })}
                isReadOnly={isReadOnly}
              />
            ) : null}
          </div>
        </section>
      ) : null}
    </div>
  );
}
