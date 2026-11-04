import { useEffect, useRef, useState, type ReactNode } from "react";
import { createAssessment } from "../../api/assessments";
import type { AssessmentDetail } from "../../api/types";
import {
  createReassessmentFlow,
  isReassessable,
  type ReassessmentOriginal,
  type ReassessmentPair,
  type ReassessmentState,
} from "./reassessment";

const primaryButton =
  "btn-soft inline-flex items-center justify-center gap-2 rounded-full border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-4 py-2 text-xs font-medium text-[var(--accent)] hover:bg-[var(--accent)]/20 disabled:cursor-not-allowed disabled:opacity-50";
const secondaryButton =
  "btn-soft rounded-full border border-white/10 bg-white/[0.04] px-4 py-2 text-xs font-medium text-[var(--muted)] hover:text-[var(--text)] disabled:cursor-not-allowed disabled:opacity-50";

type ViewProps = {
  original: ReassessmentOriginal;
  state: ReassessmentState;
  onRequest: () => void;
  onCancel: () => void;
  onConfirm: () => void;
  onDismiss: () => void;
  onOpenAssessment?: (assessmentId: string) => void;
};

function Notice({
  tone,
  title,
  children,
}: {
  tone: "info" | "warn" | "danger" | "ok";
  title: string;
  children?: ReactNode;
}) {
  const toneClass = {
    info: "border-[var(--accent)]/35 bg-[var(--accent)]/[0.07]",
    ok: "border-[var(--ok)]/35 bg-[var(--ok)]/10",
    warn: "border-[var(--warn)]/35 bg-[var(--warn)]/10",
    danger: "border-[var(--danger)]/35 bg-[var(--danger)]/10",
  }[tone];
  const titleClass = {
    info: "text-[var(--accent)]",
    ok: "text-[var(--ok)]",
    warn: "text-[var(--warn)]",
    danger: "text-[var(--danger)]",
  }[tone];
  return (
    <div className={`rounded-xl border px-4 py-3 text-sm ${toneClass}`}>
      <p className={`font-medium ${titleClass}`}>{title}</p>
      {children ? (
        <div className="mt-1.5 space-y-1.5 text-[var(--text)]/90">{children}</div>
      ) : null}
    </div>
  );
}

function CreatedDetails({
  created,
  onOpenAssessment,
}: {
  created: AssessmentDetail;
  onOpenAssessment?: (assessmentId: string) => void;
}) {
  return (
    <>
      <p>
        {"New assessment ID: "}
        <span className="mono break-all text-xs">{created.id}</span>
      </p>
      {created.error_summary ? (
        <p>
          {"Backend summary: "}
          <span className="break-words">{created.error_summary}</span>
        </p>
      ) : null}
      <p className="text-[var(--muted)]">
        The assessment is saved in the assessment history.
      </p>
      {onOpenAssessment ? (
        <button
          type="button"
          onClick={() => onOpenAssessment(created.id)}
          className={`${secondaryButton} mt-1`}
        >
          Open new assessment
        </button>
      ) : null}
    </>
  );
}

export function ReassessmentPanelView({
  original,
  state,
  onRequest,
  onCancel,
  onConfirm,
  onDismiss,
  onOpenAssessment,
}: ViewProps) {
  if (!isReassessable(original)) return null;

  const dismiss = (
    <button type="button" onClick={onDismiss} className={`${secondaryButton} mt-1`}>
      Dismiss
    </button>
  );

  return (
    <section
      id="assessment-reassessment"
      aria-label="Re-assessment"
      aria-live="polite"
      className="surface-panel scroll-mt-24 space-y-3 rounded-2xl px-4 py-4"
    >
      {state.phase === "idle" ? (
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <p className="text-sm font-medium text-[var(--text)]">Re-assessment</p>
            <p className="mt-0.5 text-xs text-[var(--muted)]">
              Run a new assessment of{" "}
              <span className="mono text-[var(--text)]">{original.target}</span> and
              open it in the comparison view with this assessment as BEFORE.
            </p>
          </div>
          <button type="button" onClick={onRequest} className={`${primaryButton} shrink-0`}>
            Re-assess this target
          </button>
        </div>
      ) : null}

      {state.phase === "confirming" ? (
        <div role="alertdialog" aria-labelledby="reassess-confirm-title" className="space-y-3">
          <p id="reassess-confirm-title" className="text-base font-semibold text-[var(--text)]">
            Re-assess <span className="mono">{original.target}</span>?
          </p>
          <div className="space-y-1.5 text-sm text-[var(--text)]/90">
            <p>
              This will run the active security assessment probes against this
              target again. The assessment may take several minutes.
            </p>
            <p>
              Only continue if this target is authorized for assessment. The
              backend checks its allowlist and refuses targets that are not on it.
            </p>
            <p className="text-[var(--muted)]">
              A re-assessment only records a new assessment; it does not change
              the target.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button type="button" onClick={onCancel} className={secondaryButton}>
              Cancel
            </button>
            <button type="button" onClick={onConfirm} className={primaryButton}>
              Start Re-assessment
            </button>
          </div>
        </div>
      ) : null}

      {state.phase === "running" ? (
        <div role="status" className="flex items-start gap-3">
          <span
            className="mt-0.5 h-4 w-4 shrink-0 animate-spin rounded-full border-2 border-[var(--accent)]/25 border-t-[var(--accent)]"
            aria-hidden
          />
          <div className="space-y-1 text-sm">
            <p className="font-medium text-[var(--text)]">Assessment running...</p>
            <p className="text-[var(--muted)]">
              Active probes are being executed against{" "}
              <span className="mono text-[var(--text)]">{original.target}</span>. This
              may take several minutes. The result appears here when the backend
              responds.
            </p>
          </div>
        </div>
      ) : null}

      {state.phase === "blocked" ? (
        <Notice tone="warn" title="A re-assessment is already running in this browser tab.">
          <p>Wait for it to finish before starting another one.</p>
          <button type="button" onClick={onCancel} className={`${secondaryButton} mt-1`}>
            Close
          </button>
        </Notice>
      ) : null}

      {state.phase === "complete" ? (
        <Notice tone="ok" title="Re-assessment completed.">
          <p>
            {"BEFORE: "}
            <span className="mono break-all text-xs">{state.beforeId}</span>
          </p>
          <p>
            {"AFTER: "}
            <span className="mono break-all text-xs">{state.afterId}</span>
          </p>
          <p className="text-[var(--muted)]">
            Both assessments were pre-selected in the comparison view.
          </p>
          {dismiss}
        </Notice>
      ) : null}

      {state.phase === "not_complete" ? (
        <Notice
          tone="warn"
          title={`The re-assessment finished with status ${state.created.status}.`}
        >
          <p>
            Comparison was not started because only COMPLETE assessments can be
            compared.
          </p>
          <CreatedDetails created={state.created} onOpenAssessment={onOpenAssessment} />
          {dismiss}
        </Notice>
      ) : null}

      {state.phase === "failed" ? (
        <Notice tone="danger" title="The re-assessment failed.">
          <p>Comparison was not started.</p>
          <CreatedDetails created={state.created} onOpenAssessment={onOpenAssessment} />
          {dismiss}
        </Notice>
      ) : null}

      {state.phase === "error" ? (
        <Notice
          tone="danger"
          title={
            state.httpStatus
              ? `The backend rejected the re-assessment (HTTP ${state.httpStatus}).`
              : "The re-assessment request could not be completed."
          }
        >
          <p className="break-words">{state.message}</p>
          <p className="text-[var(--muted)]">Comparison was not started.</p>
          {dismiss}
        </Notice>
      ) : null}
    </section>
  );
}

type PanelProps = {
  assessment: AssessmentDetail;
  onCreated?: (created: AssessmentDetail) => void;
  onComplete?: (pair: ReassessmentPair) => void;
  onOpenAssessment?: (assessmentId: string) => void;
  run?: (target: string) => Promise<AssessmentDetail>;
  /** Each new value opens the confirmation step; it never starts a check. */
  requestToken?: number;
};

export function ReassessmentPanel({
  assessment,
  onCreated,
  onComplete,
  onOpenAssessment,
  run = createAssessment,
  requestToken = 0,
}: PanelProps) {
  const callbacks = useRef({ onCreated, onComplete });
  callbacks.current = { onCreated, onComplete };
  const [state, setState] = useState<ReassessmentState>({ phase: "idle" });
  const [flow] = useState(() =>
    createReassessmentFlow({
      original: {
        id: assessment.id,
        target: assessment.target,
        status: assessment.status,
      },
      run,
      onState: setState,
      onCreated: (created) => callbacks.current.onCreated?.(created),
      onComplete: (pair) => callbacks.current.onComplete?.(pair),
    }),
  );

  useEffect(() => {
    if (requestToken > 0) flow.request();
  }, [flow, requestToken]);

  return (
    <ReassessmentPanelView
      original={assessment}
      state={state}
      onRequest={flow.request}
      onCancel={flow.cancel}
      onConfirm={() => void flow.confirm()}
      onDismiss={flow.dismiss}
      onOpenAssessment={onOpenAssessment}
    />
  );
}
