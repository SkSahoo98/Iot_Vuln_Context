import { useEffect, useState, type ReactNode } from "react";
import { fetchAssessment } from "../../api/assessments";
import type { AssessmentDetail, AssessmentFinding, AssessmentSummary } from "../../api/types";
import { compareAssessments } from "../../lib/assessmentComparison";
import { formatGeneratedAt } from "../../lib/format";
import {
  NO_VERIFICATION_COMPARISON,
  RUN_VERIFICATION_HINT,
  selectBaseline,
  verificationView,
  type VerificationSide,
  type VerificationView,
} from "../../lib/traceability";
import { SeverityBadge } from "../common/SeverityBadge";
import { formatNumber } from "./detailFormat";
import { isReassessable, type ReassessmentPair } from "./reassessment";

export type VerificationState =
  | { kind: "history_loading" }
  | { kind: "not_complete" }
  | { kind: "no_baseline" }
  | { kind: "loading"; baseline: AssessmentSummary }
  | { kind: "error"; baseline: AssessmentSummary }
  | { kind: "ready"; baseline: AssessmentSummary; view: VerificationView };

/** Loads the baseline with GET /assessments/{id}; comparing is compareAssessments'. */
export function useVerification(
  detail: AssessmentDetail,
  history: readonly AssessmentSummary[] | null,
): { state: VerificationState; retry: () => void } {
  const baseline =
    detail.status === "COMPLETE" && history ? selectBaseline(history, detail) : null;
  const baselineId = baseline?.id ?? null;
  const [loaded, setLoaded] = useState<{
    id: string;
    result: { ok: true; data: AssessmentDetail } | { ok: false };
  } | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!baselineId) return;
    let cancelled = false;
    fetchAssessment(baselineId).then(
      (data) => !cancelled && setLoaded({ id: baselineId, result: { ok: true, data } }),
      () => !cancelled && setLoaded({ id: baselineId, result: { ok: false } }),
    );
    return () => {
      cancelled = true;
    };
  }, [baselineId, attempt]);

  const retry = () => {
    setLoaded(null);
    setAttempt((value) => value + 1);
  };

  if (detail.status !== "COMPLETE") return { state: { kind: "not_complete" }, retry };
  if (!history) return { state: { kind: "history_loading" }, retry };
  if (!baseline) return { state: { kind: "no_baseline" }, retry };
  if (!loaded || loaded.id !== baseline.id) return { state: { kind: "loading", baseline }, retry };
  if (!loaded.result.ok) return { state: { kind: "error", baseline }, retry };
  return {
    state: {
      kind: "ready",
      baseline,
      view: verificationView(compareAssessments(loaded.result.data, detail)),
    },
    retry,
  };
}

const button =
  "btn-soft inline-flex min-h-11 items-center justify-center rounded-full border px-4 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50";
const primary = `${button} border-[var(--accent)]/40 bg-[var(--accent-soft)] text-[var(--accent)] hover:bg-[var(--accent)]/20`;
const secondary = `${button} border-white/10 bg-white/[0.04] text-[var(--muted)] hover:text-[var(--text)]`;

function Panel({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0 rounded-2xl border border-white/[0.06] bg-white/[0.02] px-4 py-3">
      <p className="text-[11px] font-medium uppercase tracking-[0.1em] text-[var(--muted)]">{label}</p>
      <div className="mt-2 space-y-1.5 text-sm">{children}</div>
    </div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
      <span className="text-[var(--muted)]">{label}</span>
      <span className="text-right">{children}</span>
    </div>
  );
}

function SidePanel({ label, side }: { label: string; side: VerificationSide }) {
  return (
    <Panel label={label}>
      <p className="mono text-xs text-[var(--muted)]">
        {formatGeneratedAt(side.detail.started_at) ?? "Start time not recorded"}
      </p>
      <Row label="Risk">
        {side.risk ? (
          <span className="inline-flex items-center gap-2">
            <span className="mono font-semibold">{formatNumber(side.risk.score)}</span>
            <SeverityBadge severity={side.risk.risk_level} />
          </span>
        ) : (
          "Not recorded"
        )}
      </Row>
      <Row label="Important issues">
        <span className="mono">{side.importantIssues}</span>
      </Row>
    </Panel>
  );
}

function riskChangeText(view: Extract<VerificationView, { kind: "compared" }>): string {
  if (view.riskDelta === null) {
    return view.riskUnavailable === "version_mismatch"
      ? "Not comparable (risk score versions differ)"
      : "Not recorded";
  }
  const value = formatNumber(view.riskDelta);
  return view.riskDelta > 0 ? `+${value} points` : `${value} points`;
}

const OUTCOMES = [
  { key: "resolved", label: "Resolved" },
  { key: "added", label: "New" },
  { key: "unchanged", label: "Unchanged" },
  { key: "notConfirmed", label: "Not confirmed" },
] as const;

function OutcomeList({ view }: { view: Extract<VerificationView, { kind: "compared" }> }) {
  const rows = OUTCOMES.flatMap(({ key, label }) =>
    view[key].map((finding: AssessmentFinding) => ({ label, finding })),
  );
  if (!rows.length) return null;
  return (
    <details className="group rounded-2xl border border-white/[0.06] bg-white/[0.02] px-4">
      <summary className="flex min-h-11 cursor-pointer list-none items-center gap-2 text-sm font-medium">
        <span aria-hidden className="text-[var(--muted)] transition-transform group-open:rotate-90">›</span>
        Outcome per finding ({rows.length})
      </summary>
      <ul className="space-y-1.5 pb-3 text-sm">
        {rows.map(({ label, finding }) => (
          <li
            key={`${label}-${finding.id}`}
            data-outcome={label}
            className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-white/[0.05] pt-1.5"
          >
            <span className="w-28 shrink-0 text-xs font-medium text-[var(--muted)]">{label}</span>
            <SeverityBadge severity={finding.severity} />
            <span className="min-w-0 flex-1 break-words">{finding.title}</span>
            <span className="mono text-xs text-[var(--muted)]">
              {finding.finding_id}
              {finding.port === null ? "" : ` :${finding.port}`}
            </span>
          </li>
        ))}
      </ul>
    </details>
  );
}

function NoComparison({
  reasons,
  canRun,
  onRunVerification,
}: {
  reasons?: string[];
  canRun: boolean;
  onRunVerification?: () => void;
}) {
  return (
    <div data-verification="none" className="space-y-2 rounded-2xl border border-white/[0.06] bg-white/[0.02] px-4 py-4">
      <p className="font-medium">{NO_VERIFICATION_COMPARISON}</p>
      {reasons?.length ? (
        <div className="text-sm text-[var(--muted)]">
          <p>The previous check of this target can't be compared with this one:</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-5">
            {reasons.map((reason) => (
              <li key={reason} className="break-words">{reason}</li>
            ))}
          </ul>
        </div>
      ) : null}
      <p className="text-sm text-[var(--muted)]">{RUN_VERIFICATION_HINT}</p>
      {canRun && onRunVerification ? (
        <button type="button" onClick={onRunVerification} className={primary}>
          Run verification check
        </button>
      ) : null}
    </div>
  );
}

type Props = {
  detail: AssessmentDetail;
  state: VerificationState;
  onRetry: () => void;
  onRunVerification?: () => void;
  onOpenComparison?: (pair: ReassessmentPair) => void;
};

export function VerificationEvaluation({
  detail,
  state,
  onRetry,
  onRunVerification,
  onOpenComparison,
}: Props) {
  const canRun = isReassessable(detail);
  if (state.kind === "not_complete") {
    return (
      <div data-verification="not_complete" className="rounded-2xl border border-white/[0.06] bg-white/[0.02] px-4 py-4 text-sm">
        <p className="font-medium">{NO_VERIFICATION_COMPARISON}</p>
        <p className="mt-1 text-[var(--muted)]">
          Only completed checks can be compared. This check's status is{" "}
          <span className="mono">{detail.status}</span>.
        </p>
      </div>
    );
  }
  if (state.kind === "no_baseline") {
    return <NoComparison canRun={canRun} onRunVerification={onRunVerification} />;
  }
  if (state.kind === "loading" || state.kind === "history_loading") {
    return <p className="text-sm text-[var(--muted)]">Loading the previous check of this target…</p>;
  }
  if (state.kind === "error") {
    return (
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <p className="text-[var(--danger)]">The previous check of this target could not be loaded.</p>
        <button type="button" onClick={onRetry} className={secondary}>
          Retry
        </button>
      </div>
    );
  }
  const { view } = state;
  if (view.kind === "not_comparable") {
    return <NoComparison reasons={view.reasons} canRun={canRun} onRunVerification={onRunVerification} />;
  }
  return (
    <div data-verification="compared" className="space-y-3">
      <div className="grid gap-3 md:grid-cols-3">
        <SidePanel label="Baseline" side={view.baseline} />
        <SidePanel label="Verification" side={view.verification} />
        <Panel label="Change">
          <Row label="Risk change">
            <span className="mono">{riskChangeText(view)}</span>
          </Row>
          {OUTCOMES.map(({ key, label }) => (
            <Row key={key} label={label}>
              <span className="mono">{view[key].length}</span>
            </Row>
          ))}
        </Panel>
      </div>
      <OutcomeList view={view} />
      {view.warnings.length ? (
        <ul className="list-disc space-y-0.5 pl-5 text-xs text-[var(--muted)]">
          {view.warnings.map((warning) => (
            <li key={warning} className="break-words">{warning}</li>
          ))}
        </ul>
      ) : null}
      <p className="text-xs text-[var(--muted)]">
        Outcomes come from the deterministic comparison of the two recorded checks. A finding is
        only resolved when the verification check evaluated it and did not report it.
      </p>
      {onOpenComparison ? (
        <button
          type="button"
          onClick={() => onOpenComparison({ beforeId: view.baseline.detail.id, afterId: view.verification.detail.id })}
          className={secondary}
        >
          Open full comparison
        </button>
      ) : null}
    </div>
  );
}
