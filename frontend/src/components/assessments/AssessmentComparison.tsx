import { useMemo, useRef, useState } from "react";
import { fetchAssessment } from "../../api/assessments";
import type { AssessmentSummary } from "../../api/types";
import {
  compareAssessments,
  type AssessmentComparisonResult as ComparisonData,
} from "../../lib/assessmentComparison";
import { formatFactorLabel, formatGeneratedAt } from "../../lib/format";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { AssessmentComparisonResult } from "./AssessmentComparisonResult";
import { formatNumber } from "./detailFormat";

type Props = {
  assessments: AssessmentSummary[] | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
  initialBeforeId?: string;
  initialAfterId?: string;
};

type ComparisonState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; data: ComparisonData };

const ALL_TARGETS = "";

const selectClass =
  "glass-inset mono w-full min-w-0 rounded-xl px-3 py-2.5 text-xs text-[var(--text)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]/50 disabled:cursor-not-allowed disabled:opacity-60 sm:text-sm";

const labelClass =
  "mb-1.5 block text-[11px] font-medium uppercase tracking-[0.1em] text-[var(--muted)]";

function optionLabel(assessment: AssessmentSummary): string {
  const risk =
    assessment.highest_risk === null
      ? "no overall risk"
      : `risk ${formatNumber(assessment.highest_risk)} ${assessment.highest_risk_level ?? ""}`.trim();
  return [
    assessment.id.slice(0, 8),
    assessment.target,
    formatFactorLabel(assessment.assessment_type),
    formatGeneratedAt(assessment.started_at) ?? "start not recorded",
    risk,
    assessment.status,
  ].join(" · ");
}

function AssessmentSelect({
  id,
  label,
  value,
  options,
  excludedId,
  disabled,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  options: AssessmentSummary[];
  excludedId: string;
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <div className="min-w-0 flex-1">
      <label htmlFor={id} className={labelClass}>
        {label}
      </label>
      <select
        id={id}
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
        className={selectClass}
      >
        <option value="">Select assessment…</option>
        {options.map((assessment) => (
          <option
            key={assessment.id}
            value={assessment.id}
            disabled={assessment.id === excludedId}
          >
            {optionLabel(assessment)}
          </option>
        ))}
      </select>
    </div>
  );
}

export function AssessmentComparison({
  assessments,
  loading,
  error,
  onRefresh,
  initialBeforeId,
  initialAfterId,
}: Props) {
  const [targetFilter, setTargetFilter] = useState(ALL_TARGETS);
  const [beforeId, setBeforeId] = useState(initialBeforeId ?? "");
  const [afterId, setAfterId] = useState(initialAfterId ?? "");
  const [comparison, setComparison] = useState<ComparisonState>({ status: "idle" });
  const requestRef = useRef(0);

  const complete = useMemo(
    () => (assessments ?? []).filter((item) => item.status === "COMPLETE"),
    [assessments],
  );
  const excludedCount = (assessments?.length ?? 0) - complete.length;
  const targets = useMemo(
    () => [...new Set(complete.map((item) => item.target))].sort(),
    [complete],
  );
  const options = useMemo(
    () =>
      targetFilter === ALL_TARGETS
        ? complete
        : complete.filter((item) => item.target === targetFilter),
    [complete, targetFilter],
  );

  const validBefore = options.some((item) => item.id === beforeId) ? beforeId : "";
  const validAfter = options.some((item) => item.id === afterId) ? afterId : "";
  const busy = comparison.status === "loading";
  const canCompare =
    Boolean(validBefore && validAfter) && validBefore !== validAfter && !busy;

  async function handleCompare() {
    if (!canCompare) return;
    const request = ++requestRef.current;
    setComparison({ status: "loading" });
    try {
      const [before, after] = await Promise.all([
        fetchAssessment(validBefore),
        fetchAssessment(validAfter),
      ]);
      if (request !== requestRef.current) return;
      setComparison({ status: "ready", data: compareAssessments(before, after) });
    } catch (err: unknown) {
      if (request !== requestRef.current) return;
      setComparison({
        status: "error",
        message: err instanceof Error ? err.message : "Failed to load assessments",
      });
    }
  }

  if (loading && !assessments) {
    return <LoadingState message="Loading assessment history..." />;
  }
  if (error) {
    return <ErrorState message={error} onRetry={onRefresh} />;
  }

  return (
    <div className="space-y-6">
      <section className="surface-panel space-y-4 rounded-2xl px-5 py-5">
        <div>
          <h2 className="text-base font-semibold text-[var(--text)]">
            Assessment comparison
          </h2>
          <p className="mt-1 text-sm text-[var(--muted)]">
            Compare two recorded assessments. Findings, coverage and risk values
            come from the backend; the dashboard only matches and groups them.
          </p>
        </div>

        {initialBeforeId && initialAfterId ? (
          <div className="rounded-xl border border-[var(--accent)]/30 bg-[var(--accent)]/[0.07] px-4 py-3 text-sm">
            <p className="text-[var(--text)]">
              {"Pre-selected from a re-assessment: BEFORE "}
              <span className="mono text-xs">{initialBeforeId}</span>
              {", AFTER "}
              <span className="mono text-xs">{initialAfterId}</span>.
            </p>
            {complete.some((item) => item.id === initialAfterId) ? (
              <p className="mt-1 text-[var(--muted)]">
                Select Compare Assessments to view the comparison.
              </p>
            ) : (
              <p className="mt-1 text-[var(--muted)]">
                {loading
                  ? "Loading the new assessment into the history..."
                  : "The new assessment is not in the loaded history yet. Use Refresh in the history view."}
              </p>
            )}
          </div>
        ) : null}

        {complete.length < 2 ? (
          <EmptyState message="At least two COMPLETE assessments are required for a comparison." />
        ) : (
          <>
            {targets.length > 1 ? (
              <div className="max-w-sm">
                <label htmlFor="comparison-target" className={labelClass}>
                  Target filter
                </label>
                <select
                  id="comparison-target"
                  value={targetFilter}
                  disabled={busy}
                  onChange={(event) => setTargetFilter(event.target.value)}
                  className={selectClass}
                >
                  <option value={ALL_TARGETS}>All targets</option>
                  {targets.map((target) => (
                    <option key={target} value={target}>
                      {target}
                    </option>
                  ))}
                </select>
              </div>
            ) : null}

            <div className="flex flex-col gap-3 lg:flex-row lg:items-end">
              <AssessmentSelect
                id="comparison-before"
                label="Before assessment"
                value={validBefore}
                options={options}
                excludedId={validAfter}
                disabled={busy}
                onChange={setBeforeId}
              />
              <AssessmentSelect
                id="comparison-after"
                label="After assessment"
                value={validAfter}
                options={options}
                excludedId={validBefore}
                disabled={busy}
                onChange={setAfterId}
              />
              <button
                type="button"
                onClick={() => void handleCompare()}
                disabled={!canCompare}
                aria-busy={busy}
                className="btn-soft inline-flex shrink-0 items-center justify-center gap-2 rounded-full border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-4 py-2.5 text-xs font-medium text-[var(--accent)] hover:bg-[var(--accent)]/20 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {busy ? (
                  <span
                    className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-[var(--accent)]/25 border-t-[var(--accent)]"
                    aria-hidden
                  />
                ) : null}
                {busy ? "Comparing..." : "Compare Assessments"}
              </button>
            </div>

            <p className="text-xs text-[var(--muted)]">
              Only COMPLETE assessments are listed
              {excludedCount > 0
                ? ` (${excludedCount} with another status excluded)`
                : ""}
              . An assessment cannot be selected on both sides.
            </p>
          </>
        )}
      </section>

      <div aria-live="polite">
        {comparison.status === "loading" ? (
          <LoadingState message="Loading both assessments..." />
        ) : comparison.status === "error" ? (
          <ErrorState message={comparison.message} onRetry={() => void handleCompare()} />
        ) : comparison.status === "ready" ? (
          <AssessmentComparisonResult
            key={`${comparison.data.before.id}:${comparison.data.after.id}`}
            comparison={comparison.data}
          />
        ) : null}
      </div>
    </div>
  );
}
