import { useCallback, type ReactNode } from "react";
import { fetchExperiments } from "../../api/security";
import type { AssessmentDetail } from "../../api/types";
import { useAsyncData } from "../../hooks/useAsyncData";
import { formatFactorLabel, formatGeneratedAt } from "../../lib/format";
import { GROUND_TRUTH_NOT_CONFIGURED, buildEvaluationSummary } from "../../lib/traceability";
import { SeverityBadge } from "../common/SeverityBadge";
import { StatusBadge } from "../common/StatusBadge";
import { statusTone } from "./AssessmentList";
import { formatNumber } from "./detailFormat";
import type { VerificationState } from "./VerificationEvaluation";

function Card({ title, children, wide }: { title: string; children: ReactNode; wide?: boolean }) {
  return (
    <section
      aria-label={title}
      className={`min-w-0 rounded-2xl border border-white/[0.06] bg-white/[0.02] px-4 py-3 ${
        wide ? "sm:col-span-2 lg:col-span-3" : ""
      }`}
    >
      <h4 className="text-[11px] font-medium uppercase tracking-[0.1em] text-[var(--muted)]">{title}</h4>
      <dl className="mt-2 space-y-1.5 text-sm">{children}</dl>
    </section>
  );
}

function Item({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
      <dt className="text-[var(--muted)]">{label}</dt>
      <dd className="min-w-0 break-words text-right">{children}</dd>
    </div>
  );
}

function verificationText(state: VerificationState): { baseline: string; comparison: string } {
  switch (state.kind) {
    case "history_loading":
      return { baseline: "Loading…", comparison: "Loading…" };
    case "not_complete":
      return { baseline: "Not applicable", comparison: "Not available (check not complete)" };
    case "no_baseline":
      return { baseline: "No earlier completed check", comparison: "Not available" };
    case "loading":
      return { baseline: formatGeneratedAt(state.baseline.started_at) ?? "Recorded", comparison: "Loading…" };
    case "error":
      return { baseline: formatGeneratedAt(state.baseline.started_at) ?? "Recorded", comparison: "Could not be loaded" };
    case "ready":
      return {
        baseline: formatGeneratedAt(state.baseline.started_at) ?? "Recorded",
        comparison: state.view.kind === "compared" ? "Available" : "Not available (not comparable)",
      };
  }
}

type Props = {
  detail: AssessmentDetail;
  verification: VerificationState;
  onOpenResearch?: () => void;
};

export function EvaluationSummary({ detail, verification, onOpenResearch }: Props) {
  const summary = buildEvaluationSummary(detail);
  const loadExperiments = useCallback(() => fetchExperiments(), []);
  const experiments = useAsyncData(loadExperiments, 0);
  const verify = verificationText(verification);

  return (
    <div data-evaluation-summary className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      <Card title="Assessment">
        <Item label="Target">
          <span className="mono">{detail.target}</span>
        </Item>
        <Item label="Status">
          <StatusBadge label={detail.status} tone={statusTone(detail.status)} />
        </Item>
        <Item label="Type">{formatFactorLabel(detail.assessment_type)}</Item>
        <Item label="Started">
          <span className="mono text-xs">{formatGeneratedAt(detail.started_at) ?? "Not recorded"}</span>
        </Item>
        <Item label="Completed">
          <span className="mono text-xs">
            {detail.completed_at ? formatGeneratedAt(detail.completed_at) ?? "Not recorded" : "Not recorded"}
          </span>
        </Item>
      </Card>

      <Card title="Coverage">
        <Item label="Checks performed">
          {summary.coverage.recorded ? (
            <span>
              <span className="mono">{summary.coverage.evaluated}</span> evaluated of{" "}
              <span className="mono">{summary.coverage.entries}</span> recorded
            </span>
          ) : (
            <span className="text-[var(--muted)]">Not recorded for this check</span>
          )}
        </Item>
        <Item label="Evidence records">
          <span className="mono">{summary.evidenceCount}</span>
        </Item>
        <Item label="Findings">
          <span className="mono">{summary.findingCount}</span>
        </Item>
      </Card>

      <Card title="Risk">
        {summary.risk ? (
          <>
            <Item label="Score">
              <span className="inline-flex items-center gap-2">
                <span className="mono font-semibold">{formatNumber(summary.risk.snapshot.score)}</span>
                <SeverityBadge severity={summary.risk.snapshot.risk_level} />
              </span>
            </Item>
            <Item label="Risk model">
              <span className="mono">{summary.risk.snapshot.score_version}</span>
            </Item>
            <Item label="Contributors">
              <span className="mono">{summary.risk.contributors.length}</span>
            </Item>
            <ul className="space-y-0.5 pt-1 text-xs text-[var(--muted)]">
              {summary.risk.contributors.map((factor) => (
                <li key={factor.factor} className="flex justify-between gap-3">
                  <span>{factor.label}</span>
                  <span className="mono">
                    {factor.contribution === null ? "Not recorded" : `+${formatNumber(factor.contribution)}`}
                  </span>
                </li>
              ))}
            </ul>
          </>
        ) : (
          <p className="text-[var(--muted)]">No risk result was recorded for this check.</p>
        )}
      </Card>

      <Card title="Findings">
        <Item label="Important">
          <span className="mono">{summary.findings.important}</span>
        </Item>
        <Item label="Minor">
          <span className="mono">{summary.findings.minor}</span>
        </Item>
        <Item label="Informational">
          <span className="mono">{summary.findings.informational}</span>
        </Item>
      </Card>

      <Card title="AI">
        <Item label="Explanation source">
          <span className="text-xs">Labelled on each Assistant reply</span>
        </Item>
        <p className="text-xs leading-relaxed text-[var(--muted)]">
          Explanations are written only on request, from the latest completed check's recorded risk
          result, findings, remediation and limitations. Each is labelled as an AI or rule-based
          explanation. The AI does not calculate risk, decide which vulnerabilities exist, generate
          evidence or run checks.
        </p>
      </Card>

      <Card title="Verification">
        <Item label="Baseline">
          <span className="mono text-xs">{verify.baseline}</span>
        </Item>
        <Item label="Verification">
          <span className="mono text-xs">{formatGeneratedAt(detail.started_at) ?? "This check"}</span>
        </Item>
        <Item label="Comparison">{verify.comparison}</Item>
      </Card>

      <Card title="Ground truth & experiments" wide>
        <p data-ground-truth className="text-sm">{GROUND_TRUTH_NOT_CONFIGURED}</p>
        <p className="text-xs text-[var(--muted)]">
          Detection accuracy, precision and recall are therefore not reported.
        </p>
        <div className="pt-1 text-sm">
          {experiments.loading && !experiments.data ? (
            <p className="text-[var(--muted)]">Loading recorded experiments…</p>
          ) : experiments.error ? (
            <p className="text-[var(--muted)]">Recorded experiments could not be loaded.</p>
          ) : experiments.data?.length ? (
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <ul className="space-y-0.5">
                {experiments.data.map((item) => (
                  <li key={item.id} data-experiment className="break-words">
                    {item.experiment_name}{" "}
                    <span className="mono text-xs text-[var(--muted)]">
                      {[item.model_version, item.status].filter(Boolean).join(" · ")}
                    </span>
                  </li>
                ))}
              </ul>
              {onOpenResearch ? (
                <button
                  type="button"
                  onClick={onOpenResearch}
                  className="btn-soft inline-flex min-h-11 shrink-0 items-center justify-center rounded-full border border-white/10 bg-white/[0.04] px-4 text-sm font-medium text-[var(--muted)] hover:text-[var(--text)]"
                >
                  Open Risk &amp; Research
                </button>
              ) : null}
            </div>
          ) : (
            <p className="text-[var(--muted)]">No experiment records.</p>
          )}
        </div>
      </Card>
    </div>
  );
}
