import { useState, type ReactNode } from "react";
import {
  LIMITED_NEXT_STEP,
  NO_EXACT_STEPS,
  NO_RECORDED_FIX,
  OUTCOME_NOTE,
  STILL_PRESENT_CHECKS,
  type GuidedRemediation,
  type GuidedStep,
  type IssueVerification,
} from "../../lib/assistant/guidedFix";
import type { CardIssue } from "../../lib/assistant/workflow";
import { pluralize } from "../../lib/securityHome";
import { SeverityBadge } from "../common/SeverityBadge";

const LABEL = "text-xs font-semibold text-[var(--muted)]";
const NAV_BUTTON =
  "btn-soft inline-flex min-h-11 items-center rounded-full border px-3.5 text-xs font-medium disabled:cursor-not-allowed disabled:opacity-40";

function Section({ title, children, name }: { title: string; children: ReactNode; name: string }) {
  return (
    <section className="min-w-0 space-y-1" data-guide-section={name}>
      <h3 className={LABEL}>{title}</h3>
      <div className="min-w-0 space-y-1 break-words">{children}</div>
    </section>
  );
}

function ConfigLine({ value }: { value: string }) {
  return (
    <code className="mono block min-w-0 whitespace-pre-wrap break-all rounded-lg border border-white/[0.08] bg-black/30 px-2.5 py-1.5 text-xs text-[var(--text)]">
      {value}
    </code>
  );
}

function StepBody({ step }: { step: GuidedStep }) {
  return (
    <>
      <p className="font-medium">{step.title}</p>
      <p>{step.detail}</p>
      {step.example ? (
        <div className="space-y-1" data-config-example="">
          {step.example.current ? (
            <>
              <p className={LABEL}>If you see this line</p>
              <ConfigLine value={step.example.current} />
              <p className={LABEL}>Change it to</p>
            </>
          ) : (
            <p className={LABEL}>Set</p>
          )}
          <ConfigLine value={step.example.change} />
          {step.example.note ? <p className="text-xs text-[var(--muted)]">{step.example.note}</p> : null}
        </div>
      ) : null}
      {step.warning ? (
        <p role="note" data-step-warning="" className="rounded-lg border border-[var(--warn)]/30 bg-[var(--warn)]/[0.06] px-2.5 py-1.5 text-xs">
          <span aria-hidden className="mr-1 text-[var(--warn)]">⚠</span>
          {step.warning}
        </p>
      ) : null}
    </>
  );
}

/** One step at a time with Back / Next step; all step titles under a collapsed list. */
function StepNavigator({ steps }: { steps: readonly GuidedStep[] }) {
  const [index, setIndex] = useState(0);
  const step = steps[index];
  const last = index === steps.length - 1;
  return (
    <div className="space-y-2">
      <div
        role="group"
        aria-live="polite"
        aria-label={`Step ${index + 1} of ${steps.length}`}
        data-guide-step={index + 1}
        className="min-w-0 space-y-1.5 rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 py-2.5"
      >
        <p className="text-xs font-semibold text-[var(--accent)]">
          Step {index + 1} of {steps.length}
        </p>
        <StepBody step={step} />
      </div>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={index === 0}
          onClick={() => setIndex(index - 1)}
          data-step-nav="back"
          className={`${NAV_BUTTON} border-white/[0.12] bg-white/[0.03] text-[var(--text)]`}
        >
          Back
        </button>
        <button
          type="button"
          disabled={last}
          onClick={() => setIndex(index + 1)}
          data-step-nav="next"
          className={`${NAV_BUTTON} border-[var(--accent)]/45 bg-[var(--accent-soft)] text-[var(--accent)]`}
        >
          {last ? "Last step" : "Next step"}
        </button>
      </div>
      <details className="text-xs text-[var(--muted)]" data-all-steps="">
        <summary className="inline-flex min-h-11 cursor-pointer items-center font-medium text-[var(--accent)]">See all steps</summary>
        <ol className="list-decimal space-y-0.5 pb-1 pl-5">
          {steps.map((item, i) => (
            <li key={`${i}|${item.title}`} className={i === index ? "text-[var(--text)]" : undefined}>
              {item.title}
            </li>
          ))}
        </ol>
      </details>
    </div>
  );
}

function TechnicalDetails({ lines }: { lines: readonly string[] }) {
  return (
    <details data-technical="" className="text-xs text-[var(--muted)]">
      <summary className="inline-flex min-h-11 cursor-pointer items-center font-medium text-[var(--accent)]">Technical details</summary>
      <ul className="mono space-y-1 break-all pb-1">
        {lines.map((line, index) => (
          <li key={`${index}|${line}`}>{line}</li>
        ))}
      </ul>
    </details>
  );
}

function GuideHeading({ guide }: { guide: GuidedRemediation }) {
  return (
    <div className="flex min-w-0 flex-col items-start gap-1">
      <p className="min-w-0 break-words font-semibold" data-issue-title="">
        {guide.title}
      </p>
      <span className="flex items-center gap-1.5 text-xs text-[var(--muted)]" data-issue-severity="">
        Severity: <SeverityBadge severity={guide.severity} />
      </span>
    </div>
  );
}

/** What is wrong → where → how (steps) → what it may affect → how to tell it worked. */
export function GuidedFixCard({ guide, frame }: { guide: GuidedRemediation; frame: string }) {
  return (
    <div className={`${frame} space-y-3`} data-card="GUIDED_FIX" data-guide-mode={guide.mode}>
      <GuideHeading guide={guide} />
      {guide.mode === "STEPS" ? (
        <>
          <Section title="What is wrong?" name="what">
            <p>{guide.whatIsWrong}</p>
          </Section>
          <Section title="Where do I fix it?" name="where">
            <p>{guide.whereToFix}</p>
            <p className="text-xs text-[var(--muted)]">{guide.locationNote}</p>
          </Section>
          {guide.preparation ? (
            <Section title="Before you start" name="prepare">
              <p>{guide.preparation}</p>
            </Section>
          ) : null}
          <Section title="How do I fix it?" name="steps">
            <StepNavigator steps={guide.steps} />
          </Section>
          <Section title="What might this affect?" name="impact">
            {guide.impact ? <p>{guide.impact}</p> : null}
            <p className="text-xs text-[var(--muted)]">{OUTCOME_NOTE}</p>
          </Section>
        </>
      ) : (
        <>
          <p className="font-medium">I can explain what needs to change</p>
          <Section title="What the check found" name="what">
            <p>{guide.whatIsWrong}</p>
          </Section>
          <Section title="What to change" name="change">
            <p data-recorded-fix="">{guide.recordedFix ?? NO_RECORDED_FIX}</p>
          </Section>
          <Section title="Where to look" name="where">
            <p>{guide.whereToFix}</p>
          </Section>
          <Section title="Why I can't give exact steps" name="limits">
            <p>{NO_EXACT_STEPS}</p>
          </Section>
          <Section title="Next step" name="next">
            <p>{LIMITED_NEXT_STEP}</p>
          </Section>
        </>
      )}
      <Section title="How do I know it is fixed?" name="verify">
        <p>{guide.verification}</p>
      </Section>
      <TechnicalDetails lines={guide.technical} />
    </div>
  );
}

/** "How do I fix both?": a separate guided fix per issue, chosen by the user. */
export function FixListCard({
  issues,
  startWith,
  disabled,
  frame,
  onGuidedFix,
}: {
  issues: readonly CardIssue[];
  startWith: string | null;
  disabled: boolean;
  frame: string;
  onGuidedFix?: (checkId: string) => void;
}) {
  return (
    <div className={frame} data-card="FIX_LIST">
      <ol className="space-y-2" aria-label="Issues to fix">
        {issues.map((issue, index) => (
          <li
            key={`${issue.checkId}|${issue.severity}`}
            className="min-w-0 space-y-1.5 rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 py-2"
          >
            <p className="min-w-0 break-words font-medium" data-issue-title="">
              {index + 1}. {issue.title}
            </p>
            <p className="flex flex-wrap items-center gap-1.5 text-xs text-[var(--muted)]" data-issue-severity="">
              Severity: <SeverityBadge severity={issue.severity} />
              {startWith === issue.checkId ? <span className="text-[var(--accent)]">Start here</span> : null}
            </p>
            {onGuidedFix ? (
              <button
                type="button"
                disabled={disabled}
                onClick={() => onGuidedFix(issue.checkId)}
                data-guided-fix=""
                className={`${NAV_BUTTON} border-[var(--accent)]/45 bg-[var(--accent-soft)] text-[var(--accent)] hover:bg-[var(--accent)]/20`}
              >
                Start guided fix
              </button>
            ) : null}
          </li>
        ))}
      </ol>
    </div>
  );
}

const STATUS_ICON: Record<IssueVerification["status"], { icon: string; tone: string; label: string }> = {
  NOT_OBSERVED: { icon: "✓", tone: "text-[var(--ok)]", label: "Not observed" },
  STILL_PRESENT: { icon: "⚠", tone: "text-[var(--warn)]", label: "Still observed" },
  NOT_RECHECKED: { icon: "?", tone: "text-[var(--muted)]", label: "Not checked again" },
  NOT_COMPARABLE: { icon: "?", tone: "text-[var(--muted)]", label: "Can't be compared" },
};

/** Verification result for the issue being fixed; decided by the comparison engine, never here. */
export function VerificationCard({ result, frame }: { result: IssueVerification; frame: string }) {
  const status = STATUS_ICON[result.status];
  return (
    <div className={`${frame} space-y-2`} data-card="VERIFICATION" data-verification-status={result.status}>
      <p className="min-w-0 break-words">
        {result.status === "NOT_OBSERVED"
          ? "The latest security check no longer reported:"
          : result.status === "STILL_PRESENT"
            ? "The latest security check still observed:"
            : "The issue you were fixing:"}{" "}
        <span className="font-medium">{result.title}</span>
      </p>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-sm">
        <dt className="text-[var(--muted)]">Previous</dt>
        <dd>
          <SeverityBadge severity={result.previousSeverity} />
        </dd>
        <dt className="text-[var(--muted)]">Current</dt>
        <dd className={status.tone}>
          <span aria-hidden className="mr-1">
            {status.icon}
          </span>
          {status.label}
        </dd>
      </dl>
      {result.status === "NOT_OBSERVED" || result.status === "STILL_PRESENT" ? (
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-sm" data-before-after="">
          <dt className="text-[var(--muted)]">Before</dt>
          <dd>{pluralize(result.beforeImportant, "important issue")}</dd>
          <dt className="text-[var(--muted)]">After</dt>
          <dd>{pluralize(result.afterImportant, "important issue")}</dd>
          <dt className="text-[var(--muted)]">Changed</dt>
          <dd>{pluralize(result.noLongerObserved, "issue")} no longer observed</dd>
        </dl>
      ) : null}
      {result.status === "NOT_OBSERVED" ? (
        <p className="text-xs text-[var(--muted)]">
          This specific issue was not observed in the latest check. It doesn't mean every part of your network is secure.
        </p>
      ) : null}
      {result.status === "STILL_PRESENT" ? (
        <div>
          <p className={LABEL}>What to check</p>
          <p>Go back to the guided steps and make sure that:</p>
          <ul className="list-disc pl-5">
            {STILL_PRESENT_CHECKS.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {result.status === "NOT_COMPARABLE" ? (
        <p className="text-xs text-[var(--muted)]">The two checks weren't run the same way. The full comparison shows why.</p>
      ) : null}
    </div>
  );
}
