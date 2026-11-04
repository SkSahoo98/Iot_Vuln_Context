import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { createAssessment, fetchAssessment } from "../../api/assessments";
import { explainWithAssistant } from "../../api/assistant";
import type { AssistantExplainBasis, AssistantExplainSource } from "../../api/assistant";
import type { AssessmentDetail, AssessmentSummary } from "../../api/types";
import { useAsyncData } from "../../hooks/useAsyncData";
import {
  buildAssistantContext,
  CONTEXT_LIMITATIONS,
  type AssistantContext,
  type LatestDetailState,
} from "../../lib/assistant/context";
import {
  composerKeyAction,
  createAssistantConversation,
  introText,
  openActionLabel,
  sourceLabel,
  type AssistantConversation,
  type AssistantMessage,
  type NavigationActionId,
  type RequestOutcome,
  type WorkflowDeps,
} from "../../lib/assistant/conversation";
import { MAX_REQUEST_LENGTH } from "../../lib/assistant/intents";
import { redactRuntimeText } from "../../lib/assistant/redact";
import type { AssistantAction } from "../../lib/assistant/resolve";
import {
  NAVIGATION_ACTIONS,
  type AssistantActionButton,
  type AssistantCard,
  type AssistantWorkflowState,
  type CardIssue,
  type FactItem,
  type RiskPoint,
} from "../../lib/assistant/workflow";
import { SeverityBadge } from "../common/SeverityBadge";
import { FixListCard, GuidedFixCard, VerificationCard } from "./GuidedFix";
import {
  resolveShortcut,
  shortcutById,
  shortcutHint,
  type AssistantShortcutId,
} from "../../lib/assistantActions";
import { formatRelativeTime, severityTone } from "../../lib/format";
import type { NavRequest } from "../../lib/navigation";
import { pluralize, selectLatestAssessment, type FindingCounts } from "../../lib/securityHome";

const LEVEL_TONE: Record<ReturnType<typeof severityTone>, string> = {
  danger: "text-[var(--danger)]",
  warn: "text-[var(--warn)]",
  ok: "text-[var(--ok)]",
  default: "text-[var(--text)]",
};

const INPUT_ID = "assistant-input";

function AssistantBubble({ children, tone }: { children: ReactNode; tone?: "error" }) {
  return (
    <li className="flex min-w-0 justify-start">
      <div
        className={`min-w-0 max-w-[88%] break-words rounded-2xl rounded-tl-md border px-3.5 py-2.5 text-sm leading-relaxed sm:max-w-[80%] ${
          tone === "error"
            ? "border-[var(--danger)]/30 bg-[var(--danger)]/[0.06] text-[var(--text)]"
            : "border-white/[0.07] bg-white/[0.035] text-[var(--text)]"
        }`}
      >
        <span className="sr-only">Assistant: </span>
        {children}
      </div>
    </li>
  );
}

function UserBubble({ text }: { text: string }) {
  return (
    <li className="flex min-w-0 justify-end">
      <div className="min-w-0 max-w-[88%] whitespace-pre-wrap break-words rounded-2xl rounded-tr-md border border-[var(--accent)]/25 bg-[var(--accent-soft)] px-3.5 py-2.5 text-sm leading-relaxed text-[var(--text)] sm:max-w-[80%]">
        <span className="sr-only">You: </span>
        {text}
      </div>
    </li>
  );
}

function ExplanationOpenButton({
  action,
  disabled,
  onOpen,
}: {
  action: AssistantAction;
  disabled: boolean;
  onOpen: (action: AssistantAction) => void;
}) {
  const label = openActionLabel(action.type);
  if (!label) return null;
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => onOpen(action)}
      className="btn-soft -ml-3 mt-1 inline-flex min-h-11 items-center rounded-full px-3 text-sm font-medium text-[var(--accent)] hover:bg-white/[0.04] disabled:cursor-not-allowed disabled:opacity-50"
    >
      {label}
    </button>
  );
}

const BASIS_LABEL: Record<AssistantExplainBasis, string> = {
  RISK_RESULT: "Current risk result",
  RISK_CONTRIBUTORS: "Main risk contributors",
  FINDINGS: "Recorded findings",
  REMEDIATION: "Remediation from the assessment engine",
  LIMITATIONS: "Assessment limitations",
};

const WRITTEN_BY: Record<AssistantExplainSource, string> = {
  AI: "AI explanation: the AI wrote this text from the information above.",
  DETERMINISTIC_FALLBACK:
    "Rule-based explanation: the AI was unavailable, so fixed rules wrote this from the information above.",
  DETERMINISTIC: "Rule-based explanation: fixed rules wrote this from the information above.",
};

export const AI_DOES_NOT = [
  "Calculate the risk score",
  "Decide which vulnerabilities exist",
  "Generate security evidence",
  "Run security checks",
] as const;

export function ExplanationProvenance({
  source,
  basis,
}: {
  source: AssistantExplainSource;
  basis?: readonly AssistantExplainBasis[];
}) {
  return (
    <details data-provenance={source} className="group mt-2 rounded-xl border border-white/[0.06] bg-white/[0.02]">
      <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-2 px-3 text-xs font-medium text-[var(--muted)] hover:text-[var(--text)]">
        About this explanation
        <span aria-hidden className="transition-transform group-open:rotate-90">›</span>
      </summary>
      <div className="space-y-3 px-3 pb-3 text-xs leading-relaxed">
        <p className="text-[var(--text)]">Based on your latest security check.</p>
        <div>
          <p className="font-medium text-[var(--muted)]">Information used</p>
          {basis?.length ? (
            <ul className="mt-1 space-y-0.5">
              {basis.map((item) => (
                <li key={item} data-basis={item} className="flex gap-2">
                  <span aria-hidden className="text-[var(--ok)]">✓</span>
                  {BASIS_LABEL[item]}
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-1">Recorded results of your latest completed security check.</p>
          )}
        </div>
        <div>
          <p className="font-medium text-[var(--muted)]">The AI does not</p>
          <ul className="mt-1 space-y-0.5">
            {AI_DOES_NOT.map((item) => (
              <li key={item} className="flex gap-2">
                <span aria-hidden className="text-[var(--muted)]">✗</span>
                {item}
              </li>
            ))}
          </ul>
        </div>
        <p className="text-[var(--muted)]">{WRITTEN_BY[source]}</p>
      </div>
    </details>
  );
}

const formatScore = (score: number | null) => (score === null ? null : score.toFixed(1));

function RiskValue({ level, score }: { level: string | null; score: number | null }) {
  const shown = formatScore(score);
  if (!level && !shown) return <span className="text-[var(--muted)]">not recorded</span>;
  return (
    <span className={`font-semibold ${LEVEL_TONE[severityTone(level)]}`}>
      {level ?? ""}
      {level && shown ? " — " : ""}
      {shown ?? ""}
    </span>
  );
}

/** Title on its own line, then "Severity: HIGH" on the next. */
function IssueHeading({ issue, strong }: { issue: CardIssue; strong?: boolean }) {
  return (
    <span className="flex min-w-0 flex-col items-start gap-1">
      <span className={`block min-w-0 break-words ${strong ? "font-medium" : ""}`} data-issue-title="">
        {issue.title}
      </span>
      <span className="flex items-center gap-1.5 text-xs text-[var(--muted)]" data-issue-severity="">
        Severity: <SeverityBadge severity={issue.severity} />
      </span>
      {issue.summary ? (
        <span className="block min-w-0 break-words text-xs text-[var(--muted)]" data-issue-summary="">
          {issue.summary}
        </span>
      ) : null}
    </span>
  );
}

function IssueChoices({
  issues,
  disabled,
  onSelect,
}: {
  issues: readonly CardIssue[];
  disabled: boolean;
  onSelect?: (checkId: string) => void;
}) {
  if (!issues.length) return null;
  return (
    <ul className="mt-2 space-y-1.5" aria-label="Issues">
      {issues.map((issue) => (
        <li key={`${issue.checkId}|${issue.severity}`} className="min-w-0">
          {onSelect ? (
            <button
              type="button"
              disabled={disabled}
              onClick={() => onSelect(issue.checkId)}
              data-issue-choice=""
              className="btn-soft flex min-h-11 w-full min-w-0 items-center rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 py-2 text-left hover:border-[var(--accent)]/40 disabled:cursor-not-allowed disabled:opacity-55"
            >
              <IssueHeading issue={issue} />
            </button>
          ) : (
            <IssueHeading issue={issue} />
          )}
        </li>
      ))}
    </ul>
  );
}

function FactsCard({
  items,
  technical,
  expanded,
  frame,
}: {
  items: readonly FactItem[];
  technical: readonly string[];
  expanded?: boolean;
  frame: string;
}) {
  return (
    <div className={frame} data-card="FACTS">
      {items.length ? (
        <ul className="space-y-1.5">
          {items.map((item, index) => (
            <li key={`${index}|${item.title}`} className="min-w-0">
              <p className="break-words font-medium">{item.title}</p>
              {item.detail ? <p className="break-words text-xs text-[var(--muted)]">{item.detail}</p> : null}
            </li>
          ))}
        </ul>
      ) : null}
      {technical.length ? (
        <details data-technical="" open={expanded} className="text-xs text-[var(--muted)]">
          <summary className="inline-flex min-h-11 cursor-pointer items-center font-medium text-[var(--accent)]">
            Show technical details
          </summary>
          <ul className="mono space-y-1 break-all pb-1">
            {technical.map((line, index) => (
              <li key={`${index}|${line}`}>{line}</li>
            ))}
          </ul>
        </details>
      ) : null}
    </div>
  );
}

function ComparisonGroup({ label, issues }: { label: string; issues: readonly CardIssue[] }) {
  return (
    <div className="min-w-0">
      <p className="text-xs font-medium text-[var(--muted)]">
        {label}: {issues.length}
      </p>
      {issues.length ? (
        <ul className="mt-1 list-disc space-y-0.5 pl-5">
          {issues.map((issue) => (
            <li key={`${issue.checkId}|${issue.severity}`} className="break-words">
              {issue.title}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

const COUNT_CHIP = "inline-flex items-center gap-1 rounded-full border border-white/[0.08] bg-white/[0.03] px-2.5 py-0.5 text-xs";
const GROUP_HEADING = "text-sm font-semibold";

/** Important issues, then the LOW/INFO findings as counts; every finding of the check is counted. */
function ResultFindings({
  findings,
  importantIssues,
  issues,
  disabled,
  onSelectIssue,
  onViewFindings,
}: {
  findings: FindingCounts;
  importantIssues: number;
  issues: readonly CardIssue[];
  disabled: boolean;
  onSelectIssue?: (checkId: string) => void;
  onViewFindings?: () => void;
}) {
  const lower: [number, string][] = [
    [findings.low, "LOW"],
    [findings.info, "INFO"],
  ];
  return (
    <>
      <section className="min-w-0 space-y-1" data-result-group="important">
        {findings.important ? (
          <>
            <p className={GROUP_HEADING}>{pluralize(importantIssues, "Important Issue")}</p>
            <IssueChoices issues={issues} disabled={disabled} onSelect={onSelectIssue} />
          </>
        ) : (
          <p className="text-sm">No high-priority issues were found.</p>
        )}
      </section>
      <section className="min-w-0 space-y-1 border-t border-white/[0.06] pt-1.5" data-result-group="additional">
        {findings.additional ? (
          <>
            <p className={GROUP_HEADING}>{pluralize(findings.additional, "Additional Finding")}</p>
            <ul className="flex flex-wrap gap-1.5" aria-label="Additional findings by severity">
              {lower
                .filter(([count]) => count > 0)
                .map(([count, label]) => (
                  <li key={label} className={COUNT_CHIP} data-severity-count={label}>
                    <span className="font-semibold">{count}</span> {label}
                  </li>
                ))}
            </ul>
          </>
        ) : (
          <p className="text-xs text-[var(--muted)]">No additional lower-severity findings.</p>
        )}
      </section>
      {onViewFindings && findings.total ? (
        <button
          type="button"
          onClick={onViewFindings}
          data-view-all-findings=""
          className="btn-soft inline-flex min-h-11 items-center rounded-full border border-[var(--accent)]/35 bg-white/[0.03] px-3.5 text-xs font-medium text-[var(--accent)] hover:bg-[var(--accent-soft)]"
        >
          View all findings
        </button>
      ) : null}
    </>
  );
}

function signedScore(delta: number): string {
  if (delta === 0) return "no change";
  return `${delta > 0 ? "+" : "−"}${Math.abs(delta).toFixed(1)}`;
}

/** Important / additional findings before and after, and the risk change from the comparison engine. */
function ComparisonCounts({ before, after, delta }: { before: FindingCounts; after: FindingCounts; delta: number | null }) {
  return (
    <dl className="grid grid-cols-[auto_auto_auto] justify-start gap-x-4 gap-y-0.5 text-sm" data-comparison-counts="">
      <dt className="text-xs text-[var(--muted)]" />
      <dd className="text-xs text-[var(--muted)]">Before</dd>
      <dd className="text-xs text-[var(--muted)]">After</dd>
      <dt className="text-[var(--muted)]">Important</dt>
      <dd>{before.important}</dd>
      <dd>{after.important}</dd>
      <dt className="text-[var(--muted)]">Additional</dt>
      <dd>{before.additional}</dd>
      <dd>{after.additional}</dd>
      <dt className="text-[var(--muted)]">Risk change</dt>
      <dd className="col-span-2">{delta === null ? "can't be compared" : signedScore(delta)}</dd>
    </dl>
  );
}

function RiskPointText({ point }: { point: RiskPoint | null }) {
  return point ? <RiskValue level={point.level} score={point.score} /> : <RiskValue level={null} score={null} />;
}

/** Deterministic backend values; rendered above any explanation text. */
function WorkflowCard({
  card,
  disabled,
  onSelectIssue,
  onGuidedFix,
  onViewFindings,
  latestAssessmentId,
  placement,
}: {
  card: AssistantCard;
  disabled: boolean;
  onSelectIssue?: (checkId: string) => void;
  onGuidedFix?: (checkId: string) => void;
  /** Opens the existing technical findings list of the latest check. */
  onViewFindings?: () => void;
  latestAssessmentId: string | null;
  /** Above an explanation, below a fixed headline such as "Security check complete." */
  placement: "above" | "below";
}) {
  const frame = `${placement === "above" ? "mb-2" : "mt-2"} min-w-0 space-y-1.5 rounded-xl border border-white/[0.07] bg-black/10 px-3 py-2.5`;
  switch (card.kind) {
    case "RESULT":
      return (
        <div className={frame} data-card="RESULT">
          <p>
            Risk: <RiskValue level={card.riskLevel} score={card.riskScore} />
          </p>
          {card.findings ? (
            <ResultFindings
              findings={card.findings}
              importantIssues={card.importantIssues ?? card.issues.length}
              issues={card.issues}
              disabled={disabled}
              onSelectIssue={onSelectIssue}
              onViewFindings={card.assessmentId !== null && card.assessmentId === latestAssessmentId ? onViewFindings : undefined}
            />
          ) : (
            <>
              <p>
                Important issues:{" "}
                <span className="font-semibold">{card.importantIssues ?? "not recorded"}</span>
              </p>
              <IssueChoices issues={card.issues} disabled={disabled} onSelect={onSelectIssue} />
            </>
          )}
        </div>
      );
    case "ISSUES":
      return (
        <div className={frame} data-card="ISSUES">
          <IssueChoices issues={card.issues} disabled={disabled} onSelect={onSelectIssue} />
          {card.additionalFindings ? (
            <p className="text-xs text-[var(--muted)]" data-additional-findings="">
              Plus {pluralize(card.additionalFindings, "additional lower-severity finding")}.
            </p>
          ) : card.additionalFindings === null && card.minorIssues ? (
            <p className="text-xs text-[var(--muted)]">
              Plus {card.minorIssues} minor {card.minorIssues === 1 ? "issue" : "issues"}.
            </p>
          ) : null}
        </div>
      );
    case "ISSUE":
      return (
        <div className={frame} data-card="ISSUE">
          <IssueHeading issue={card.issue} strong />
          {card.meaning ? (
            <p>
              <span className="text-xs font-medium text-[var(--muted)]">Why it matters: </span>
              {card.meaning}
            </p>
          ) : null}
          {card.remediation ? (
            <p data-remediation="">
              <span className="text-xs font-medium text-[var(--muted)]">Recommended fix: </span>
              {card.remediation}
            </p>
          ) : null}
          {card.next ? (
            <p data-next-step="">
              <span className="text-xs font-medium text-[var(--muted)]">Next step: </span>
              {card.next}
            </p>
          ) : null}
        </div>
      );
    case "FACTS":
      return <FactsCard items={card.items} technical={card.technical} expanded={card.expanded} frame={frame} />;
    case "COMPARISON":
      return (
        <div className={frame} data-card="COMPARISON">
          <p>
            Before: <RiskPointText point={card.before} />
          </p>
          <p>
            After: <RiskPointText point={card.after} />
          </p>
          <ComparisonCounts before={card.counts.before} after={card.counts.after} delta={card.delta} />
          <ComparisonGroup label="Resolved" issues={card.resolved} />
          <ComparisonGroup label="New" issues={card.added} />
          <ComparisonGroup label="Still present" issues={card.remaining} />
          {card.notRechecked.length ? (
            <ComparisonGroup label="Not checked again" issues={card.notRechecked} />
          ) : null}
        </div>
      );
    case "GUIDED_FIX":
      return <GuidedFixCard guide={card.guide} frame={frame} />;
    case "FIX_LIST":
      return (
        <FixListCard issues={card.issues} startWith={card.startWith} disabled={disabled} frame={frame} onGuidedFix={onGuidedFix} />
      );
    case "VERIFICATION":
      return <VerificationCard result={card.result} frame={frame} />;
  }
}

function WorkflowActions({
  actions,
  busy,
  running,
  onAsk,
  onRun,
  onNavigate,
  onGuidedFix,
  onNotYet,
}: {
  actions: readonly AssistantActionButton[];
  busy: boolean;
  running: boolean;
  onAsk: (label: string) => void;
  onRun: (kind: "CHECK" | "VERIFY") => void;
  onNavigate: (id: NavigationActionId) => void;
  onGuidedFix?: (checkId: string) => void;
  onNotYet?: () => void;
}) {
  const shown = actions.filter(
    (action) => (action.id !== "guided-fix" || (onGuidedFix && action.checkId)) && (action.id !== "not-yet" || onNotYet),
  );
  return (
    <div className="mt-2 flex flex-wrap gap-2">
      {shown.map((action) => {
        const isRun = action.id === "run-check" || action.id === "run-verification";
        const disabled = isRun ? running : busy;
        const onClick = () => {
          if (action.id === "run-check") onRun("CHECK");
          else if (action.id === "run-verification") onRun("VERIFY");
          else if (action.id === "guided-fix") onGuidedFix?.(action.checkId!);
          else if (action.id === "not-yet") onNotYet?.();
          else if (NAVIGATION_ACTIONS.includes(action.id)) onNavigate(action.id as NavigationActionId);
          else onAsk(action.label);
        };
        return (
          <button
            key={`${action.id}|${action.label}`}
            type="button"
            disabled={disabled}
            onClick={onClick}
            data-workflow-action={action.id}
            className={`btn-soft inline-flex min-h-11 items-center rounded-full border px-3.5 text-xs font-medium disabled:cursor-not-allowed disabled:opacity-50 ${
              action.primary
                ? "border-[var(--accent)]/50 bg-[var(--accent-soft)] text-[var(--accent)] hover:bg-[var(--accent)]/20"
                : "border-[var(--accent)]/35 bg-white/[0.03] text-[var(--accent)] hover:bg-[var(--accent-soft)]"
            }`}
          >
            {action.label}
          </button>
        );
      })}
    </div>
  );
}

const SIDEBAR_HEADING = "text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--muted)]";

function IssueCounts({ context }: { context: AssistantContext }) {
  if (context.issueStatus === "LOADING") {
    return <p className="mt-3 text-xs text-[var(--muted)]">Loading the issues from your latest check…</p>;
  }
  const counts = context.issueCounts;
  if (context.issueStatus !== "AVAILABLE" || !counts) {
    return <p className="mt-3 text-xs text-[var(--muted)]">Couldn't load the issues from your latest check.</p>;
  }
  const findings = context.findingCounts;
  if (findings && findings.total === 0) {
    return <p className="mt-3 text-sm">No findings were recorded in the latest check.</p>;
  }
  if (!findings && !counts.importantIssues && !counts.minorIssues) {
    return <p className="mt-3 text-sm">No important or minor issues recorded.</p>;
  }
  return (
    <ul className="mt-3 flex flex-wrap gap-2 text-xs" aria-label="Findings in your latest check">
      <li className="rounded-full border border-white/[0.08] bg-white/[0.03] px-2.5 py-1">
        <span className="font-semibold">{counts.importantIssues}</span>{" "}
        {counts.importantIssues === 1 ? "important issue" : "important issues"}
      </li>
      {findings ? (
        <li className="rounded-full border border-white/[0.08] bg-white/[0.03] px-2.5 py-1">
          <span className="font-semibold">{findings.additional}</span>{" "}
          {findings.additional === 1 ? "additional finding" : "additional findings"}
        </li>
      ) : (
        <li className="rounded-full border border-white/[0.08] bg-white/[0.03] px-2.5 py-1">
          <span className="font-semibold">{counts.minorIssues}</span>{" "}
          {counts.minorIssues === 1 ? "minor issue" : "minor issues"}
        </li>
      )}
    </ul>
  );
}

function StatusState({ title, text, when }: { title: string; text: string; when?: string | null }) {
  return (
    <>
      <p className="mt-2 text-base font-semibold uppercase leading-tight tracking-tight">{title}</p>
      <p className="mt-1 text-sm text-[var(--muted)]">{text}</p>
      {when ? <p className="mt-1 text-xs text-[var(--muted)]">Started {when}</p> : null}
    </>
  );
}

/** Latest assessment as AssistantContext holds it; an older complete check is never shown as current. */
function SecurityStatusCard({
  context,
  loadFailed,
  now,
}: {
  context: AssistantContext | null;
  loadFailed: boolean;
  now: number | undefined;
}) {
  const latest = context?.latestAssessment ?? null;
  const started = latest ? formatRelativeTime(latest.startedAt, now) : null;
  let body: ReactNode;
  if (!context) {
    body = (
      <p className="mt-2 text-sm text-[var(--muted)]">
        {loadFailed ? "Couldn't load your security checks." : "Loading your security status…"}
      </p>
    );
  } else {
    switch (context.availability) {
      case "NO_ASSESSMENT":
        body = (
          <StatusState
            title="No security check yet"
            text="Your network has not been checked yet. Start with “Check my IoT network” below."
          />
        );
        break;
      case "ASSESSMENT_RUNNING":
        body = <StatusState title="Check in progress" text="Your latest security check is still running." when={started} />;
        break;
      case "ASSESSMENT_INCOMPLETE":
        body = <StatusState title="Latest check incomplete" text={CONTEXT_LIMITATIONS.incomplete} when={started} />;
        break;
      case "ASSESSMENT_FAILED":
        body = <StatusState title="Latest check failed" text={CONTEXT_LIMITATIONS.failed} when={started} />;
        break;
      case "ASSESSMENT_AVAILABLE": {
        const level = context.risk?.level ?? null;
        const score = formatScore(context.risk?.score ?? null);
        const checked = latest ? formatRelativeTime(latest.completedAt ?? latest.startedAt, now) : null;
        body = (
          <>
            <p className="mt-2 flex flex-wrap items-baseline gap-x-3 gap-y-1">
              {level ? (
                <span className="text-xl font-semibold uppercase leading-tight tracking-tight">
                  <span className={LEVEL_TONE[severityTone(level)]}>{level}</span> risk
                </span>
              ) : (
                <span className="text-base font-semibold">Risk level not recorded</span>
              )}
              {score ? (
                <span className="text-sm text-[var(--muted)]">
                  <span className="font-semibold text-[var(--text)]">{score}</span> / 100
                </span>
              ) : null}
            </p>
            {checked ? <p className="mt-0.5 text-xs text-[var(--muted)]">Last checked {checked}</p> : null}
            <IssueCounts context={context} />
          </>
        );
        break;
      }
    }
  }
  return (
    <section
      aria-labelledby="assistant-status"
      data-security-status={context?.availability ?? (loadFailed ? "ERROR" : "LOADING")}
      className="surface-panel min-w-0 rounded-2xl p-4"
    >
      <h2 id="assistant-status" className={SIDEBAR_HEADING}>
        Your security status
      </h2>
      {body}
    </section>
  );
}

const SHORTCUT_ICON: Record<AssistantShortcutId, string> = {
  check: "M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z",
  "whats-wrong": "M12 4l9 16H3L12 4zM12 10v4M12 17h.01",
  "explain-risk": "M5 20v-6M12 20V8M19 20V4",
  "fix-issue": "M14.7 6.3a4 4 0 0 0-5.4 5.4L4 17l3 3 5.3-5.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.5-.5-.5-2.5z",
  verify: "M20 12a8 8 0 1 1-2.3-5.7M20 4v4h-4M9 12l2 2 4-4",
  summary: "M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01",
};

/** Rows of two, in ASSISTANT_SHORTCUTS order. */
const SHORTCUT_GROUPS: readonly (readonly AssistantShortcutId[])[] = [
  ["check", "whats-wrong"],
  ["explain-risk", "fix-issue"],
  ["verify", "summary"],
];

function ShortcutIcon({ id }: { id: AssistantShortcutId }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      className="h-4 w-4"
      aria-hidden
    >
      <path d={SHORTCUT_ICON[id]} />
    </svg>
  );
}

function AssistantActions({
  context,
  busy,
  request,
}: {
  context: AssistantContext | null;
  busy: boolean;
  /** The view's single request entry point, shared with the composer. */
  request: (text: string, source: "composer" | "shortcut") => void;
}) {
  return (
    <section aria-labelledby="assistant-actions" className="surface-panel min-w-0 rounded-2xl p-3">
      <h2 id="assistant-actions" className={`${SIDEBAR_HEADING} px-1`}>
        What would you like to do?
      </h2>
      <div className="mt-2 space-y-2">
        {SHORTCUT_GROUPS.map((group) => (
          <ul key={group.join("|")} className="space-y-1">
            {group.map((id) => {
              const shortcut = shortcutById(id);
              const resolution = resolveShortcut(shortcut.id, context);
              const hint = shortcutHint(resolution);
              const suggested = id === "check" && context?.availability === "NO_ASSESSMENT";
              return (
                <li key={shortcut.id} className="min-w-0">
                  <button
                    type="button"
                    onClick={() => request(shortcut.label, "shortcut")}
                    disabled={busy}
                    data-intent={resolution.intent}
                    data-action={resolution.action.type}
                    data-available={hint === null}
                    className={`btn-soft flex min-h-12 w-full min-w-0 items-center gap-3 rounded-xl border px-3 py-1.5 text-left hover:border-[var(--accent)]/40 hover:bg-white/[0.05] disabled:cursor-not-allowed disabled:opacity-55 ${
                      suggested
                        ? "border-[var(--accent)]/50 bg-[var(--accent-soft)]"
                        : "border-white/[0.08] bg-white/[0.03]"
                    } ${hint ? "opacity-75" : ""}`}
                  >
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[var(--accent-soft)] text-[var(--accent)]">
                      <ShortcutIcon id={shortcut.id} />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block break-words text-sm font-medium text-[var(--text)]">
                        {shortcut.label}
                      </span>
                      <span className="block break-words text-xs text-[var(--muted)]">
                        {hint ?? shortcut.description}
                      </span>
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        ))}
      </div>
      <p className="mt-2 px-1 text-[11px] leading-snug text-[var(--muted)]">
        Explanations are written from your latest completed security check. Checking
        and verifying follow fixed rules, and a new check starts only when you choose to run it.
      </p>
    </section>
  );
}

type ViewProps = {
  /** null while the assessment list is loading or failed to load. */
  context: AssistantContext | null;
  assessmentsError: string | null;
  onRetryAssessments: () => void;
  messages: readonly AssistantMessage[];
  /** Processing label while a request is handled; null when idle. */
  status: string | null;
  /** The single entry point for typed requests and shortcuts. */
  onRequest: (text: string) => Promise<RequestOutcome> | void;
  /** Opens the part of the app an explanation refers to. */
  onOpenAction?: (action: AssistantAction) => void;
  /** A check started from the assistant that has not finished yet. */
  running?: AssistantWorkflowState["running"];
  /** Explicit Run security check / Run verification check clicks. */
  onRunCheck?: (kind: "CHECK" | "VERIFY") => void;
  onSelectIssue?: (checkId: string) => void;
  /** Explicit "Start guided fix" / "View guided fix" clicks. */
  onGuidedFix?: (checkId: string) => void;
  /** Explicit "Not yet" click when a verification check is offered. */
  onNotYet?: () => void;
  onWorkflowNavigate?: (id: NavigationActionId) => void;
  now?: number;
};

export function AssistantView({
  context,
  assessmentsError,
  onRetryAssessments,
  messages,
  status,
  onRequest,
  onOpenAction,
  running = null,
  onRunCheck,
  onSelectIssue,
  onGuidedFix,
  onNotYet,
  onWorkflowNavigate,
  now,
}: ViewProps) {
  const lastAssistantId = [...messages].reverse().find((message) => message.role === "assistant")?.id;
  const latestAssessmentId = context?.latestAssessment?.id ?? null;
  const viewFindings = onWorkflowNavigate ? () => onWorkflowNavigate("technical-details") : undefined;
  const [draft, setDraft] = useState("");
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const logRef = useRef<HTMLOListElement>(null);
  const fromComposer = useRef(false);
  const busy = status !== null;

  useEffect(() => {
    const log = logRef.current;
    if (log) log.scrollTop = log.scrollHeight;
  }, [messages.length, status]);

  useEffect(() => {
    if (!busy && fromComposer.current) {
      fromComposer.current = false;
      inputRef.current?.focus();
    }
  }, [busy]);

  function request(text: string, source: "composer" | "shortcut") {
    if (busy || !text.trim()) return;
    fromComposer.current = source === "composer";
    if (source === "composer") setDraft("");
    void onRequest(text);
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    request(draft, "composer");
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    const action = composerKeyAction({
      key: event.key,
      shiftKey: event.shiftKey,
      isComposing: event.nativeEvent.isComposing,
    });
    if (action === "submit") {
      event.preventDefault();
      request(draft, "composer");
    }
  }

  return (
    <div
      data-assistant-workspace=""
      className="grid min-w-0 gap-4 lg:h-[calc(100dvh-var(--assistant-offset))] lg:min-h-[32rem] lg:grid-cols-[minmax(0,3fr)_minmax(20rem,2fr)] lg:grid-rows-[minmax(0,1fr)]"
    >
      <section
        aria-labelledby="assistant-greeting"
        data-assistant-chat=""
        className="surface-panel flex min-h-0 min-w-0 flex-col overflow-hidden rounded-2xl"
      >
        <h2
          id="assistant-greeting"
          className="border-b border-white/[0.06] px-4 py-3 text-sm font-semibold text-[var(--text)] sm:text-base"
        >
          How can I help with your security?
        </h2>
        <ol
          ref={logRef}
          role="log"
          aria-live="polite"
          aria-label="Conversation with the security assistant"
          className="relative max-h-[min(30rem,58dvh)] min-h-0 min-w-0 flex-1 space-y-3 overflow-y-auto overscroll-contain px-4 py-4 lg:max-h-none"
        >
          <AssistantBubble>
            {context ? (
              <p>{introText(context)}</p>
            ) : assessmentsError ? (
              <>
                <p className="text-[var(--danger)]">
                  Couldn't load your latest security check. {redactRuntimeText(assessmentsError)}
                </p>
                <button
                  type="button"
                  onClick={onRetryAssessments}
                  className="btn-soft -ml-3 mt-1 inline-flex min-h-11 items-center rounded-full px-3 text-sm font-medium text-[var(--accent)] hover:bg-white/[0.04]"
                >
                  Retry
                </button>
              </>
            ) : (
              <p className="text-[var(--muted)]">Loading your latest security check…</p>
            )}
          </AssistantBubble>

          {messages.map((message) =>
            message.role === "user" ? (
              <UserBubble key={message.id} text={message.text} />
            ) : (
              <AssistantBubble key={message.id} tone={message.tone}>
                {message.card && message.source ? (
                  <WorkflowCard
                    card={message.card}
                    disabled={busy}
                    onSelectIssue={onSelectIssue}
                    onGuidedFix={onGuidedFix}
                    onViewFindings={viewFindings}
                    latestAssessmentId={latestAssessmentId}
                    placement="above"
                  />
                ) : null}
                {message.source ? (
                  <p data-source={message.source} className="mb-1.5 text-[11px] text-[var(--muted)]">
                    {sourceLabel(message.source)}
                  </p>
                ) : null}
                <p className={message.source || message.text.includes("\n") ? "whitespace-pre-line" : undefined}>
                  {message.text}
                </p>
                {message.card && !message.source ? (
                  <WorkflowCard
                    card={message.card}
                    disabled={busy}
                    onSelectIssue={onSelectIssue}
                    onGuidedFix={onGuidedFix}
                    onViewFindings={viewFindings}
                    latestAssessmentId={latestAssessmentId}
                    placement="below"
                  />
                ) : null}
                {message.source ? (
                  <ExplanationProvenance source={message.source} basis={message.basis} />
                ) : null}
                {message.source && message.action && onOpenAction ? (
                  <ExplanationOpenButton action={message.action} disabled={busy} onOpen={onOpenAction} />
                ) : null}
                {message.actions?.length && message.id === lastAssistantId && onRunCheck && onWorkflowNavigate ? (
                  <WorkflowActions
                    actions={message.actions}
                    busy={busy}
                    running={running !== null}
                    onAsk={(label) => request(label, "shortcut")}
                    onRun={onRunCheck}
                    onNavigate={onWorkflowNavigate}
                    onGuidedFix={onGuidedFix}
                    onNotYet={onNotYet}
                  />
                ) : null}
                {message.suggestions?.length ? (
                  <div className="mt-2 flex flex-wrap gap-2">
                    {message.suggestions.map((id) => {
                      const label = shortcutById(id).label;
                      return (
                        <button
                          key={id}
                          type="button"
                          disabled={busy}
                          onClick={() => request(label, "shortcut")}
                          className="btn-soft inline-flex min-h-11 items-center rounded-full border border-[var(--accent)]/35 bg-white/[0.03] px-3.5 text-xs font-medium text-[var(--accent)] hover:bg-[var(--accent-soft)] disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          {label}
                        </button>
                      );
                    })}
                  </div>
                ) : null}
              </AssistantBubble>
            ),
          )}

          {running ? (
            <li className="flex min-w-0 justify-start">
              <p role="status" data-running={running.kind} className="break-words px-1 text-sm text-[var(--muted)]">
                {running.kind === "VERIFY" ? "Running a verification check" : "Running a security check"} of{" "}
                {running.target}… This can take a minute.
              </p>
            </li>
          ) : null}

          {status ? (
            <li className="flex min-w-0 justify-start">
              <p role="status" className="px-1 text-sm text-[var(--muted)]">
                {status}
              </p>
            </li>
          ) : null}
        </ol>

        <form
          onSubmit={onSubmit}
          className="flex min-w-0 items-end gap-2 border-t border-white/[0.06] p-3"
        >
          <label htmlFor={INPUT_ID} className="sr-only">
            Ask about your security
          </label>
          <textarea
            id={INPUT_ID}
            ref={inputRef}
            rows={1}
            value={draft}
            maxLength={MAX_REQUEST_LENGTH}
            disabled={busy}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Ask about your security..."
            aria-describedby="assistant-input-hint"
            className="glass-inset field-sizing-content max-h-32 min-h-11 w-full min-w-0 flex-1 resize-none rounded-xl px-3.5 py-2.5 text-sm text-[var(--text)] placeholder:text-[var(--muted)]/70 disabled:cursor-not-allowed disabled:opacity-60"
          />
          <button
            type="submit"
            disabled={busy || !draft.trim()}
            aria-label="Send message"
            className="btn-soft inline-flex min-h-11 shrink-0 items-center rounded-full border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-4 text-sm font-medium text-[var(--accent)] hover:bg-[var(--accent)]/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Send
          </button>
        </form>
        <p id="assistant-input-hint" className="sr-only">
          Press Enter to send. Press Shift and Enter for a new line.
        </p>
      </section>

      <aside
        aria-label="Security status and actions"
        data-assistant-sidebar=""
        className="flex min-h-0 min-w-0 flex-col gap-3 lg:overflow-y-auto"
      >
        <SecurityStatusCard context={context} loadFailed={assessmentsError !== null} now={now} />
        <AssistantActions context={context} busy={busy} request={request} />
      </aside>
    </div>
  );
}

type Props = {
  assessments: AssessmentSummary[] | null;
  assessmentsError: string | null;
  onRetryAssessments: () => void;
  onNavigate: (request: NavRequest) => void;
  /** Conversation is kept by the app so it survives leaving the Assistant. */
  messages: readonly AssistantMessage[];
  onMessage: (message: AssistantMessage) => void;
  /** Workflow state is kept by the app too; without it there is no workflow. */
  workflow?: AssistantWorkflowState;
  getWorkflow?: () => AssistantWorkflowState;
  onWorkflowChange?: (patch: Partial<AssistantWorkflowState>) => void;
  onAssessmentCreated?: () => void;
  now?: number;
};

export function AssistantPage({
  assessments,
  assessmentsError,
  onRetryAssessments,
  onNavigate,
  messages,
  onMessage,
  workflow,
  getWorkflow,
  onWorkflowChange,
  onAssessmentCreated,
  now,
}: Props) {
  const latest = assessments ? selectLatestAssessment(assessments) : null;
  const detailId = latest?.status === "COMPLETE" ? latest.id : null;

  const loadDetail = useCallback(
    (): Promise<AssessmentDetail | null> =>
      detailId ? fetchAssessment(detailId) : Promise.resolve(null),
    [detailId],
  );
  const detail = useAsyncData(loadDetail, 0);

  const context = useMemo(() => {
    if (!assessments) return null;
    let detailState: LatestDetailState | null = null;
    if (detailId) {
      detailState = detail.error
        ? { status: "error", message: detail.error }
        : detail.data && detail.data.id === detailId
          ? { status: "ready", detail: detail.data }
          : { status: "loading" };
    }
    return buildAssistantContext(assessments, detailState);
  }, [assessments, detailId, detail.data, detail.error]);

  const latestDetail = detailId && detail.data?.id === detailId ? detail.data : null;
  const [status, setStatus] = useState<string | null>(null);
  const latestDeps = useRef({ context, latestDetail, onNavigate, onMessage, getWorkflow, onWorkflowChange, onAssessmentCreated });
  latestDeps.current = { context, latestDetail, onNavigate, onMessage, getWorkflow, onWorkflowChange, onAssessmentCreated };
  const conversation = useRef<AssistantConversation | null>(null);
  const hasWorkflow = Boolean(getWorkflow && onWorkflowChange);

  useEffect(() => {
    const workflowDeps: WorkflowDeps | undefined = hasWorkflow
      ? {
          get: () => latestDeps.current.getWorkflow!(),
          update: (patch) => latestDeps.current.onWorkflowChange?.(patch),
          runAssessment: createAssessment,
          loadAssessment: fetchAssessment,
          onAssessmentCreated: () => latestDeps.current.onAssessmentCreated?.(),
        }
      : undefined;
    const controller = createAssistantConversation({
      getContext: () => latestDeps.current.context,
      getLatestDetail: () => latestDeps.current.latestDetail,
      navigate: (request) => latestDeps.current.onNavigate(request),
      addMessage: (message) => latestDeps.current.onMessage(message),
      setStatus,
      explain: explainWithAssistant,
      ...(workflowDeps ? { workflow: workflowDeps } : {}),
    });
    conversation.current = controller;
    return () => {
      controller.close();
      conversation.current = null;
    };
  }, [hasWorkflow]);

  const handleAssistantRequest = useCallback(
    (text: string): Promise<RequestOutcome> =>
      conversation.current?.handleAssistantRequest(text) ??
      Promise.resolve({ status: "rejected", reason: "closed" }),
    [],
  );

  const openAction = useCallback((action: AssistantAction) => {
    conversation.current?.openAction(action);
  }, []);
  const runCheck = useCallback((kind: "CHECK" | "VERIFY") => {
    void conversation.current?.runCheck(kind);
  }, []);
  const selectIssue = useCallback((checkId: string) => {
    conversation.current?.selectIssue(checkId);
  }, []);
  const workflowNavigate = useCallback((id: NavigationActionId) => {
    conversation.current?.openWorkflowAction(id);
  }, []);
  const guidedFix = useCallback((checkId: string) => {
    conversation.current?.startGuidedFix(checkId);
  }, []);
  const notYet = useCallback(() => {
    conversation.current?.declineVerification();
  }, []);

  return (
    <AssistantView
      context={context}
      assessmentsError={assessmentsError}
      onRetryAssessments={onRetryAssessments}
      messages={messages}
      status={status}
      onRequest={handleAssistantRequest}
      onOpenAction={openAction}
      {...(hasWorkflow
        ? {
            running: workflow?.running ?? null,
            onRunCheck: runCheck,
            onSelectIssue: selectIssue,
            onGuidedFix: guidedFix,
            onNotYet: notYet,
            onWorkflowNavigate: workflowNavigate,
          }
        : {})}
      now={now}
    />
  );
}
