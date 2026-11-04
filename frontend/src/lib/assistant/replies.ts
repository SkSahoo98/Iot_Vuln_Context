/**
 * Short replies about the issues of the latest complete check: the issue list,
 * one issue's meaning, why it matters and how serious it is, and the short
 * clarifications for unclear questions. Titles, severities, meanings and fixes
 * are the recorded values (UX-1 mapping and backend remediation); the impact
 * line is the fixed plain-language copy per check. Nothing here calls a model,
 * scores risk or starts a check.
 */
import { findingDisplayTitle, issueGroup, issueImpact, pluralize } from "../securityHome";
import type { AssistantContext, AssistantIssue } from "./context";
import { issueBullets, OPEN_PORT_NOTE, type FactAnswer } from "./facts";
import {
  findingCountLines,
  findingsOverviewText,
  issueCountText,
  issuesCard,
  lowerSeverityKinds,
  MAX_LISTED_ISSUES,
  WORKFLOW_ACTIONS,
} from "./workflow";

const URGENT = new Set(["CRITICAL", "HIGH"]);

/** "What are these security issues?": count, then the most important issues to choose from. */
export function buildIssueSummaryResponse(context: AssistantContext): FactAnswer {
  const issues = context.importantIssues ?? [];
  const allFindings = context.findingCounts?.additional ? [WORKFLOW_ACTIONS.viewAllFindings] : [];
  return {
    text: issueCountText(context),
    card: issues.length ? issuesCard(context) : null,
    actions:
      issues.length > 1
        ? [WORKFLOW_ACTIONS.reviewIssues, WORKFLOW_ACTIONS.mostSerious, WORKFLOW_ACTIONS.evidence, ...allFindings]
        : issues.length === 1
          ? [WORKFLOW_ACTIONS.reviewIssues, WORKFLOW_ACTIONS.howFix, WORKFLOW_ACTIONS.evidence, ...allFindings]
          : [WORKFLOW_ACTIONS.reviewIssues, ...allFindings],
  };
}

const NUMBER_WORDS: Record<string, number> = { one: 1, two: 2, three: 3, four: 4, five: 5 };

/** The number in "only two" / "only 2"; null for other count questions. */
export function askedFindingCount(matchedPhrase: string | null): number | null {
  const word = (matchedPhrase ?? "").match(/^only (\w+)$/)?.[1];
  if (!word) return null;
  return NUMBER_WORDS[word] ?? (Number.isInteger(Number(word)) ? Number(word) : null);
}

/**
 * "How many issues?", "Are there only two vulnerabilities?": the recorded
 * findings by group. LOW and INFO findings are never called vulnerabilities.
 */
export function buildFindingCountResponse(context: AssistantContext, asked: number | null): FactAnswer {
  const counts = context.findingCounts!;
  const issues = context.issueCounts?.importantIssues ?? null;
  const actions = counts.total ? [WORKFLOW_ACTIONS.viewAllFindings, ...(counts.important ? [WORKFLOW_ACTIONS.mostSerious] : [])] : [];
  if (asked === null) return { text: findingCountLines(counts, issues).join("\n"), card: null, actions };
  if (counts.total === 0) {
    return { text: "No. Your latest check recorded no findings.\nThat covers only the checks run on your authorized target.", card: null, actions };
  }
  const answer = asked === counts.total ? "Yes." : "No.";
  const important = counts.important;
  const additional = counts.additional;
  const labels = [counts.critical && "CRITICAL", counts.high && "HIGH", counts.medium && "MEDIUM"].filter(Boolean).join("/");
  const kinds = lowerSeverityKinds(counts);
  const importantNoun =
    issues === null || issues === important
      ? important === 1 ? "is an important security issue" : "are important security issues"
      : important === 1 ? "is an important finding" : "are important findings";
  let detail: string;
  if (important && additional) {
    detail = `${important} ${importantNoun} (${labels}), while the other ${additional} ${additional === 1 ? `is a ${kinds} finding` : `are ${kinds} findings`}.`;
  } else if (important) {
    detail = `${important === 1 ? "It" : `All ${important}`} ${importantNoun} (${labels}). No additional lower-severity findings.`;
  } else {
    detail = `No high-priority issues were found — ${counts.total === 1 ? `it is a ${kinds} finding` : `all are ${kinds} findings`}.`;
  }
  return { text: `${answer} Your check produced ${pluralize(counts.total, "finding")}.\n${detail}`, card: null, actions };
}

type LowerGroup = { title: string; severity: string; count: number };
type RecordedFindings = { findings: readonly (Parameters<typeof findingDisplayTitle>[0] & { severity: string })[] };

/** LOW and INFO findings grouped by check and severity, LOW first, with the Security page's titles. */
function lowerSeverityGroups(detail: RecordedFindings): LowerGroup[] {
  const groups = new Map<string, LowerGroup>();
  for (const finding of detail.findings) {
    if (issueGroup(finding.severity) === "important") continue;
    const key = `${finding.finding_id}|${finding.severity}`;
    const group = groups.get(key);
    if (group) group.count += 1;
    else groups.set(key, { title: findingDisplayTitle(finding), severity: finding.severity, count: 1 });
  }
  const rank = (severity: string) => (issueGroup(severity) === "observation" ? 1 : 0);
  return [...groups.values()].sort((a, b) => rank(a.severity) - rank(b.severity) || a.title.localeCompare(b.title));
}

/** "Show me everything": every recorded finding in short groups; the full records stay under View all findings. */
export function buildAllFindingsResponse(context: AssistantContext, detail: RecordedFindings | null): FactAnswer {
  const counts = context.findingCounts!;
  const issues = context.importantIssues ?? [];
  const lines = [findingsOverviewText(counts, context.issueCounts?.importantIssues ?? null)];
  if (counts.total) {
    lines.push(...issueBullets(issues));
    if (detail) {
      for (const group of lowerSeverityGroups(detail)) {
        lines.push(`• ${group.title} — ${group.severity}${group.count > 1 ? ` (${group.count} findings)` : ""}`);
      }
    }
    lines.push("View all findings opens every recorded finding with its evidence.");
  } else {
    lines.push("That covers only the checks run on your authorized target.");
  }
  return {
    text: lines.join("\n"),
    card: null,
    actions: counts.total ? [{ ...WORKFLOW_ACTIONS.viewAllFindings, primary: true }, ...(issues.length ? [WORKFLOW_ACTIONS.mostSerious] : [])] : [],
    shown: issues.map((issue) => issue.checkId),
  };
}

export type IssueAspect = "MEANING" | "WHY" | "SEVERITY";

const NO_DESCRIPTION = "There's no plain-language description for this issue yet; the technical details show what was recorded.";

/** One issue: what it is, why it matters, or how serious it is. */
export function buildIssueExplanationResponse(issue: AssistantIssue, aspect: IssueAspect): FactAnswer {
  const impact = issueImpact(issue.checkId);
  switch (aspect) {
    case "MEANING":
      return {
        text: `${issue.title} — ${issue.severity}.\n${issue.meaning ?? NO_DESCRIPTION}`,
        card: null,
        actions: [WORKFLOW_ACTIONS.whyProblem, WORKFLOW_ACTIONS.howFix, WORKFLOW_ACTIONS.seeTechnical],
      };
    case "WHY": {
      const lines = [impact ?? issue.meaning ?? NO_DESCRIPTION];
      lines.push(issue.remediation ? `Fix: ${issue.remediation}` : "No recorded fix is available for this issue.");
      return {
        text: lines.join("\n"),
        card: null,
        actions: [WORKFLOW_ACTIONS.howFix, WORKFLOW_ACTIONS.tellMore, WORKFLOW_ACTIONS.seeTechnical],
      };
    }
    case "SEVERITY": {
      const severity = issue.severity.toUpperCase();
      const rating = URGENT.has(severity)
        ? `Yes. “${issue.title}” is rated ${issue.severity}, so it's worth fixing soon.`
        : severity === "MEDIUM"
          ? `“${issue.title}” is rated ${issue.severity}: worth fixing, but less urgent than HIGH issues.`
          : `“${issue.title}” is rated ${issue.severity}, a minor issue.`;
      const reason = impact ?? issue.meaning;
      return {
        text: reason ? `${rating}\n${reason}` : rating,
        card: null,
        actions: [WORKFLOW_ACTIONS.howFix, WORKFLOW_ACTIONS.whyProblem, WORKFLOW_ACTIONS.seeTechnical],
      };
    }
  }
}

/**
 * "Which one is more serious?": the recorded severity order of the important
 * issues. `top` is the single most serious issue, or null when tied or none.
 */
export function buildMostSeriousResponse(context: AssistantContext): FactAnswer & { top: AssistantIssue | null } {
  const issues = context.importantIssues ?? [];
  if (!issues.length) {
    return {
      text: "Your latest check found no important security issues, so there's nothing to rank.",
      card: null,
      actions: [WORKFLOW_ACTIONS.reviewIssues],
      top: null,
    };
  }
  const [first] = issues;
  if (issues.length === 1) {
    return {
      text: `“${first.title}” is the only important issue — ${first.severity}.\nStart with it, then run another check.`,
      card: null,
      actions: [WORKFLOW_ACTIONS.howFix, WORKFLOW_ACTIONS.whyProblem],
      top: first,
    };
  }
  const tied = issues.filter((issue) => issue.severity === first.severity);
  if (tied.length > 1) {
    return {
      text: `These are all rated ${first.severity}. Choose one to start with:`,
      card: issuesCard({ ...context, importantIssues: tied }),
      actions: [WORKFLOW_ACTIONS.reviewIssues],
      top: null,
    };
  }
  const next = issues.slice(1, MAX_LISTED_ISSUES);
  return {
    text: [
      `“${first.title}” is the most serious — ${first.severity}.`,
      ...next.map((issue) => `Next: “${issue.title}” — ${issue.severity}.`),
      "Start with the most serious one, then run another check.",
    ].join("\n"),
    card: null,
    actions: [WORKFLOW_ACTIONS.howFix, WORKFLOW_ACTIONS.whyProblem, WORKFLOW_ACTIONS.seeTechnical],
    top: first,
    shown: [first, ...next].map((issue) => issue.checkId),
  };
}

export type GroupAspect = "MEANING" | "WHY" | "SEVERITY" | "FIX";

const severityAdvice = (severity: string) => {
  const level = severity.toUpperCase();
  return URGENT.has(level) ? "fix this soon" : level === "MEDIUM" ? "worth fixing, less urgent" : "minor";
};

/** "What are these two?", "How do I fix both?": one short line per referenced issue. */
export function buildIssueGroupResponse(issues: readonly AssistantIssue[], aspect: GroupAspect): FactAnswer {
  const listed = issues.slice(0, MAX_LISTED_ISSUES);
  const name = listed.length === 2 ? "both issues" : `these ${listed.length} issues`;
  if (aspect === "FIX") return buildFixListResponse(listed);
  const shown = listed.map((issue) => issue.checkId);
  switch (aspect) {
    case "MEANING":
      return {
        text: [
          listed.length === 2 ? "Here's what the two issues mean:" : `Here's what these ${listed.length} issues mean:`,
          ...listed.map((issue) => `• ${issue.title} (${issue.severity}): ${issue.meaning ?? NO_DESCRIPTION}`),
        ].join("\n"),
        card: null,
        actions: [WORKFLOW_ACTIONS.mostSerious, WORKFLOW_ACTIONS.fixThem, WORKFLOW_ACTIONS.whyTheyMatter],
        shown,
      };
    case "WHY":
      return {
        text: [
          `Why ${name} matter:`,
          ...listed.map((issue) => `• ${issue.title}: ${issueImpact(issue.checkId) ?? issue.meaning ?? NO_DESCRIPTION}`),
        ].join("\n"),
        card: null,
        actions: [WORKFLOW_ACTIONS.fixThem, WORKFLOW_ACTIONS.mostSerious],
        shown,
      };
    case "SEVERITY":
      return {
        text: [
          "How serious each one is:",
          ...listed.map((issue) => `• ${issue.title} — ${issue.severity}: ${severityAdvice(issue.severity)}`),
          `Start with “${listed[0].title}”.`,
        ].join("\n"),
        card: null,
        actions: [WORKFLOW_ACTIONS.fixThem, WORKFLOW_ACTIONS.whyTheyMatter],
        shown,
      };
  }
}

/**
 * "How do I fix both?": one guided fix per issue, never one combined set of
 * instructions. The only ordering offered is the recorded severity.
 */
export function buildFixListResponse(issues: readonly AssistantIssue[], asWhich = false): FactAnswer {
  const listed = issues.slice(0, MAX_LISTED_ISSUES);
  const rank = (issue: AssistantIssue) => SEVERITY_ORDER.indexOf(issue.severity.toUpperCase());
  const top = [...listed].sort((a, b) => rank(a) - rank(b))[0];
  const tied = listed.filter((issue) => rank(issue) === rank(top)).length > 1;
  const startWith = top && !tied ? top : null;
  return {
    text: [
      asWhich ? "Which issue do you want to fix?" : `Fix these ${listed.length} issues one at a time.`,
      startWith ? `Start with the ${startWith.severity} severity issue.` : "Choose one to start with.",
    ].join(" "),
    card: {
      kind: "FIX_LIST",
      issues: listed.map((issue) => ({ checkId: issue.checkId, title: issue.title, severity: issue.severity })),
      startWith: startWith?.checkId ?? null,
    },
    actions: [],
    shown: listed.map((issue) => issue.checkId),
  };
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

/** "The LOW one" when no important issue of that severity was recorded. */
export function buildNoSeverityResponse(context: AssistantContext, severity: string): FactAnswer {
  const issues = context.importantIssues ?? [];
  return {
    text: issues.length
      ? `Your latest check didn't report an important ${severity} issue. These are the important ones:`
      : `Your latest check didn't report an important ${severity} issue.`,
    card: issues.length ? issuesCard(context) : null,
    actions: [],
  };
}

export const NO_ISSUE_MATCH = "I couldn't match that to one of the current issues.";

/** "The telnet one" when no current issue fits the description. */
export function buildNoMatchResponse(context: AssistantContext, candidates: readonly AssistantIssue[]): FactAnswer {
  return {
    text: candidates.length ? `${NO_ISSUE_MATCH} These are the current ones:` : NO_ISSUE_MATCH,
    card: candidates.length ? issuesCard({ ...context, importantIssues: [...candidates] }) : null,
    actions: [],
  };
}

/** Several issues are on screen and the question doesn't say which one. */
export function buildWhichIssueResponse(context: AssistantContext): FactAnswer {
  return { text: "Which issue do you mean? Choose one:", card: issuesCard(context), actions: [] };
}

/** "Is it bad?" after a ports answer: important issues recorded on that port (or on any port). */
export function buildPortIssuesResponse(context: AssistantContext, port: number | null): FactAnswer {
  const issues = (context.importantIssues ?? []).filter((issue) =>
    port === null ? issue.ports.length > 0 : issue.ports.includes(port),
  );
  const place = port === null ? "the open ports" : `port ${port}`;
  if (!issues.length) {
    return {
      text: `${OPEN_PORT_NOTE}\nYour latest check didn't report an important issue on ${place}.`,
      card: null,
      actions: [WORKFLOW_ACTIONS.reviewIssues],
    };
  }
  const listed = issues.slice(0, MAX_LISTED_ISSUES);
  return {
    text: [OPEN_PORT_NOTE, `On ${place}, your latest check found:`, ...issueBullets(listed)].join("\n"),
    card: null,
    actions: [WORKFLOW_ACTIONS.securityIssues, WORKFLOW_ACTIONS.howFix],
    shown: listed.map((issue) => issue.checkId),
  };
}

export type ClarificationKind = "WHAT" | "TOPIC";

/** A short question instead of a guess, with the three things the assistant can explain. */
export function buildClarificationResponse(kind: ClarificationKind): FactAnswer {
  return {
    text:
      kind === "WHAT"
        ? "Which part would you like me to explain?"
        : "I can explain your latest security check. What would you like to see?",
    card: null,
    actions: [WORKFLOW_ACTIONS.securityIssues, WORKFLOW_ACTIONS.riskScore, WORKFLOW_ACTIONS.portsShort],
  };
}
