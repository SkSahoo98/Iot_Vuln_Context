/**
 * Security home state derived from the assessment API only. Values are taken
 * from backend records as returned; nothing here scores or detects anything.
 */
import type { AssessmentDetail, AssessmentFinding, AssessmentSummary } from "../api/types";
import { recordedRemediation } from "../components/assessments/detailFormat";

/** Milliseconds since epoch, or null when the timestamp cannot be read. */
function instant(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function startInstant(item: AssessmentSummary): number | null {
  return instant(item.started_at) ?? instant(item.created_at);
}

/**
 * Most recent assessment by recorded start time (completion and creation time
 * break ties). Records without a readable timestamp are never chosen over
 * records that have one.
 */
export function selectLatestAssessment(
  items: readonly AssessmentSummary[],
): AssessmentSummary | null {
  let latest: AssessmentSummary | null = null;
  for (const item of items) {
    if (latest === null || isNewer(item, latest)) latest = item;
  }
  return latest;
}

function isNewer(a: AssessmentSummary, b: AssessmentSummary): boolean {
  const aBatch = a.metadata?.batch_id;
  const bBatch = b.metadata?.batch_id;
  if (aBatch && bBatch && aBatch === bBatch) {
    if (a.assessment_type === "ENVIRONMENT" && b.assessment_type !== "ENVIRONMENT") return true;
    if (b.assessment_type === "ENVIRONMENT" && a.assessment_type !== "ENVIRONMENT") return false;
  }

  const keys: ((item: AssessmentSummary) => number | null)[] = [
    startInstant,
    (item) => instant(item.completed_at),
    (item) => instant(item.created_at),
  ];
  for (const key of keys) {
    const left = key(a);
    const right = key(b);
    if (left === right) continue;
    if (left === null) return false;
    if (right === null) return true;
    return left > right;
  }
  return false;
}

export type HomeState =
  | { kind: "empty" }
  | { kind: "complete"; latest: AssessmentSummary }
  | { kind: "incomplete"; latest: AssessmentSummary }
  | { kind: "failed"; latest: AssessmentSummary }
  | { kind: "running"; latest: AssessmentSummary };

export function securityHomeState(items: readonly AssessmentSummary[]): HomeState {
  const latest = selectLatestAssessment(items);
  if (!latest) return { kind: "empty" };
  switch (latest.status) {
    case "COMPLETE":
      return { kind: "complete", latest };
    case "INCOMPLETE":
      return { kind: "incomplete", latest };
    case "FAILED":
      return { kind: "failed", latest };
    default:
      return { kind: "running", latest };
  }
}

/** Plain-language wording per catalog check ID (scanner/core/catalog.py). */
const ISSUE_COPY: Record<string, { title: string; summary: string }> = {
  "NET-01": {
    title: "Open network service found",
    summary: "A network service on the target accepts connections.",
  },
  "NET-02": {
    title: "More network services are open than expected",
    summary:
      "The number of open services is above the configured limit, which widens the attack surface.",
  },
  "NET-03": {
    title: "Telnet remote access is exposed",
    summary:
      "Telnet is reachable. It sends passwords and session data without encryption.",
  },
  "NET-04": {
    title: "FTP file transfer is exposed",
    summary: "An FTP service is reachable on the target.",
  },
  "NET-06": {
    title: "An administrative service is reachable",
    summary:
      "A service on the configured list of administrative ports accepts connections.",
  },
  "IOT-MQTT-01": {
    title: "MQTT broker accepts connections without a password",
    summary:
      "The broker accepted a connection that supplied no username or password.",
  },
  "IOT-MQTT-02": {
    title: "MQTT traffic is not encrypted",
    summary:
      "The broker accepted unencrypted MQTT and no encrypted MQTT listener was reachable.",
  },
  "IOT-MQTT-03": {
    title: "MQTT broker reveals its software version",
    summary: "The broker's version was readable through its system status topics.",
  },
  "WEB-01": {
    title: "Web interface is served without encryption",
    summary: "A web page was served over plain HTTP and no HTTPS service was found.",
  },
  "WEB-02": {
    title: "Web security headers are missing",
    summary:
      "The web server's responses lack some recommended browser security headers.",
  },
  "WEB-03": {
    title: "Web server reveals software details",
    summary: "The web server's response headers disclose software or version details.",
  },
  "TLS-01": {
    title: "Encrypted service available",
    summary: "An encrypted (TLS) connection to the service succeeded.",
  },
  "TLS-02": {
    title: "Security certificate has expired",
    summary: "An encrypted service presented a certificate that is past its expiry date.",
  },
  "TLS-03": {
    title: "Outdated encryption protocol in use",
    summary: "An encrypted service negotiated TLS 1.1 or an older protocol version.",
  },
  "TLS-04": {
    title: "Security certificate could not be verified",
    summary:
      "The certificate could not be validated against trusted certificate authorities.",
  },
};

/**
 * Why each catalog check matters, in plain words. It describes what the issue
 * could allow, not what was observed; observations stay in ISSUE_COPY.summary.
 */
const ISSUE_IMPACT: Record<string, string> = {
  "NET-01": "Every reachable service is another way into the device, so services that aren't needed are worth closing.",
  "NET-02": "Each extra open service is another way for someone on the network to reach the device.",
  "NET-03": "Anyone who can see the network traffic may be able to read Telnet passwords and commands.",
  "NET-04": "FTP usually sends logins and files without encryption, so they may be readable on the network.",
  "NET-06": "Administrative services can control the device, so they should only be reachable from trusted hosts.",
  "IOT-MQTT-01": "Anyone who can reach the broker may be able to connect without logging in.",
  "IOT-MQTT-02": "Messages sent to the broker may be readable by anyone who can see the network traffic.",
  "IOT-MQTT-03": "Knowing the exact software version makes it easier to look up known weaknesses for it.",
  "WEB-01": "Pages and any logins sent over plain HTTP may be readable on the network.",
  "WEB-02": "Without these headers, browsers apply fewer built-in protections to the page.",
  "WEB-03": "Software and version details make it easier to look up known weaknesses.",
  "TLS-02": "An expired certificate no longer proves the service's identity, and clients may reject it.",
  "TLS-03": "Old TLS versions have known weaknesses that make encrypted traffic easier to attack.",
  "TLS-04": "Without a verifiable certificate, a client can't be sure it is talking to the real service.",
};

/** Plain-language impact of a catalog check; null for checks without one. */
export function issueImpact(checkId: string): string | null {
  return ISSUE_IMPACT[checkId] ?? null;
}

export type IssueGroup = "important" | "minor" | "observation";

const IMPORTANT = new Set(["CRITICAL", "HIGH", "MEDIUM"]);
const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

export function issueGroup(severity: string): IssueGroup {
  const value = severity.toUpperCase();
  if (IMPORTANT.has(value)) return "important";
  if (value === "INFO") return "observation";
  return "minor";
}

export type SimpleIssue = {
  /** Stable React key; not for display. */
  key: string;
  /** Catalog check ID reported by the backend (finding_id). */
  checkId: string;
  severity: string;
  title: string;
  summary: string | null;
  remediation: string | null;
  /** Number of findings of this check in the assessment. */
  occurrences: number;
  /** Distinct ports recorded on these findings, ascending; empty when none. */
  ports: number[];
  /** Highest backend risk score recorded for these findings (ordering only). */
  recordedScore: number | null;
};

export type IssueSummary = {
  important: SimpleIssue[];
  minor: SimpleIssue[];
  observationCount: number;
};

function bySeverityThenScore(a: SimpleIssue, b: SimpleIssue): number {
  const rank =
    (SEVERITY_RANK[a.severity.toUpperCase()] ?? 5) -
    (SEVERITY_RANK[b.severity.toUpperCase()] ?? 5);
  if (rank !== 0) return rank;
  const score = (b.recordedScore ?? -1) - (a.recordedScore ?? -1);
  if (score !== 0) return score;
  return a.title.localeCompare(b.title);
}

/**
 * One simple issue per check: the same check reported on several services is
 * shown once. Severity, title fallback and remediation are backend values.
 */
export function summarizeIssues(
  detail: Pick<AssessmentDetail, "findings" | "risk_snapshots">,
): IssueSummary {
  const scoreByFinding = new Map<string, number>();
  for (const snapshot of detail.risk_snapshots) {
    if (snapshot.finding_ref) scoreByFinding.set(snapshot.finding_ref, snapshot.score);
  }

  const byCheck = new Map<string, SimpleIssue>();
  let observationCount = 0;

  for (const finding of detail.findings) {
    if (issueGroup(finding.severity) === "observation") {
      observationCount += 1;
      continue;
    }
    const groupKey = `${finding.finding_id}|${finding.severity}`;
    const score = scoreByFinding.get(finding.id) ?? null;
    const existing = byCheck.get(groupKey);
    if (existing) {
      existing.occurrences += 1;
      if (finding.port !== null && !existing.ports.includes(finding.port)) {
        existing.ports.push(finding.port);
      }
      if (score !== null && (existing.recordedScore ?? -1) < score) {
        existing.recordedScore = score;
      }
      continue;
    }
    const copy = ISSUE_COPY[finding.finding_id];
    byCheck.set(groupKey, {
      key: groupKey,
      checkId: finding.finding_id,
      severity: finding.severity,
      title: copy?.title ?? finding.title,
      summary: copy?.summary ?? null,
      remediation: recordedRemediation(finding.remediation),
      occurrences: 1,
      ports: finding.port === null ? [] : [finding.port],
      recordedScore: score,
    });
  }

  const issues = [...byCheck.values()];
  for (const issue of issues) issue.ports.sort((a, b) => a - b);
  return {
    important: issues
      .filter((issue) => issueGroup(issue.severity) === "important")
      .sort(bySeverityThenScore),
    minor: issues
      .filter((issue) => issueGroup(issue.severity) === "minor")
      .sort(bySeverityThenScore),
    observationCount,
  };
}

/**
 * Recorded findings by severity, one per finding record (not grouped by check).
 * Important = CRITICAL/HIGH/MEDIUM; additional = LOW and INFO, grouped by
 * issueGroup like the rest of the app.
 */
export type FindingCounts = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  important: number;
  additional: number;
  total: number;
};

export function countFindings(findings: readonly Pick<AssessmentFinding, "severity">[]): FindingCounts {
  const counts: FindingCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, important: 0, additional: 0, total: 0 };
  for (const finding of findings) {
    const severity = finding.severity.toUpperCase();
    const group = issueGroup(severity);
    if (group === "important") {
      counts.important += 1;
      if (severity === "CRITICAL") counts.critical += 1;
      else if (severity === "HIGH") counts.high += 1;
      else counts.medium += 1;
    } else {
      counts.additional += 1;
      if (group === "observation") counts.info += 1;
      else counts.low += 1;
    }
    counts.total += 1;
  }
  return counts;
}

/** Plain-language title of a finding's check, or the recorded title. */
export function findingDisplayTitle(finding: Pick<AssessmentFinding, "finding_id" | "title">): string {
  return ISSUE_COPY[finding.finding_id]?.title ?? finding.title;
}

export function pluralize(count: number, singular: string, plural = `${singular}s`) {
  return `${count} ${count === 1 ? singular : plural}`;
}
