/**
 * Before/after comparison of two backend assessment runs.
 *
 * Presentation logic only: findings and evidence are matched and grouped, and
 * backend values are passed through. Nothing here detects vulnerabilities,
 * scores risk or infers coverage from finding absence.
 *
 * Kept free of runtime imports so it can be exercised directly with Node.
 */
import type {
  AssessmentDetail,
  AssessmentEvidence,
  AssessmentFinding,
  RiskSnapshot,
} from "../api/types";

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/** Run-independent finding identity. Finding UUIDs are run-specific. */
export function findingKey(finding: AssessmentFinding): string {
  return JSON.stringify([finding.finding_id, finding.target, finding.port]);
}

/** Display grouping for evidence. Evidence UUIDs are run-specific. */
export function evidenceKey(evidence: AssessmentEvidence): string {
  return JSON.stringify([evidence.check_type, evidence.target, evidence.port]);
}

function coverageKey(checkId: string, port: number | null): string {
  return JSON.stringify([checkId, port]);
}

function comparePorts(a: number | null, b: number | null): number {
  return (a ?? -1) - (b ?? -1);
}

// ---------------------------------------------------------------------------
// Coverage (metadata.checks_evaluated, recorded by the backend since Phase 3F-A)
// ---------------------------------------------------------------------------

export const COVERAGE_EVALUATED = "EVALUATED";
export const COVERAGE_NOT_APPLICABLE = "NOT_APPLICABLE";
export const COVERAGE_NOT_EVALUATED = "NOT_EVALUATED";

// Backend CheckCoverage merge rule: the weaker status wins for duplicate keys.
// Unrecognised statuses are treated as weaker than all known ones.
const COVERAGE_RANK: Record<string, number> = {
  [COVERAGE_NOT_EVALUATED]: 0,
  [COVERAGE_NOT_APPLICABLE]: 1,
  [COVERAGE_EVALUATED]: 2,
};

function coverageRank(status: string): number {
  return COVERAGE_RANK[status] ?? -1;
}

export type CoverageIndex =
  | { recorded: false }
  | {
      recorded: true;
      entries: Map<string, string>;
      entryCount: number;
      invalidEntries: number;
      /** AFTER-run scanned port set; scope of port-less (scan-wide) entries. */
      scannedPorts: number[] | null;
    };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPort(value: unknown): value is number | null {
  return value === null || (typeof value === "number" && Number.isInteger(value));
}

function numberList(value: unknown): number[] | null {
  if (!Array.isArray(value)) return null;
  return value.every((item) => typeof item === "number") ? (value as number[]) : null;
}

export function readCoverage(detail: AssessmentDetail): CoverageIndex {
  const raw = detail.metadata?.checks_evaluated;
  if (!Array.isArray(raw)) return { recorded: false };

  const entries = new Map<string, string>();
  let invalidEntries = 0;
  for (const item of raw) {
    if (
      !isRecord(item) ||
      typeof item.check_id !== "string" ||
      !isPort(item.port) ||
      typeof item.status !== "string"
    ) {
      invalidEntries += 1;
      continue;
    }
    const key = coverageKey(item.check_id, item.port);
    const current = entries.get(key);
    if (current === undefined || coverageRank(item.status) < coverageRank(current)) {
      entries.set(key, item.status);
    }
  }
  return {
    recorded: true,
    entries,
    entryCount: raw.length,
    invalidEntries,
    scannedPorts: numberList(detail.metadata?.ports),
  };
}

export type CoverageLookup =
  | { kind: "not_recorded" }
  | { kind: "no_entry" }
  | { kind: "entry"; status: string; scope: "port" | "scan_wide" };

/**
 * Coverage for one (check_id, port). An exact entry wins. A port-less entry
 * is the backend's scan-wide record (e.g. NET-* checks) and is only used for
 * a port that is in the run's scanned port set.
 */
export function lookupCoverage(
  index: CoverageIndex,
  checkId: string,
  port: number | null,
): CoverageLookup {
  if (!index.recorded) return { kind: "not_recorded" };
  const exact = index.entries.get(coverageKey(checkId, port));
  if (exact !== undefined) return { kind: "entry", status: exact, scope: "port" };
  if (port !== null && index.scannedPorts?.includes(port)) {
    const scanWide = index.entries.get(coverageKey(checkId, null));
    if (scanWide !== undefined) {
      return { kind: "entry", status: scanWide, scope: "scan_wide" };
    }
  }
  return { kind: "no_entry" };
}

// ---------------------------------------------------------------------------
// Risk snapshots (backend values; never recalculated)
// ---------------------------------------------------------------------------

function latest(snapshots: RiskSnapshot[]): RiskSnapshot | null {
  if (!snapshots.length) return null;
  return snapshots.reduce((best, item) =>
    item.created_at > best.created_at ? item : best,
  );
}

/** Same selection the backend summary uses: newest snapshot with finding_ref NULL. */
export function overallSnapshot(detail: AssessmentDetail): RiskSnapshot | null {
  return latest(detail.risk_snapshots.filter((item) => item.finding_ref === null));
}

export function findingSnapshot(
  detail: AssessmentDetail,
  finding: AssessmentFinding,
): RiskSnapshot | null {
  return latest(detail.risk_snapshots.filter((item) => item.finding_ref === finding.id));
}

export type RiskComparison = {
  before: RiskSnapshot | null;
  after: RiskSnapshot | null;
  /** AFTER - BEFORE, only when both exist with the same score version. */
  delta: number | null;
  unavailableReason: "missing" | "version_mismatch" | null;
};

export function compareRisk(
  before: RiskSnapshot | null,
  after: RiskSnapshot | null,
): RiskComparison {
  if (!before || !after) {
    return { before, after, delta: null, unavailableReason: "missing" };
  }
  if (before.score_version !== after.score_version) {
    return { before, after, delta: null, unavailableReason: "version_mismatch" };
  }
  return {
    before,
    after,
    delta: Math.round((after.score - before.score) * 1000) / 1000,
    unavailableReason: null,
  };
}

// ---------------------------------------------------------------------------
// Comparability gate
// ---------------------------------------------------------------------------

export type GateIssue = {
  level: "blocking" | "warning";
  message: string;
};

/** Metadata that changes which findings the backend rules can produce. */
export const FINDING_CONFIG_KEYS = [
  "ports",
  "nmap_arguments",
  "open_service_threshold",
  "admin_service_ports",
  "mqtt_broker_port",
  "mqtt_tls_port",
] as const;

/** Metadata that can change whether probes complete, but not rule logic. */
const EXECUTION_CONFIG_KEYS = ["nmap_timeout_seconds", "probe_timeout_seconds"] as const;

function normalizeConfig(value: unknown): string {
  const ports = numberList(value);
  return JSON.stringify(ports ? [...ports].sort((a, b) => a - b) : value);
}

function missingSides(
  before: AssessmentDetail,
  after: AssessmentDetail,
  key: string,
): string | null {
  const b = before.metadata?.[key] === undefined;
  const a = after.metadata?.[key] === undefined;
  if (b && a) return "both assessments";
  if (b) return "the BEFORE assessment";
  if (a) return "the AFTER assessment";
  return null;
}

function formatKeyParts(finding: AssessmentFinding): string {
  return `(${finding.finding_id}, ${finding.target}, ${finding.port ?? "no port"})`;
}

/** Comparison keys that occur more than once in one run, described for display. */
export function duplicateFindingKeys(detail: AssessmentDetail): string[] {
  return [...groupBy(detail.findings, findingKey).values()]
    .filter((group) => group.length > 1)
    .map((group) => `${formatKeyParts(group[0])} × ${group.length}`);
}

export function checkComparability(
  before: AssessmentDetail,
  after: AssessmentDetail,
): GateIssue[] {
  const issues: GateIssue[] = [];
  const block = (message: string) => issues.push({ level: "blocking", message });
  const warn = (message: string) => issues.push({ level: "warning", message });

  if (before.id === after.id) {
    block("Cannot compare: the same assessment was selected as BEFORE and AFTER.");
  }

  const beforeStart = Date.parse(before.started_at);
  const afterStart = Date.parse(after.started_at);
  if (Number.isNaN(beforeStart) || Number.isNaN(afterStart)) {
    block("Cannot compare: the start time of one or both assessments could not be read.");
  } else if (beforeStart > afterStart) {
    block("Cannot compare: the BEFORE assessment started after the AFTER assessment.");
  } else if (beforeStart === afterStart && before.id !== after.id) {
    warn("Both assessments have the same recorded start time; their order cannot be confirmed.");
  }

  for (const [label, detail] of [
    ["BEFORE", before],
    ["AFTER", after],
  ] as const) {
    const duplicates = duplicateFindingKeys(detail);
    if (duplicates.length) {
      block(
        `Cannot compare: the ${label} assessment contains duplicate finding keys (finding_id, target, port): ${duplicates.join("; ")}.`,
      );
    }
  }
  if (before.status !== "COMPLETE") {
    block(
      `Cannot compare: the BEFORE assessment status is ${before.status}; only COMPLETE assessments can be compared.`,
    );
  }
  if (after.status !== "COMPLETE") {
    block(
      `Cannot compare: the AFTER assessment status is ${after.status}; only COMPLETE assessments can be compared.`,
    );
  }
  const beforeIsEnv = before.assessment_type === "ENVIRONMENT" || before.target === "AUTHORIZED_IOT";
  const afterIsEnv = after.assessment_type === "ENVIRONMENT" || after.target === "AUTHORIZED_IOT";
  if (beforeIsEnv !== afterIsEnv) {
    block("Cannot compare: assessment scopes differ (single-device assessment vs AUTHORIZED_IOT environment assessment).");
  }
  if (before.target !== after.target) {
    block(`Cannot compare: targets differ (${before.target} vs ${after.target}).`);
  }
  if (before.assessment_type !== after.assessment_type) {
    block(
      `Cannot compare: assessment types differ (${before.assessment_type} vs ${after.assessment_type}).`,
    );
  }

  const beforeCatalog = before.metadata?.check_catalog_version;
  const afterCatalog = after.metadata?.check_catalog_version;
  if (beforeCatalog !== undefined && afterCatalog !== undefined) {
    if (beforeCatalog !== afterCatalog) {
      block(
        `Cannot compare: check catalog versions differ (${String(beforeCatalog)} vs ${String(afterCatalog)}).`,
      );
    }
  } else {
    warn(
      `Check catalog version was not recorded for ${missingSides(before, after, "check_catalog_version")}; it cannot be verified that both runs used the same check definitions.`,
    );
  }

  const differing: string[] = [];
  const unverified: string[] = [];
  for (const key of FINDING_CONFIG_KEYS) {
    const b = before.metadata?.[key];
    const a = after.metadata?.[key];
    if (b === undefined || a === undefined) unverified.push(key);
    else if (normalizeConfig(b) !== normalizeConfig(a)) differing.push(key);
  }
  if (differing.length) {
    block(
      `Cannot compare: finding-affecting configuration differs (${differing.join(", ")}).`,
    );
  }
  if (unverified.length) {
    warn(
      `Finding-affecting configuration could not be fully verified; not recorded for one or both assessments: ${unverified.join(", ")}.`,
    );
  }

  const executionDiffers = EXECUTION_CONFIG_KEYS.filter((key) => {
    const b = before.metadata?.[key];
    const a = after.metadata?.[key];
    return b !== undefined && a !== undefined && normalizeConfig(b) !== normalizeConfig(a);
  });
  if (executionDiffers.length) {
    warn(
      `Execution settings differ (${executionDiffers.join(", ")}); this can affect which checks completed.`,
    );
  }

  if (!readCoverage(after).recorded) {
    warn(
      "Resolution status is unavailable because AFTER coverage was not recorded. Findings absent from the AFTER assessment are listed as not confirmed.",
    );
  }
  if (!readCoverage(before).recorded) {
    warn(
      "BEFORE coverage was not recorded; a NEW finding may not have been evaluated in the BEFORE assessment.",
    );
  }

  return issues;
}

export function isComparable(issues: GateIssue[]): boolean {
  return issues.every((issue) => issue.level !== "blocking");
}

// ---------------------------------------------------------------------------
// Finding comparison
// ---------------------------------------------------------------------------

export type UnconfirmedReason =
  | "NOT_EVALUATED"
  | "NOT_APPLICABLE"
  | "COVERAGE_NOT_RECORDED"
  | "NO_COVERAGE_ENTRY"
  | "UNRECOGNIZED_STATUS";

export type RemainingFinding = {
  key: string;
  before: AssessmentFinding;
  after: AssessmentFinding;
  risk: RiskComparison;
};

export type NewFinding = {
  key: string;
  after: AssessmentFinding;
  risk: RiskSnapshot | null;
  beforeCoverage: CoverageLookup;
};

export type ResolvedFinding = {
  key: string;
  before: AssessmentFinding;
  risk: RiskSnapshot | null;
  coverage: CoverageLookup;
};

export type UnconfirmedFinding = ResolvedFinding & { reason: UnconfirmedReason };

export type FindingComparison = {
  remaining: RemainingFinding[];
  added: NewFinding[];
  resolved: ResolvedFinding[];
  unconfirmed: UnconfirmedFinding[];
};

function groupBy<T>(items: T[], keyOf: (item: T) => string): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const key = keyOf(item);
    const group = groups.get(key);
    if (group) group.push(item);
    else groups.set(key, [item]);
  }
  return groups;
}

/** Throws on duplicate keys; the comparability gate blocks such runs first. */
function uniqueFindings(detail: AssessmentDetail): Map<string, AssessmentFinding> {
  const duplicates = duplicateFindingKeys(detail);
  if (duplicates.length) {
    throw new Error(`Duplicate finding keys in assessment ${detail.id}: ${duplicates.join("; ")}`);
  }
  return new Map(detail.findings.map((finding) => [findingKey(finding), finding]));
}

function byFinding(a: AssessmentFinding, b: AssessmentFinding): number {
  return (
    a.finding_id.localeCompare(b.finding_id) ||
    a.target.localeCompare(b.target) ||
    comparePorts(a.port, b.port)
  );
}

function unconfirmedReason(lookup: CoverageLookup): UnconfirmedReason | null {
  if (lookup.kind === "not_recorded") return "COVERAGE_NOT_RECORDED";
  if (lookup.kind === "no_entry") return "NO_COVERAGE_ENTRY";
  if (lookup.status === COVERAGE_EVALUATED) return null;
  if (lookup.status === COVERAGE_NOT_EVALUATED) return "NOT_EVALUATED";
  if (lookup.status === COVERAGE_NOT_APPLICABLE) return "NOT_APPLICABLE";
  return "UNRECOGNIZED_STATUS";
}

export function compareFindings(
  before: AssessmentDetail,
  after: AssessmentDetail,
): FindingComparison {
  const beforeFindings = uniqueFindings(before);
  const afterFindings = uniqueFindings(after);
  const afterCoverage = readCoverage(after);
  const beforeCoverage = readCoverage(before);
  const result: FindingComparison = {
    remaining: [],
    added: [],
    resolved: [],
    unconfirmed: [],
  };

  for (const [key, finding] of beforeFindings) {
    const match = afterFindings.get(key);
    if (match) {
      result.remaining.push({
        key,
        before: finding,
        after: match,
        risk: compareRisk(
          findingSnapshot(before, finding),
          findingSnapshot(after, match),
        ),
      });
      continue;
    }
    const coverage = lookupCoverage(afterCoverage, finding.finding_id, finding.port);
    const entry: ResolvedFinding = {
      key,
      before: finding,
      risk: findingSnapshot(before, finding),
      coverage,
    };
    const reason = unconfirmedReason(coverage);
    if (reason === null) result.resolved.push(entry);
    else result.unconfirmed.push({ ...entry, reason });
  }

  for (const [key, finding] of afterFindings) {
    if (beforeFindings.has(key)) continue;
    result.added.push({
      key,
      after: finding,
      risk: findingSnapshot(after, finding),
      beforeCoverage: lookupCoverage(beforeCoverage, finding.finding_id, finding.port),
    });
  }

  result.remaining.sort((a, b) => byFinding(a.before, b.before));
  result.added.sort((a, b) => byFinding(a.after, b.after));
  result.resolved.sort((a, b) => byFinding(a.before, b.before));
  result.unconfirmed.sort((a, b) => byFinding(a.before, b.before));
  return result;
}

// ---------------------------------------------------------------------------
// Evidence comparison (side by side; differences are not interpreted)
// ---------------------------------------------------------------------------

export type EvidenceRow = {
  key: string;
  checkType: string;
  target: string;
  port: number | null;
  before: AssessmentEvidence[];
  after: AssessmentEvidence[];
};

export function compareEvidence(
  before: AssessmentDetail,
  after: AssessmentDetail,
): EvidenceRow[] {
  const rows = new Map<string, EvidenceRow>();
  const add = (item: AssessmentEvidence, side: "before" | "after") => {
    const key = evidenceKey(item);
    let row = rows.get(key);
    if (!row) {
      row = {
        key,
        checkType: item.check_type,
        target: item.target,
        port: item.port,
        before: [],
        after: [],
      };
      rows.set(key, row);
    }
    row[side].push(item);
  };
  before.evidence.forEach((item) => add(item, "before"));
  after.evidence.forEach((item) => add(item, "after"));

  return [...rows.values()].sort(
    (a, b) =>
      a.checkType.localeCompare(b.checkType) ||
      a.target.localeCompare(b.target) ||
      comparePorts(a.port, b.port),
  );
}

// ---------------------------------------------------------------------------
// Full comparison
// ---------------------------------------------------------------------------

export type AssessmentComparisonResult = {
  before: AssessmentDetail;
  after: AssessmentDetail;
  issues: GateIssue[];
  comparable: boolean;
  risk: RiskComparison;
  findings: FindingComparison | null;
  evidence: EvidenceRow[] | null;
  afterCoverage: CoverageIndex;
  beforeCoverage: CoverageIndex;
};

export function compareAssessments(
  before: AssessmentDetail,
  after: AssessmentDetail,
): AssessmentComparisonResult {
  const issues = checkComparability(before, after);
  const comparable = isComparable(issues);
  const risk = compareRisk(overallSnapshot(before), overallSnapshot(after));
  if (risk.unavailableReason === "version_mismatch") {
    issues.push({
      level: "warning",
      message: "Cannot compare risk scores: risk score versions differ.",
    });
  }
  return {
    before,
    after,
    issues,
    comparable,
    risk,
    findings: comparable ? compareFindings(before, after) : null,
    evidence: comparable ? compareEvidence(before, after) : null,
    afterCoverage: readCoverage(after),
    beforeCoverage: readCoverage(before),
  };
}
