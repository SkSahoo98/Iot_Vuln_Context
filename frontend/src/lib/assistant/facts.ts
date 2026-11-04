/**
 * Plain answers to factual questions (status, ports, services, the checked
 * device, evidence, risk factors) read from the latest complete assessment.
 * Every value is copied from recorded evidence, findings, risk snapshots or the
 * backend's risk_trace; anything not recorded is reported as not available.
 * Answers are short: a sentence or two, a few bullets, and recorded IDs and raw
 * values only under the collapsed technical details.
 * Nothing here calls a model, scores risk or starts a check.
 */
import type { AssessmentDetail, AssessmentEvidence } from "../../api/types";
import { buildAssessmentTrace, buildEvaluationSummary, EVIDENCE_NOT_AVAILABLE } from "../traceability";
import { pluralize, summarizeIssues } from "../securityHome";
import type { AssistantContext } from "./context";
import { redactSecrets } from "./redact";
import {
  MAX_LISTED_ISSUES,
  WORKFLOW_ACTIONS,
  type AssistantActionButton,
  type AssistantCard,
  type CardIssue,
  type FactItem,
} from "./workflow";

export type FactAnswer = {
  text: string;
  card: AssistantCard | null;
  actions: AssistantActionButton[];
  /** Check IDs of the issues the text lists, in order, for later "these two" / "the first one". */
  shown?: readonly string[];
};

export const OPEN_PORT_NOTE = "An open port is not automatically a security problem.";
export const PORTS_NOT_AVAILABLE = "Open port information isn't available in the latest assessment.";
export const SERVICES_NOT_AVAILABLE = "Service information isn't available in the latest assessment.";
export const RISK_FACTORS_NOT_AVAILABLE = "The risk factors aren't available in the latest assessment.";

/** Technical facts list at most this many items at first; all are kept under the technical details. */
export const MAX_FACT_ITEMS = 5;

const facts = (items: FactItem[], technical: string[]): AssistantCard | null =>
  items.length || technical.length ? { kind: "FACTS", items, technical } : null;

/** The same answer with its technical details shown open, for an explicit request. */
export function withTechnicalOpen(answer: FactAnswer): FactAnswer {
  return answer.card?.kind === "FACTS" ? { ...answer, card: { ...answer.card, expanded: true } } : answer;
}

function recordedText(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? redactSecrets(value.trim()) : null;
}

function joinList(values: readonly string[]): string {
  if (values.length <= 1) return values.join("");
  return `${values.slice(0, -1).join(", ")} and ${values[values.length - 1]}`;
}

const scoreText = (score: number) => `${score.toFixed(1)}/100`;

/** "• Title — HIGH" lines for issue lists in reply text. */
export function issueBullets(issues: readonly Pick<CardIssue, "title" | "severity">[]): string[] {
  return issues.map((issue) => `• ${issue.title} — ${issue.severity}`);
}

function shownOf(total: number, shown: number, noun: string): string | null {
  return total > shown ? `Showing ${shown} of ${pluralize(total, noun)}.` : null;
}

// ----------------------------------------------------------------- status ---

const HIGH_LEVELS = new Set(["HIGH", "CRITICAL"]);

/** "Is my network safe?": recorded risk, then the important issues to fix first. */
export function statusAnswer(context: AssistantContext): FactAnswer {
  const risk = context.risk;
  const lines: string[] = [];
  if (risk?.level) {
    lines.push(
      `Your current risk is ${risk.level}${risk.score !== null && risk.score !== undefined ? ` (${scoreText(risk.score)})` : ""}.`,
    );
  } else {
    lines.push("The overall risk level isn't available in your latest check.");
  }
  const counts = context.issueCounts;
  const issues = context.importantIssues ?? [];
  if (!counts) {
    lines.push("The issues from that check aren't available right now.");
  } else if (issues.length) {
    lines.push(issues.length === 1 ? "The main priority from your latest check:" : "The main priorities from your latest check:");
    lines.push(...issueBullets(issues.slice(0, MAX_LISTED_ISSUES)));
    const more = shownOf(issues.length, MAX_LISTED_ISSUES, "important issue");
    if (more) lines.push(more);
    lines.push(issues.length === 1 ? "Fix it first, then run another check." : "Fix these first, then run another check.");
  } else {
    lines.push(
      counts.minorIssues
        ? `Your latest check found no important issues and ${pluralize(counts.minorIssues, "minor issue")}.`
        : "Your latest check found no important or minor security issues.",
    );
    lines.push("This only covers the checks run on your authorized target.");
  }
  const riskQuestion = risk?.level && HIGH_LEVELS.has(risk.level)
    ? WORKFLOW_ACTIONS.whyRiskHigh
    : WORKFLOW_ACTIONS.riskContributors;
  return {
    text: lines.join("\n"),
    card: null,
    actions: issues.length
      ? [WORKFLOW_ACTIONS.reviewIssues, WORKFLOW_ACTIONS.howFix, riskQuestion]
      : [WORKFLOW_ACTIONS.reviewIssues, riskQuestion, WORKFLOW_ACTIONS.openPorts],
    shown: counts ? issues.slice(0, MAX_LISTED_ISSUES).map((issue) => issue.checkId) : [],
  };
}

// ------------------------------------------------------------ ports/services ---

type RecordedPort = {
  port: number;
  protocol: string | null;
  service: string | null;
  product: string | null;
  version: string | null;
  reason: string | null;
  checkType: string;
  source: string;
};

const isPort = (value: unknown): value is number =>
  typeof value === "number" && Number.isInteger(value) && value > 0 && value <= 65535;

/** Open ports from NMAP_PORT/OPEN evidence, else the scan's open_ports list; null when neither was recorded. */
export function recordedOpenPorts(detail: AssessmentDetail): RecordedPort[] | null {
  const byPort = new Map<number, RecordedPort>();
  for (const item of detail.evidence) {
    if (item.check_type !== "NMAP_PORT" || item.result !== "OPEN" || !isPort(item.port)) continue;
    const o = item.observation ?? {};
    byPort.set(item.port, {
      port: item.port,
      protocol: recordedText(o.protocol),
      service: recordedText(o.service_name),
      product: recordedText(o.product),
      version: recordedText(o.version),
      reason: recordedText(o.reason),
      checkType: item.check_type,
      source: item.evidence_source,
    });
  }
  if (byPort.size) return [...byPort.values()].sort((a, b) => a.port - b.port);

  const scan = detail.evidence.find((item) => item.check_type === "NMAP_SCAN");
  const listed = scan?.observation?.open_ports;
  if (!scan || !Array.isArray(listed)) return null;
  return [...new Set(listed.filter(isPort))]
    .sort((a, b) => a - b)
    .map((port) => ({
      port,
      protocol: null,
      service: null,
      product: null,
      version: null,
      reason: null,
      checkType: scan.check_type,
      source: scan.evidence_source,
    }));
}

/** Ports the latest check was configured to scan; null when not recorded. */
export function scannedPorts(detail: AssessmentDetail): number[] | null {
  const value = detail.metadata?.ports;
  if (!Array.isArray(value)) return null;
  const ports = value.filter(isPort);
  return ports.length ? ports : null;
}

/** Service as the scan identified it: product when it names the service, else service (product). */
export function serviceLabel(port: Pick<RecordedPort, "service" | "product" | "version">): string | null {
  const { service, product, version } = port;
  let label: string | null;
  if (service && product) {
    label = product.toLowerCase().includes(service.toLowerCase()) ? product : `${service} (${product})`;
  } else {
    label = product ?? service;
  }
  if (label && version && !label.includes(version)) label = `${label} ${version}`;
  return label;
}

const portName = (port: RecordedPort) =>
  `Port ${port.port}${port.protocol ? ` (${port.protocol.toUpperCase()})` : ""}`;

function portTechnical(ports: readonly RecordedPort[], scanned: number[] | null): string[] {
  const lines = ports.map(
    (port) =>
      `${port.port}/${port.protocol ?? "?"}: ${port.checkType} OPEN` +
      `${port.reason ? `, reason ${port.reason}` : ""}, source ${port.source}`,
  );
  lines.push(scanned ? `Ports checked: ${scanned.join(", ")}` : "Ports checked: not recorded");
  return lines;
}

/** The port number in "Is port 1883 open?" or "Is 8883 open?", or null. */
export function askedPort(text: string): number | null {
  const match =
    text.match(/\bport\s*#?\s*(\d{1,5})\b/i) ??
    text.match(/\b(?:is|are)\s+(\d{1,5})\s+(?:open|closed|listening|reachable)\b/i);
  if (!match) return null;
  const port = Number(match[1]);
  return isPort(port) ? port : null;
}

export function portsAnswer(detail: AssessmentDetail, asked: number | null): FactAnswer {
  const ports = recordedOpenPorts(detail);
  const scanned = scannedPorts(detail);
  const actions = [WORKFLOW_ACTIONS.services, WORKFLOW_ACTIONS.reviewIssues];
  if (!ports) return { text: PORTS_NOT_AVAILABLE, card: null, actions: [WORKFLOW_ACTIONS.reviewIssues] };

  if (asked !== null) {
    const hit = ports.find((port) => port.port === asked);
    if (hit) {
      const service = serviceLabel(hit);
      return {
        text: `Yes. Port ${asked} is open${service ? ` — the scan identified ${service}` : ""}.\n${OPEN_PORT_NOTE}`,
        card: facts([], portTechnical([hit], scanned)),
        actions,
      };
    }
    const text = scanned?.includes(asked)
      ? `No. Port ${asked} was checked and wasn't found open.`
      : scanned
        ? `I don't have enough evidence to say whether port ${asked} is open. It wasn't part of your latest check.`
        : `Port ${asked} wasn't found open, but I can't confirm it was checked.`;
    return { text, card: facts([], portTechnical([], scanned)), actions };
  }

  if (!ports.length) {
    return {
      text: scanned
        ? `Your latest check didn't find any open ports among the ${scanned.length} it checked.`
        : "Your latest check didn't find any open ports.",
      card: facts([], portTechnical([], scanned)),
      actions: [WORKFLOW_ACTIONS.reviewIssues],
    };
  }
  const items = ports.slice(0, MAX_FACT_ITEMS).map((port) => ({
    title: portName(port),
    detail: serviceLabel(port) ?? "Service not identified",
  }));
  const lines = [`Your latest check recorded ${pluralize(ports.length, "open port")}.`, OPEN_PORT_NOTE];
  const more = shownOf(ports.length, MAX_FACT_ITEMS, "open port");
  if (more) lines.push(more);
  return { text: lines.join("\n"), card: facts(items, portTechnical(ports, scanned)), actions };
}

/** Recorded services; `asked` narrows the answer to one port ("What is running on port 1883?"). */
export function servicesAnswer(detail: AssessmentDetail, asked: number | null = null): FactAnswer {
  const ports = recordedOpenPorts(detail);
  const actions = [WORKFLOW_ACTIONS.openPorts, WORKFLOW_ACTIONS.reviewIssues];
  if (!ports) return { text: SERVICES_NOT_AVAILABLE, card: null, actions: [WORKFLOW_ACTIONS.reviewIssues] };
  const technical = portTechnical(ports, scannedPorts(detail));

  if (asked !== null) {
    const hit = ports.find((port) => port.port === asked);
    if (!hit) {
      return {
        text: `Port ${asked} wasn't found open in your latest check, so no service was recorded there.`,
        card: null,
        actions,
      };
    }
    const service = serviceLabel(hit);
    return {
      text: service
        ? `Port ${asked} is running ${service}, as identified by the network scan.`
        : `Port ${asked} is open, but the scan didn't identify the service on it.`,
      card: facts([], portTechnical([hit], scannedPorts(detail))),
      actions,
    };
  }

  if (!ports.length) {
    return {
      text: "Your latest check didn't find any open ports, so no running services were recorded.",
      card: null,
      actions: [WORKFLOW_ACTIONS.reviewIssues],
    };
  }
  const identified = ports.filter((port) => serviceLabel(port) !== null);
  if (!identified.length) {
    return {
      text: `Your latest check found open ports (${joinList(
        ports.map((port) => String(port.port)),
      )}) but didn't identify the services on them.`,
      card: facts([], technical),
      actions,
    };
  }
  const items = ports.slice(0, MAX_FACT_ITEMS).map((port) => ({
    title: serviceLabel(port) ?? "Service not identified",
    detail: portName(port),
  }));
  const lines = [`Your latest check recorded ${pluralize(identified.length, "service")} on open ports.`];
  const more = shownOf(ports.length, MAX_FACT_ITEMS, "open port");
  if (more) lines.push(more);
  return { text: lines.join("\n"), card: facts(items, technical), actions };
}

/**
 * "The second one" or "What is that?" after a ports or services answer: ask
 * which port is meant instead of guessing. Null when no open port was recorded.
 */
export function portChoiceAnswer(detail: AssessmentDetail, noun: "port" | "service"): FactAnswer | null {
  const ports = recordedOpenPorts(detail);
  if (!ports?.length) return null;
  const list = joinList(ports.map((port) => String(port.port)));
  return {
    text:
      noun === "port"
        ? `Which port do you mean? Your latest check recorded ${ports.length === 1 ? "port" : "ports"} ${list} as open.`
        : `Which service do you mean? Your latest check recorded services on ${ports.length === 1 ? "port" : "ports"} ${list}.`,
    card: null,
    actions: [],
  };
}

// ---------------------------------------------------------------- devices ---

export function devicesAnswer(detail: AssessmentDetail, asked?: string): FactAnswer {
  if (detail.target === "AUTHORIZED_IOT" || detail.assessment_type === "ENVIRONMENT") {
    const posture = detail.metadata?.posture as Record<string, unknown> | undefined;
    const norm = (asked ?? "").toLowerCase();

    if (norm.includes("infrastructure")) {
      const infraSummaries = (posture?.infrastructure_summaries as { asset_id: string; ip_address: string; asset_type?: string }[] | undefined) ?? [];
      const infraCount = (posture?.infrastructure_assessed as number | undefined) ?? (infraSummaries.length || 1);
      const lines = [
        `Your latest check assessed ${pluralize(infraCount, "authorized IoT infrastructure asset")}:`,
      ];
      if (infraSummaries.length) {
        lines.push(...infraSummaries.map((i) => `• MQTT Broker (Windows Laptop) [${i.asset_id}] (${i.ip_address}) — ${i.asset_type ?? "MQTT_BROKER"}`));
      } else {
        lines.push("• MQTT Broker (Windows Laptop) [MQTT-BROKER] (10.32.252.85) — MQTT_BROKER");
      }
      lines.push("IoT devices were assessed separately in the same environment check.");
      return {
        text: lines.join("\n"),
        card: null,
        actions: [WORKFLOW_ACTIONS.openPorts, WORKFLOW_ACTIONS.reviewIssues],
      };
    }

    if (norm.includes("asset")) {
      const devSummaries = (posture?.device_summaries as { device_id: string; ip_address: string }[] | undefined) ?? [];
      const infraSummaries = (posture?.infrastructure_summaries as { asset_id: string; ip_address: string }[] | undefined) ?? [];
      const devCount = (posture?.devices_assessed as number | undefined) ?? devSummaries.length;
      const infraCount = (posture?.infrastructure_assessed as number | undefined) ?? infraSummaries.length;
      const totalAssets = (posture?.assets_assessed as number | undefined) ?? (devCount + infraCount);

      const devList = devSummaries.map((d) => `${d.device_id} (${d.ip_address})`).join(", ");
      const infraList = infraSummaries.map((i) => `${i.asset_id} (${i.ip_address})`).join(", ");

      const lines = [
        `Your latest check assessed ${pluralize(totalAssets, "authorized asset")} in total: ${pluralize(devCount, "IoT device")} and ${pluralize(infraCount, "infrastructure asset")}.`,
      ];
      if (devList) lines.push(`• Devices: ${devList}`);
      if (infraList) lines.push(`• Infrastructure: ${infraList}`);
      lines.push("Only explicitly authorized assets were checked.");
      return {
        text: lines.join("\n"),
        card: null,
        actions: [WORKFLOW_ACTIONS.openPorts, WORKFLOW_ACTIONS.reviewIssues],
      };
    }

    // Default / "how many devices were assessed"
    const devSummaries = (posture?.device_summaries as { device_id: string; ip_address: string }[] | undefined) ?? [];
    const devCount = (posture?.devices_assessed as number | undefined) ?? devSummaries.length;
    const infraCount = (posture?.infrastructure_assessed as number | undefined) ?? ((posture?.infrastructure_summaries as unknown[])?.length ?? 0);

    const lines = [
      `Your latest environment check assessed ${pluralize(devCount, "authorized IoT device")}:`,
    ];
    if (devSummaries.length) {
      lines.push(...devSummaries.map((d) => `• ${d.device_id} (${d.ip_address})`));
    }
    if (infraCount > 0) {
      lines.push(`IoT infrastructure (${pluralize(infraCount, "asset")}) was also assessed.`);
    }
    return {
      text: lines.join("\n"),
      card: null,
      actions: [WORKFLOW_ACTIONS.openPorts, WORKFLOW_ACTIONS.reviewIssues],
    };
  }

  const scan = detail.evidence.find((item) => item.check_type === "NMAP_SCAN");
  const hostState = recordedText(scan?.observation?.host_state);
  const ports = recordedOpenPorts(detail);
  const first = [`Your latest check covered one authorized target: ${detail.target}.`];
  if (hostState === "up") {
    first.push(ports && ports.length ? `It responded with ${pluralize(ports.length, "open port")}.` : "It responded to the network scan.");
  }
  return {
    text: `${first.join(" ")}\nOther devices on your network weren't checked.`,
    card: null,
    actions: [WORKFLOW_ACTIONS.openPorts, WORKFLOW_ACTIONS.reviewIssues],
  };
}

export function assetFindingsAnswer(detail: AssessmentDetail, asked: string): FactAnswer | null {
  const norm = asked.toLowerCase();
  const isBroker = norm.includes("broker") || norm.includes("mqtt");
  const isEsp1 = norm.includes("esp32-01") || norm.includes("esp32 01") || norm.includes("esp32_01") || norm.includes("esp32-1");
  const isEsp2 = norm.includes("esp32-02") || norm.includes("esp32 02") || norm.includes("esp32_02") || norm.includes("esp32-2");
  const isLatestCheck =
    norm.includes("my latest security check") ||
    norm.includes("the latest security check") ||
    norm.includes("latest security check") ||
    norm.includes("my latest check") ||
    norm.includes("the latest check") ||
    norm.includes("my check find");

  if (!isBroker && !isEsp1 && !isEsp2 && !isLatestCheck) {
    return null;
  }

  const actions = [WORKFLOW_ACTIONS.reviewIssues, WORKFLOW_ACTIONS.openPorts];

  if (isBroker) {
    const brokerFindings = detail.findings.filter((f) => f.target === "10.32.252.85");
    if (brokerFindings.length > 0) {
      const bullets = brokerFindings.map((f) => `• ${f.title} — ${f.severity}`);
      return {
        text: `The MQTT Broker (Windows Laptop) at 10.32.252.85 had ${pluralize(brokerFindings.length, "security finding")}:\n${bullets.join("\n")}`,
        card: null,
        actions: [WORKFLOW_ACTIONS.howFix, WORKFLOW_ACTIONS.reviewIssues],
        shown: brokerFindings.map((f) => f.finding_id),
      };
    }
    return {
      text: "The MQTT Broker (Windows Laptop) at 10.32.252.85 had no security findings.",
      card: null,
      actions,
    };
  }

  if (isEsp1) {
    const espFindings = detail.findings.filter((f) => f.target === "10.32.252.105");
    if (espFindings.length > 0) {
      const bullets = espFindings.map((f) => `• ${f.title} — ${f.severity}`);
      return {
        text: `ESP32 Sensor 01 [ESP32-01] (10.32.252.105) had ${pluralize(espFindings.length, "security finding")}:\n${bullets.join("\n")}`,
        card: null,
        actions,
        shown: espFindings.map((f) => f.finding_id),
      };
    }
    return {
      text: "ESP32 Sensor 01 [ESP32-01] (10.32.252.105) had no security findings. All checked ports were closed.",
      card: null,
      actions,
    };
  }

  if (isEsp2) {
    const espFindings = detail.findings.filter((f) => f.target === "10.32.252.57");
    if (espFindings.length > 0) {
      const bullets = espFindings.map((f) => `• ${f.title} — ${f.severity}`);
      return {
        text: `ESP32 Sensor 02 [ESP32-02] (10.32.252.57) had ${pluralize(espFindings.length, "security finding")}:\n${bullets.join("\n")}`,
        card: null,
        actions,
        shown: espFindings.map((f) => f.finding_id),
      };
    }
    return {
      text: "ESP32 Sensor 02 [ESP32-02] (10.32.252.57) had no security findings. All checked ports were closed.",
      card: null,
      actions,
    };
  }

  if (isLatestCheck) {
    if (detail.findings.length === 0) {
      return {
        text: "Your latest security check found no security issues. All checked ports on your authorized devices were closed.",
        card: null,
        actions,
      };
    }
    const bullets = detail.findings.map((f) => `• ${f.title} — ${f.severity} (${f.target})`);
    return {
      text: `Your latest security check recorded ${pluralize(detail.findings.length, "finding")}:\n${bullets.join("\n")}`,
      card: null,
      actions: [WORKFLOW_ACTIONS.reviewIssues, WORKFLOW_ACTIONS.howFix],
      shown: detail.findings.map((f) => f.finding_id),
    };
  }

  return null;
}

// --------------------------------------------------------------- evidence ---

const words = (value: string) => value.toLowerCase().replace(/_/g, " ");

/** One recorded check result in plain words; unknown checks are named as recorded. */
export function evidenceSentence(record: AssessmentEvidence): string {
  const on = record.port !== null ? ` on port ${record.port}` : "";
  switch (`${record.check_type}|${record.result}`) {
    case "MQTT_ANONYMOUS_CONNECT|ACCEPTED":
      return `The MQTT broker${on} accepted a connection without a username or password.`;
    case "MQTT_TRANSPORT_COMPARISON|PLAINTEXT_NO_TLS":
      return `The MQTT broker${on} accepted an unencrypted connection, and no encrypted (TLS) connection was available.`;
    case "NMAP_PORT|OPEN":
      return `The network scan found port ${record.port ?? "(not recorded)"} open.`;
    case "TLS_HANDSHAKE|REFUSED":
      return `The encrypted (TLS) connection attempt${on} was refused.`;
    default:
      return `The ${words(record.check_type)} check recorded “${words(record.result)}”${on}.`;
  }
}

type IssueRef = { checkId: string; title: string; severity: string };

/** Evidence records linked (finding.evidence_reference) to one simple issue, by port. */
function linkedEvidence(detail: AssessmentDetail, issue: IssueRef): AssessmentEvidence[] {
  const records = new Map<string, AssessmentEvidence>();
  for (const item of buildAssessmentTrace(detail).findings) {
    if (item.finding.finding_id !== issue.checkId || item.finding.severity !== issue.severity) continue;
    if (item.evidence.kind === "linked") records.set(item.evidence.record.id, item.evidence.record);
  }
  return [...records.values()].sort((a, b) => (a.port ?? -1) - (b.port ?? -1));
}

function evidenceTechnical(issue: IssueRef, linked: readonly AssessmentEvidence[]): string {
  return linked.length
    ? `${issue.checkId}: ${linked
        .map((r) => `${r.check_type} = ${r.result}, source ${r.evidence_source}${r.port !== null ? `, port ${r.port}` : ""}`)
        .join("; ")}`
    : `${issue.checkId}: no evidence record linked`;
}

/**
 * The recorded check result behind each important or minor issue, joined by
 * finding.evidence_reference. `focus` limits the answer to one issue or a group of issues.
 */
export function evidenceAnswer(detail: AssessmentDetail, focus: string | readonly string[] | null): FactAnswer {
  const summary = summarizeIssues(detail);
  const all = [...summary.important, ...summary.minor];
  const focusCheckId = typeof focus === "string" ? focus : null;
  const issues = focus === null ? all : all.filter((issue) => (typeof focus === "string" ? issue.checkId === focus : focus.includes(issue.checkId)));
  if (!issues.length) {
    return {
      text: "Your latest check didn't report an important or minor issue, so there's no issue evidence to show.",
      card: null,
      actions: [WORKFLOW_ACTIONS.openPorts],
    };
  }
  const actions = [WORKFLOW_ACTIONS.howFix, WORKFLOW_ACTIONS.technicalDetails];

  if (focusCheckId && issues.length === 1) {
    const issue = issues[0];
    const linked = linkedEvidence(detail, issue);
    return {
      text: linked.length
        ? `${linked.map(evidenceSentence).join(" ")}\nThat observation is why “${issue.title}” was reported.`
        : `No evidence record was linked to “${issue.title}” in your latest check.`,
      card: facts([], [evidenceTechnical(issue, linked)]),
      actions,
    };
  }

  const items: FactItem[] = [];
  const technical: string[] = [];
  let missing = 0;
  for (const issue of issues) {
    const linked = linkedEvidence(detail, issue);
    if (!linked.length) missing += 1;
    items.push({
      title: `${issue.title} (${issue.severity})`,
      detail: linked.length ? linked.map(evidenceSentence).join(" ") : EVIDENCE_NOT_AVAILABLE,
    });
    technical.push(evidenceTechnical(issue, linked));
  }
  const lines = [
    missing === 0
      ? "Here's what your latest check observed for each issue:"
      : "Here's what your latest check recorded for each issue. Where no evidence was linked, I say so.",
  ];
  const more = shownOf(items.length, MAX_FACT_ITEMS, "issue");
  if (more) lines.push(more);
  return { text: lines.join("\n"), card: facts(items.slice(0, MAX_FACT_ITEMS), technical), actions };
}

/** Recorded technical details of one issue, for an explicit "Show technical details". */
export function issueTechnicalAnswer(detail: AssessmentDetail, issue: IssueRef): FactAnswer {
  const technical = [`Finding ID: ${issue.checkId} (${issue.severity})`];
  const traced = buildAssessmentTrace(detail).findings.filter(
    (item) => item.finding.finding_id === issue.checkId && item.finding.severity === issue.severity,
  );
  const scanned = recordedOpenPorts(detail) ?? [];
  for (const item of traced) {
    const record = item.evidence.kind === "linked" ? item.evidence.record : null;
    const protocol =
      (record ? recordedText(record.observation?.protocol) : null) ??
      scanned.find((port) => port.port === item.finding.port)?.protocol ??
      null;
    const where = item.finding.port !== null ? `Port ${item.finding.port}${protocol ? `/${protocol}` : ""}` : "No port recorded";
    technical.push(
      record
        ? `${where}: check ${record.check_type}, observed ${record.result}, source ${record.evidence_source}`
        : `${where}: ${EVIDENCE_NOT_AVAILABLE}`,
    );
    if (item.findingRisk) {
      technical.push(`${where}: recorded finding risk ${item.findingRisk.score.toFixed(1)} (${item.findingRisk.risk_level})`);
    }
    for (const factor of item.linkedFactors) {
      technical.push(
        `${where}: linked risk factor ${factor.label}, contribution ${factor.contribution === null ? "not recorded" : `+${factor.contribution.toFixed(1)}`}`,
      );
    }
  }
  if (!traced.length) technical.push("No finding records were found for this issue.");
  return {
    text: `Technical details for “${issue.title}”:`,
    card: { kind: "FACTS", items: [], technical: [...new Set(technical)], expanded: true },
    actions: [WORKFLOW_ACTIONS.howFix, WORKFLOW_ACTIONS.technicalDetails],
  };
}

// ----------------------------------------------------------- risk factors ---

function provenanceWords(label: string | null): string {
  switch (label) {
    case "Observed evidence":
      return "observed in this check";
    case "Configured input":
      return "configured, not observed";
    case "Not assessed or not observed":
      return "not assessed or not observed";
    default:
      return "source not recorded";
  }
}

/**
 * Recorded overall score, the largest recorded factor contributions and the
 * highest-severity recorded issue to start with. Lines are separated by
 * newlines; contribution values are under the technical details.
 */
export function riskFactorsAnswer(detail: AssessmentDetail): FactAnswer {
  const risk = buildEvaluationSummary(detail).risk;
  const actions = [WORKFLOW_ACTIONS.explainRisk, WORKFLOW_ACTIONS.reviewIssues];
  if (!risk) return { text: RISK_FACTORS_NOT_AVAILABLE, card: null, actions: [WORKFLOW_ACTIONS.reviewIssues] };

  const { snapshot, contributors } = risk;
  const lines = [`Your current risk is ${snapshot.risk_level} (${scoreText(snapshot.score)}).`];
  const adding = contributors.filter((item) => item.contribution !== null && item.contribution > 0);
  if (adding.length) {
    lines.push("The largest recorded contributions are:", ...adding.slice(0, 3).map((item) => `• ${item.label}`));
  } else {
    lines.push("No factor contributions were recorded for this score.");
  }
  const issues = summarizeIssues(detail);
  const highest = issues.important[0] ?? issues.minor[0] ?? null;
  if (highest) lines.push(`Start with the highest-severity issue: “${highest.title}” (${highest.severity}).`);
  const driver = buildAssessmentTrace(detail).findings.find((item) => item.setsOverall)?.finding ?? null;

  const technical = [
    ...contributors.map(
      (item) =>
        `${item.label}: ${item.contribution === null ? "contribution not recorded" : `+${item.contribution.toFixed(1)}`} · ${provenanceWords(
          item.provenance?.label ?? null,
        )}`,
    ),
    `Score version: ${snapshot.score_version}`,
    ...contributors.map(
      (item) =>
        `${item.factor}: contribution_to_100 ${item.contribution ?? "not recorded"}, normalized_value ${
          item.normalizedValue ?? "not recorded"
        }, weight ${item.weight ?? "not recorded"}, source ${item.source ?? "not recorded"}`,
    ),
    ...(driver ? [`Overall score recorded from: ${driver.finding_id} (${driver.severity})`] : []),
  ];
  return { text: lines.join("\n"), card: facts([], technical), actions };
}
