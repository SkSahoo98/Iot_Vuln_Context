/**
 * Guided remediation: the recorded fix of an issue presented as where to fix
 * it, numbered steps, what the change may affect and how the next check will
 * show it. This is a presentation layer only. The backend remediation
 * (scanner/core/catalog.py) stays authoritative: every guide names the exact
 * recorded fix it was written from, and when the recorded fix differs, or a
 * check has no guide, only the recorded fix is shown with an explanation of
 * why exact steps can't be given. Configuration values appear only where the
 * recorded fix names them; secrets are always placeholders.
 * Nothing here detects issues, scores risk, starts a check or calls a model.
 */
import type { AssessmentDetail } from "../../api/types";
import { compareAssessments } from "../assessmentComparison";
import { summarizeIssues } from "../securityHome";
import type { AssistantIssue } from "./context";
import { evidenceAnswer, recordedOpenPorts, serviceLabel } from "./facts";
import { FIX_SECTION_PHRASES, type FixSection } from "./intents";

export type GuidedExample = {
  /** Line to look for, when the recorded fix implies it. */
  current?: string;
  /** Line to set; placeholders in <ANGLE_BRACKETS>. */
  change: string;
  note?: string;
};

export type GuidedStep = {
  title: string;
  detail: string;
  example?: GuidedExample;
  warning?: string;
};

export type GuidedRemediation = {
  checkId: string;
  title: string;
  severity: string;
  /** STEPS: a guide written for this recorded fix. LIMITED: only the recorded fix can be shown. */
  mode: "STEPS" | "LIMITED";
  whatIsWrong: string;
  whereToFix: string;
  /** Why the exact file or screen can't be named. */
  locationNote: string;
  preparation: string | null;
  steps: GuidedStep[];
  /** The recorded fix, verbatim; shown as "What to change" when LIMITED. */
  recordedFix: string | null;
  impact: string | null;
  verification: string;
  /** Recorded identifiers and raw values, shown only when expanded. */
  technical: string[];
};

/** What the recorded data says about where the issue was found. */
export type GuidePlace = {
  target: string | null;
  /** Service names the scan recorded on the issue's ports, e.g. "mosquitto version 2.1.2". */
  software: string[];
};

type Guidance = {
  /** The backend remediation this guide was written from, verbatim. */
  basedOn: string;
  where: (place: GuidePlace) => string;
  locationNote: string;
  preparation?: string;
  /** Empty: the recorded fix is too general for safe steps. */
  steps: GuidedStep[];
  impact: string;
  verification: string;
};

export const OUTCOME_NOTE =
  "This change addresses the recorded issue. A new security check is needed to confirm it's no longer observed.";
export const NO_EXACT_STEPS =
  "The assessment does not contain enough information about your system configuration to safely identify the exact file or application screen.";
export const LIMITED_NEXT_STEP =
  "Open the configuration for the service responsible for this issue, or show the technical details to your administrator.";
export const NO_RECORDED_FIX = "No recorded fix is available for this issue.";
const DEFAULT_VERIFICATION = "The next security check will show whether this issue is still observed.";

const scanned = (place: GuidePlace) => (place.target ? `the device your check scanned, ${place.target}` : "the device your check scanned");
const identified = (place: GuidePlace) =>
  place.software.length ? ` Your check identified the software there as “${place.software.join("”, “")}”.` : "";

const MQTT_WHERE = (place: GuidePlace) =>
  `On the computer that runs your MQTT broker — ${scanned(place)}.${identified(place)}`;
const DEVICE_WHERE = (what: string) => (place: GuidePlace) =>
  `On ${scanned(place)}, in the settings that control ${what}.${identified(place)}`;
const WEB_WHERE = (place: GuidePlace) =>
  `In the settings of the web server or web interface on ${scanned(place)}.${identified(place)}`;
const TLS_WHERE = (place: GuidePlace) =>
  `In the settings of the encrypted (TLS) service on ${scanned(place)}.${identified(place)}`;

const BROKER_LOCATION =
  "I can tell you what needs to change, but I can't safely identify the exact configuration file from the information available — its location depends on how the broker was installed.";
const DEVICE_LOCATION =
  "I don't know what kind of device or operating system this is, so I can't safely name the exact setting or screen.";
const WEB_LOCATION =
  "I don't know which web server software this is, so I can't safely name the exact setting or file.";
const TLS_LOCATION =
  "I don't know which software provides this service, so I can't safely name the exact setting or file.";

const OPEN_BROKER_CONFIG: GuidedStep = {
  title: "Open the broker's configuration",
  detail: "On the computer that runs the broker, open the configuration file the broker reads when it starts. Keep a copy of it before you change anything.",
};
const RESTART_BROKER: GuidedStep = {
  title: "Restart the broker",
  detail: "Restart the MQTT broker so it loads the new settings.",
};
const RESTART_SERVICE: GuidedStep = {
  title: "Restart the service",
  detail: "Restart the service, if it needs a restart to load the new settings.",
};
/** Added after every guide's own steps. */
export const RUN_CHECK_STEP: GuidedStep = {
  title: "Run another security check",
  detail: "Choose “Check whether it's fixed”. A new check of your authorized target starts only when you confirm it.",
};

/** One guide per catalog check ID (scanner/core/catalog.py, IoT-CHECKS-v1). */
const GUIDANCE: Record<string, Guidance> = {
  "IOT-MQTT-01": {
    basedOn: "Set allow_anonymous false, configure a password_file, and enforce topic ACLs for each client.",
    where: MQTT_WHERE,
    locationNote: BROKER_LOCATION,
    preparation: "Make sure you can sign in to that computer and edit the broker's settings, and that you can update the MQTT settings of the devices that use it.",
    steps: [
      OPEN_BROKER_CONFIG,
      {
        title: "Turn off anonymous access",
        detail: "Anonymous access means a device can connect without proving who it is. Set the broker to refuse those connections.",
        example: { current: "allow_anonymous true", change: "allow_anonymous false", note: "If the line isn't in the file, add it." },
      },
      {
        title: "Add a password file",
        detail: "Point the broker to a file of MQTT usernames and passwords, and add a login for each device that connects. Your broker's documentation explains the tool that creates this file.",
        example: { change: "password_file <PATH_TO_PASSWORD_FILE>" },
        warning: "Never type a real password into this assistant. <MQTT_USERNAME> and <MQTT_PASSWORD> stand for values only you should see.",
      },
      {
        title: "Limit what each device can do",
        detail: "Topic ACLs (access control lists) decide which topics each login may read or publish. Give each device access only to the topics it needs.",
      },
      RESTART_BROKER,
      {
        title: "Update your devices",
        detail: "Give every device and app that connects to this broker — for example ESP32 boards and data collectors — its own <MQTT_USERNAME> and <MQTT_PASSWORD> in its MQTT settings. Then check that each one connects again.",
      },
    ],
    impact: "After this change, devices that connect without a username and password will be refused until you give them a login. Plan to update them right after restarting the broker.",
    verification: "In the next security check, the connection attempt without a username or password should be refused. If it's still accepted, this issue will be reported again.",
  },
  "IOT-MQTT-02": {
    basedOn: "Enable an MQTT TLS listener (port 8883) with a valid certificate and move clients to it.",
    where: MQTT_WHERE,
    locationNote:
      "I can tell you what needs to change, but I can't safely give the exact configuration lines or certificate locations from the information available — they depend on how the broker was installed.",
    preparation: "You'll need a valid certificate for the broker. A certificate proves the broker's identity, so devices can trust the encrypted connection.",
    steps: [
      {
        title: "Get a certificate for the broker",
        detail: "Use a valid certificate that the devices connecting to the broker will trust.",
      },
      {
        title: "Add an encrypted listener on port 8883",
        detail: "A listener is a port the broker accepts connections on. In the broker's configuration, add a TLS (encrypted) listener on port 8883 that uses the certificate.",
      },
      RESTART_BROKER,
      {
        title: "Move your devices to the encrypted port",
        detail: "Change each device's MQTT settings to connect with TLS on port 8883. Then check that each one connects again.",
      },
    ],
    impact: "Devices you move to port 8883 must trust the broker's certificate, or they won't be able to connect. Devices that still use the unencrypted connection aren't protected until you move them.",
    verification: "The next security check should find an encrypted MQTT connection available on port 8883. If it doesn't, this issue will be reported again.",
  },
  "IOT-MQTT-03": {
    basedOn: "Restrict $SYS topic access to administrative clients via ACLs.",
    where: MQTT_WHERE,
    locationNote: BROKER_LOCATION,
    steps: [
      OPEN_BROKER_CONFIG,
      {
        title: "Limit the status topics",
        detail: "The broker's $SYS topics report its status and version. Use topic ACLs (access control lists) so only administrative logins can read them.",
      },
      RESTART_BROKER,
    ],
    impact: "Tools that read the broker's status topics will need an administrative login.",
    verification: "The next security check should no longer be able to read the broker's version.",
  },
  "NET-01": {
    basedOn: "Confirm the service is required; close or firewall it otherwise.",
    where: DEVICE_WHERE("which network services run"),
    locationNote: DEVICE_LOCATION,
    steps: [
      { title: "Check whether the service is needed", detail: "Find out what uses this service. The technical details show the port your check found open." },
      { title: "Close it or limit access", detail: "If it isn't needed, turn the service off. If it is, use a firewall to allow only the computers that need it." },
    ],
    impact: "Anything that uses this service will lose access if you close it or block it.",
    verification: "The next security check will show whether this service is still reachable.",
  },
  "NET-02": {
    basedOn: "Disable services that are not required for the device's function.",
    where: DEVICE_WHERE("which network services run"),
    locationNote: DEVICE_LOCATION,
    steps: [],
    impact: "Anything that uses a service you turn off will lose access to it.",
    verification: "The next security check should find fewer open services than the configured limit.",
  },
  "NET-03": {
    basedOn: "Disable Telnet and use SSH with key-based authentication if remote administration is required.",
    where: DEVICE_WHERE("remote access"),
    locationNote: DEVICE_LOCATION,
    steps: [
      { title: "Find out who uses Telnet", detail: "Check whether anyone still manages this device with Telnet." },
      { title: "Turn off Telnet", detail: "Disable the Telnet service on the device." },
      {
        title: "Use SSH instead, if you need remote access",
        detail: "SSH is an encrypted remote login. Set it up with key-based authentication, which uses a key file instead of a password.",
      },
    ],
    impact: "Anyone or anything that manages this device over Telnet will lose that access until it switches to SSH.",
    verification: "The next security check should no longer find Telnet reachable on the device.",
  },
  "NET-04": {
    basedOn: "Disable FTP or replace it with SFTP/FTPS restricted to authorized hosts.",
    where: DEVICE_WHERE("file transfer"),
    locationNote: DEVICE_LOCATION,
    steps: [
      { title: "Find out who uses FTP", detail: "Check whether anything still transfers files to or from this device with FTP." },
      {
        title: "Turn off FTP, or replace it",
        detail: "If nothing needs it, disable the FTP service. If file transfer is needed, use SFTP or FTPS instead — both encrypt the transfer.",
      },
      { title: "Allow only trusted computers", detail: "Restrict the replacement service to the computers that are authorized to use it." },
    ],
    impact: "Anything that transfers files with FTP will stop working until it uses the replacement.",
    verification: "The next security check should no longer find FTP reachable on the device.",
  },
  "NET-06": {
    basedOn: "Verify the administrative service is required and restrict it to management hosts.",
    where: DEVICE_WHERE("which services can be reached from the network"),
    locationNote: DEVICE_LOCATION,
    steps: [
      { title: "Check whether the service is needed", detail: "Find out what uses this administrative service. The technical details show the port your check found." },
      {
        title: "Limit who can reach it",
        detail: "Allow only the computers you use to manage the device (management hosts), for example with a firewall rule. If nothing needs the service, turn it off.",
      },
    ],
    impact: "Computers that aren't on your list of management hosts will no longer be able to reach this service.",
    verification: "The next security check will report this again if the service is still reachable from the computer that runs the checks.",
  },
  "WEB-01": {
    basedOn: "Serve the interface over HTTPS and redirect plaintext HTTP.",
    where: WEB_WHERE,
    locationNote: WEB_LOCATION,
    steps: [
      { title: "Turn on HTTPS", detail: "HTTPS is the encrypted version of HTTP. Enable it for the web interface." },
      { title: "Redirect plain HTTP to HTTPS", detail: "Set requests to the plain http:// address to be sent on to the HTTPS address." },
      RESTART_SERVICE,
    ],
    impact: "Bookmarks and apps that use the plain http:// address will be sent to HTTPS. Any that can't use HTTPS will need updating.",
    verification: "The next security check should find an HTTPS service on the device.",
  },
  "WEB-02": {
    basedOn: "Add the missing security headers in the web server configuration.",
    where: WEB_WHERE,
    locationNote: WEB_LOCATION,
    steps: [],
    impact: "Security headers change how browsers treat the page. Test the web interface after adding them.",
    verification: "The next security check should no longer report missing security headers.",
  },
  "WEB-03": {
    basedOn: "Suppress version details in the Server / X-Powered-By headers.",
    where: WEB_WHERE,
    locationNote: WEB_LOCATION,
    steps: [
      { title: "Open the web server's settings", detail: "Find the settings that control the response headers the server sends." },
      { title: "Hide version details", detail: "Turn off the software and version details the server adds to its Server and X-Powered-By headers." },
      RESTART_SERVICE,
    ],
    impact: "This only changes what the server reveals about itself; it normally doesn't change how the web interface works.",
    verification: "The next security check should no longer find software details in the response headers.",
  },
  "TLS-01": {
    basedOn: "No action required; certificate and protocol checks are reported separately.",
    where: TLS_WHERE,
    locationNote: TLS_LOCATION,
    steps: [],
    impact: "No change is needed for this observation.",
    verification: DEFAULT_VERIFICATION,
  },
  "TLS-02": {
    basedOn: "Renew the certificate and deploy it to the service.",
    where: TLS_WHERE,
    locationNote: TLS_LOCATION,
    steps: [
      { title: "Renew the certificate", detail: "Get a new certificate from whoever issued the expired one." },
      { title: "Install it on the service", detail: "Replace the expired certificate in the service's settings." },
      RESTART_SERVICE,
    ],
    impact: "Clients will see the new certificate. Any that were set to trust only the old certificate will need the new one.",
    verification: "The next security check should find a certificate that hasn't expired.",
  },
  "TLS-03": {
    basedOn: "Disable TLS 1.1 and older; allow TLS 1.2 and TLS 1.3 only.",
    where: TLS_WHERE,
    locationNote: TLS_LOCATION,
    steps: [
      { title: "Open the service's TLS settings", detail: "Find the setting that lists which TLS versions the service accepts." },
      { title: "Allow only TLS 1.2 and TLS 1.3", detail: "Turn off TLS 1.1 and older versions." },
      RESTART_SERVICE,
    ],
    impact: "Old devices or apps that only support TLS 1.1 or older won't be able to connect.",
    verification: "The next security check should negotiate TLS 1.2 or newer.",
  },
  "TLS-04": {
    basedOn: "Use a certificate issued by a CA trusted by the clients and matching the service address.",
    where: TLS_WHERE,
    locationNote: TLS_LOCATION,
    steps: [
      {
        title: "Get a trusted certificate",
        detail: "Use a certificate from a certificate authority (CA) — an organisation your clients already trust — issued for the address clients use to reach the service.",
      },
      { title: "Install it on the service", detail: "Replace the current certificate in the service's settings." },
      RESTART_SERVICE,
    ],
    impact: "Clients that were set to accept the old certificate may need updating.",
    verification: "The next security check should be able to verify the certificate.",
  },
};

const sameText = (a: string, b: string) => a.replace(/\s+/g, " ").trim() === b.replace(/\s+/g, " ").trim();

/** Check IDs with a guide; the rest are shown as LIMITED. */
export const GUIDED_CHECK_IDS: readonly string[] = Object.keys(GUIDANCE);

/** Target and recorded software for the issue's ports, from the latest check. */
export function guidePlace(issue: Pick<AssistantIssue, "ports">, target: string | null, detail: AssessmentDetail | null): GuidePlace {
  const ports = detail ? recordedOpenPorts(detail) ?? [] : [];
  const software = [
    ...new Set(
      ports
        .filter((port) => issue.ports.includes(port.port))
        .map(serviceLabel)
        .filter((label): label is string => Boolean(label)),
    ),
  ];
  return { target, software };
}

function technicalLines(issue: AssistantIssue, guide: Guidance | null, mode: GuidedRemediation["mode"], detail: AssessmentDetail | null): string[] {
  const lines = [
    `Check ID: ${issue.checkId} (${issue.severity})`,
    `Recorded fix: ${issue.remediation ?? "not recorded"}`,
    `Ports: ${issue.ports.length ? issue.ports.join(", ") : "not recorded"}`,
  ];
  const ports = detail ? recordedOpenPorts(detail) ?? [] : [];
  for (const port of ports.filter((item) => issue.ports.includes(item.port))) {
    const label = serviceLabel(port);
    if (label) lines.push(`Service on port ${port.port}: ${label}`);
  }
  if (detail) {
    const card = evidenceAnswer(detail, issue.checkId).card;
    if (card?.kind === "FACTS") lines.push(...card.technical.map((line) => `Evidence: ${line}`));
  }
  lines.push(
    mode === "STEPS"
      ? "Steps: written for this recorded fix"
      : guide
        ? "Steps: not shown — the recorded fix differs from the one the guide was written for, or is too general"
        : "Steps: no guide exists for this check",
  );
  return lines;
}

/** The guided fix of one issue; LIMITED whenever steps can't be tied to the recorded fix. */
export function buildGuidedRemediation(
  issue: AssistantIssue,
  place: GuidePlace,
  detail: AssessmentDetail | null = null,
): GuidedRemediation {
  const guide = GUIDANCE[issue.checkId] ?? null;
  const matches = Boolean(guide && issue.remediation !== null && sameText(issue.remediation, guide.basedOn));
  const mode: GuidedRemediation["mode"] = matches && guide!.steps.length ? "STEPS" : "LIMITED";
  const fallbackWhere = `On ${scanned(place)}, in the configuration of the service responsible for this issue.${identified(place)}`;
  return {
    checkId: issue.checkId,
    title: issue.title,
    severity: issue.severity,
    mode,
    whatIsWrong: issue.meaning ?? "Your latest check recorded this issue; the technical details show what was observed.",
    whereToFix: guide ? guide.where(place) : fallbackWhere,
    locationNote: mode === "STEPS" ? guide!.locationNote : NO_EXACT_STEPS,
    preparation: mode === "STEPS" ? guide!.preparation ?? null : null,
    steps: mode === "STEPS" ? [...guide!.steps, RUN_CHECK_STEP] : [],
    recordedFix: issue.remediation,
    impact: matches ? guide!.impact : null,
    verification: matches ? guide!.verification : DEFAULT_VERIFICATION,
    technical: technicalLines(issue, guide, mode, detail),
  };
}

// ------------------------------------------------------------ guide sections ---

/** Which part of the guide a fix question asks for. */
export type FixAspect = "STEPS" | FixSection;

/** The part of the guide a classified FIX request asks for (by its matched phrase). */
export function fixAspect(matchedPhrase: string | null): FixAspect {
  for (const [aspect, phrases] of Object.entries(FIX_SECTION_PHRASES) as [FixSection, readonly string[]][]) {
    if (matchedPhrase && phrases.includes(matchedPhrase)) return aspect;
  }
  return "STEPS";
}

/** A request standing for the same aspect about the issue now in focus. */
export const ASPECT_REQUEST: Record<FixAspect, string> = {
  STEPS: "how do i fix it",
  WHERE: "where do i fix it",
  IMPACT: "what might this affect",
  VERIFY_HOW: "how do i know its fixed",
};

/** One section of the guide as a short reply text. */
export function guideSectionText(guide: GuidedRemediation, aspect: Exclude<FixAspect, "STEPS">): string {
  switch (aspect) {
    case "WHERE":
      return `Where to fix “${guide.title}”:\n${guide.whereToFix}\n${guide.locationNote}`;
    case "IMPACT":
      return guide.impact
        ? `What changing this might affect:\n${guide.impact}\n${OUTCOME_NOTE}`
        : `I can't say what this change might affect from the information available.\n${OUTCOME_NOTE}`;
    case "VERIFY_HOW":
      return `How you'll know “${guide.title}” is fixed:\n${guide.verification}\nOnly a new security check can confirm it, and nothing runs until you choose to.`;
  }
}

// ------------------------------------------------------------- verification ---

export type IssueVerificationStatus = "NOT_OBSERVED" | "STILL_PRESENT" | "NOT_RECHECKED" | "NOT_COMPARABLE";

export type IssueVerification = {
  status: IssueVerificationStatus;
  checkId: string;
  title: string;
  previousSeverity: string;
  /** Important issues (CRITICAL/HIGH/MEDIUM) in each check. */
  beforeImportant: number;
  afterImportant: number;
  /** Important or minor issues of the previous check not observed in the new one. */
  noLongerObserved: number;
};

/**
 * What the existing comparison engine says about one issue between the
 * previous check and the verification check. Fixed only when the comparison
 * is valid, the issue was checked again and it was not observed; null when
 * the previous check didn't report the issue.
 */
export function verifyIssue(before: AssessmentDetail, after: AssessmentDetail, checkId: string): IssueVerification | null {
  const previous = summarizeIssues(before);
  const issue = [...previous.important, ...previous.minor].find((item) => item.checkId === checkId);
  if (!issue) return null;
  const result = compareAssessments(before, after);
  const base = {
    checkId,
    title: issue.title,
    previousSeverity: issue.severity,
    beforeImportant: previous.important.length,
    afterImportant: summarizeIssues(after).important.length,
    noLongerObserved: 0,
  };
  if (!result.comparable || !result.findings) return { ...base, status: "NOT_COMPARABLE" };
  const { remaining, added, resolved, unconfirmed } = result.findings;
  const resolvedChecks = new Set(
    resolved.filter((item) => item.before.severity !== "INFO").map((item) => `${item.before.finding_id}|${item.before.severity}`),
  );
  const counted = { ...base, noLongerObserved: resolvedChecks.size };
  const isIssue = (findingId: string) => findingId === checkId;
  if (remaining.some((item) => isIssue(item.after.finding_id)) || added.some((item) => isIssue(item.after.finding_id))) {
    return { ...counted, status: "STILL_PRESENT" };
  }
  if (unconfirmed.some((item) => isIssue(item.before.finding_id))) return { ...counted, status: "NOT_RECHECKED" };
  if (resolved.some((item) => isIssue(item.before.finding_id))) return { ...counted, status: "NOT_OBSERVED" };
  return null;
}

export const VERIFICATION_HEADLINE: Record<IssueVerificationStatus, string> = {
  NOT_OBSERVED: "This issue appears to be fixed.",
  STILL_PRESENT: "This issue is still present.",
  NOT_RECHECKED: "The new check didn't check this issue again, so I can't tell whether it's fixed.",
  NOT_COMPARABLE: "These two checks can't be compared directly, so I can't tell whether this issue is fixed.",
};

/** What to look at again when the issue is still observed. */
export const STILL_PRESENT_CHECKS: readonly string[] = [
  "the required setting was changed",
  "affected devices were updated",
  "the service was restarted, if it needed a restart",
];
