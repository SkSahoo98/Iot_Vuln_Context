/**
 * Assistant intents and a deterministic first-pass classifier. Matching is by
 * listed phrases on word boundaries only; anything else is UNKNOWN.
 */

/**
 * FIXED ("I fixed it") and COMPARE ("What changed?") only move the workflow
 * forward; neither starts a check. TECHNICAL is a factual question answered
 * from the latest complete check's records, never by a model.
 */
export type AssistantIntent =
  | "CHECK"
  | "EXPLAIN"
  | "FIX"
  | "VERIFY"
  | "FIXED"
  | "COMPARE"
  | "SUMMARY"
  | "TECHNICAL"
  | "UNKNOWN";

export type SupportedIntent = Exclude<AssistantIntent, "UNKNOWN">;

export type IntentConfidence = "HIGH" | "MEDIUM" | "LOW";

export type ExplainSubject = "RISK" | "ISSUES";

export type TechnicalTopic = "PORTS" | "SERVICES" | "DEVICES" | "FINDINGS" | "EVIDENCE" | "RISK_FACTORS";

/** What an EXPLAIN or TECHNICAL request is about; null for every other intent. */
export type IntentSubject = ExplainSubject | TechnicalTopic | null;

export type AssistantIntentResult = {
  intent: AssistantIntent;
  confidence: IntentConfidence;
  /** Normalized phrase that decided the intent; null when none did. */
  matchedPhrase: string | null;
  subject: IntentSubject;
  requiresAssessment: boolean;
  requiresComparison: boolean;
  reason: string;
};

export const INTENT_REQUIREMENTS: Record<
  AssistantIntent,
  { requiresAssessment: boolean; requiresComparison: boolean }
> = {
  CHECK: { requiresAssessment: false, requiresComparison: false },
  EXPLAIN: { requiresAssessment: true, requiresComparison: false },
  FIX: { requiresAssessment: true, requiresComparison: false },
  VERIFY: { requiresAssessment: true, requiresComparison: true },
  FIXED: { requiresAssessment: true, requiresComparison: true },
  COMPARE: { requiresAssessment: true, requiresComparison: true },
  SUMMARY: { requiresAssessment: true, requiresComparison: false },
  TECHNICAL: { requiresAssessment: true, requiresComparison: false },
  UNKNOWN: { requiresAssessment: false, requiresComparison: false },
};

/** SUMMARY phrases asking for the current status, answered from recorded values only. */
export const STATUS_PHRASES: readonly string[] = [
  "is my iot network safe",
  "is my network safe",
  "is my iot network secure",
  "is my network secure",
  "am i safe",
  "how secure is my network",
  "how secure is my iot network",
  "how safe is my network",
  "whats my security status",
  "what is my security status",
  "what is my risk",
  "whats my risk",
  "risk score",
  "what is my score",
  "whats my score",
  "am i secure",
  "how safe am i",
  "is my network at risk",
  "is my iot network at risk",
  "how risky is my network",
];

const SUBJECTED_INTENTS: readonly AssistantIntent[] = ["EXPLAIN", "TECHNICAL"];

export type FixSection = "WHERE" | "IMPACT" | "VERIFY_HOW";

/** FIX phrases that ask for one part of the guided fix: where, what it affects, how to tell it worked. */
export const FIX_SECTION_PHRASES: Record<FixSection, readonly string[]> = {
  WHERE: ["where do i fix", "where can i fix", "where do i change", "where is this setting", "where is that setting", "where is the setting"],
  IMPACT: [
    "what happens if i change", "what might this affect", "what will this affect", "what does this affect",
    "will this break", "will it break", "will that break",
  ],
  VERIFY_HOW: [
    "how do i know its fixed", "how do i know it is fixed", "how do i know if its fixed", "how will i know its fixed",
    "how will i know if its fixed", "how do i know it worked", "how will i know it worked",
  ],
};

/** FINDINGS phrases asking how many findings were recorded ("Are there only two vulnerabilities?"). */
export const FINDING_COUNT_PHRASES: readonly string[] = [
  "how many issues", "how many findings", "how many vulnerabilities", "how many problems",
  "how many security issues", "how many security problems", "how many issues were found",
  "how many findings were found", "total findings", "any other findings", "are there other findings",
  "are there more findings", "is that all you found", "is that everything you found",
  "only one", "only 1", "only two", "only 2", "only three", "only 3", "only four", "only 4", "only five", "only 5",
];

/** FINDINGS phrases asking for the complete list of recorded findings. */
export const ALL_FINDINGS_PHRASES: readonly string[] = [
  "show me everything", "show everything", "view all findings", "show all findings", "show me all findings",
  "all findings", "all the findings", "all of the findings", "every finding", "full list of findings",
  "complete list of findings", "everything you found", "everything that was found",
];

export type IntentPhrase = {
  /** Written in normalized form (see normalizeRequest). */
  phrase: string;
  intent: SupportedIntent;
  subject?: Exclude<IntentSubject, null>;
};

export const INTENT_PHRASES: readonly IntentPhrase[] = [
  { phrase: "check my network", intent: "CHECK" },
  { phrase: "check my iot network", intent: "CHECK" },
  { phrase: "scan my network", intent: "CHECK" },
  { phrase: "scan my iot network", intent: "CHECK" },
  { phrase: "run a security check", intent: "CHECK" },
  { phrase: "start a security check", intent: "CHECK" },
  { phrase: "check security", intent: "CHECK" },
  { phrase: "check my security", intent: "CHECK" },
  { phrase: "check again", intent: "CHECK" },
  { phrase: "check it again", intent: "CHECK" },
  { phrase: "run that again", intent: "CHECK" },
  { phrase: "run it again", intent: "CHECK" },
  { phrase: "run again", intent: "CHECK" },
  { phrase: "run the check again", intent: "CHECK" },
  { phrase: "run the scan again", intent: "CHECK" },
  { phrase: "scan again", intent: "CHECK" },
  { phrase: "run another check", intent: "CHECK" },
  { phrase: "rerun", intent: "CHECK" },
  { phrase: "rescan", intent: "CHECK" },

  { phrase: "explain my risk", intent: "EXPLAIN", subject: "RISK" },
  { phrase: "explain the risk", intent: "EXPLAIN", subject: "RISK" },
  { phrase: "why is this risky", intent: "EXPLAIN", subject: "ISSUES" },
  { phrase: "what is wrong", intent: "EXPLAIN", subject: "ISSUES" },
  { phrase: "whats wrong", intent: "EXPLAIN", subject: "ISSUES" },
  { phrase: "explain this issue", intent: "EXPLAIN", subject: "ISSUES" },
  { phrase: "why is it risky", intent: "EXPLAIN", subject: "ISSUES" },
  { phrase: "why does this matter", intent: "EXPLAIN", subject: "ISSUES" },
  { phrase: "why does it matter", intent: "EXPLAIN", subject: "ISSUES" },
  { phrase: "explain why this matters", intent: "EXPLAIN", subject: "ISSUES" },

  { phrase: "how do i fix", intent: "FIX" },
  { phrase: "how do i fix this", intent: "FIX" },
  { phrase: "how can i fix", intent: "FIX" },
  { phrase: "how to fix", intent: "FIX" },
  { phrase: "help me fix", intent: "FIX" },
  { phrase: "help me fix this", intent: "FIX" },
  { phrase: "what should i do", intent: "FIX" },
  { phrase: "how do i remediate", intent: "FIX" },
  { phrase: "fix it", intent: "FIX" },
  { phrase: "fix this", intent: "FIX" },
  { phrase: "fix that", intent: "FIX" },
  { phrase: "can i fix", intent: "FIX" },
  { phrase: "how should i fix", intent: "FIX" },
  { phrase: "how do i solve", intent: "FIX" },
  { phrase: "how can i solve", intent: "FIX" },
  { phrase: "how to solve", intent: "FIX" },
  { phrase: "how do i secure", intent: "FIX" },
  { phrase: "how can i secure", intent: "FIX" },
  { phrase: "what do i change", intent: "FIX" },
  { phrase: "what should i change", intent: "FIX" },
  { phrase: "what do i need to change", intent: "FIX" },
  ...Object.values(FIX_SECTION_PHRASES).flat().map((phrase): IntentPhrase => ({ phrase, intent: "FIX" })),

  { phrase: "did i fix it", intent: "VERIFY" },
  { phrase: "check if i fixed it", intent: "VERIFY" },
  { phrase: "verify the fix", intent: "VERIFY" },
  { phrase: "verify my fix", intent: "VERIFY" },
  { phrase: "check again after fixing", intent: "VERIFY" },
  { phrase: "did the issue go away", intent: "VERIFY" },
  { phrase: "is it fixed", intent: "VERIFY" },
  { phrase: "is this fixed", intent: "VERIFY" },
  { phrase: "is that fixed", intent: "VERIFY" },
  { phrase: "is the issue fixed", intent: "VERIFY" },
  { phrase: "is the security issue fixed", intent: "VERIFY" },
  { phrase: "verify after fixing", intent: "VERIFY" },
  { phrase: "verify it", intent: "VERIFY" },
  { phrase: "verify this", intent: "VERIFY" },
  { phrase: "verify that", intent: "VERIFY" },
  { phrase: "did the issues go away", intent: "VERIFY" },
  { phrase: "did the security issue go away", intent: "VERIFY" },
  { phrase: "did the security issues go away", intent: "VERIFY" },
  { phrase: "check whether its fixed", intent: "VERIFY" },
  { phrase: "check whether it is fixed", intent: "VERIFY" },
  { phrase: "check if its fixed", intent: "VERIFY" },
  { phrase: "check if it is fixed", intent: "VERIFY" },
  { phrase: "check whether i fixed it", intent: "VERIFY" },

  { phrase: "i fixed it", intent: "FIXED" },
  { phrase: "i fixed this", intent: "FIXED" },
  { phrase: "i fixed that", intent: "FIXED" },
  { phrase: "i fixed the issue", intent: "FIXED" },
  { phrase: "i fixed the problem", intent: "FIXED" },
  { phrase: "i have fixed it", intent: "FIXED" },
  { phrase: "ive fixed it", intent: "FIXED" },
  { phrase: "i applied the fix", intent: "FIXED" },
  { phrase: "ive completed the fix", intent: "FIXED" },
  { phrase: "i have completed the fix", intent: "FIXED" },
  { phrase: "i completed the fix", intent: "FIXED" },

  { phrase: "what changed", intent: "COMPARE" },
  { phrase: "what has changed", intent: "COMPARE" },
  { phrase: "what changed after i fixed it", intent: "COMPARE" },
  { phrase: "see what changed", intent: "COMPARE" },
  { phrase: "view before after", intent: "COMPARE" },
  { phrase: "view before and after", intent: "COMPARE" },
  { phrase: "did the security improve", intent: "COMPARE" },
  { phrase: "did my security improve", intent: "COMPARE" },
  { phrase: "did security improve", intent: "COMPARE" },

  { phrase: "give me a summary", intent: "SUMMARY" },
  { phrase: "summarize my security", intent: "SUMMARY" },
  { phrase: "summarise my security", intent: "SUMMARY" },
  { phrase: "security summary", intent: "SUMMARY" },
  { phrase: "what happened in my last check", intent: "SUMMARY" },
  { phrase: "summarize my last check", intent: "SUMMARY" },
  { phrase: "summarize results", intent: "SUMMARY" },
  { phrase: "summarize the results", intent: "SUMMARY" },
  { phrase: "summarize the new check", intent: "SUMMARY" },
  { phrase: "summarize", intent: "SUMMARY" },
  { phrase: "summarise", intent: "SUMMARY" },
  { phrase: "summary", intent: "SUMMARY" },
  { phrase: "what is the summary", intent: "SUMMARY" },
  { phrase: "whats the summary", intent: "SUMMARY" },
  { phrase: "how did the check go", intent: "SUMMARY" },
  { phrase: "how did my check go", intent: "SUMMARY" },
  { phrase: "how did my last check go", intent: "SUMMARY" },
  { phrase: "how did the scan go", intent: "SUMMARY" },
  ...STATUS_PHRASES.map((phrase): IntentPhrase => ({ phrase, intent: "SUMMARY" })),

  { phrase: "open ports", intent: "TECHNICAL", subject: "PORTS" },
  { phrase: "open port", intent: "TECHNICAL", subject: "PORTS" },
  { phrase: "ports open", intent: "TECHNICAL", subject: "PORTS" },
  { phrase: "ports are open", intent: "TECHNICAL", subject: "PORTS" },
  { phrase: "port open", intent: "TECHNICAL", subject: "PORTS" },
  { phrase: "any ports", intent: "TECHNICAL", subject: "PORTS" },
  { phrase: "any port", intent: "TECHNICAL", subject: "PORTS" },
  { phrase: "what ports", intent: "TECHNICAL", subject: "PORTS" },
  { phrase: "which ports", intent: "TECHNICAL", subject: "PORTS" },
  { phrase: "is port", intent: "TECHNICAL", subject: "PORTS" },
  { phrase: "listening ports", intent: "TECHNICAL", subject: "PORTS" },

  { phrase: "what services", intent: "TECHNICAL", subject: "SERVICES" },
  { phrase: "which services", intent: "TECHNICAL", subject: "SERVICES" },
  { phrase: "services are running", intent: "TECHNICAL", subject: "SERVICES" },
  { phrase: "services running", intent: "TECHNICAL", subject: "SERVICES" },
  { phrase: "running services", intent: "TECHNICAL", subject: "SERVICES" },
  { phrase: "exposed services", intent: "TECHNICAL", subject: "SERVICES" },
  { phrase: "services are exposed", intent: "TECHNICAL", subject: "SERVICES" },
  { phrase: "what service", intent: "TECHNICAL", subject: "SERVICES" },
  { phrase: "which service", intent: "TECHNICAL", subject: "SERVICES" },
  { phrase: "what is running", intent: "TECHNICAL", subject: "SERVICES" },
  { phrase: "whats running", intent: "TECHNICAL", subject: "SERVICES" },
  { phrase: "what runs", intent: "TECHNICAL", subject: "SERVICES" },
  { phrase: "running on port", intent: "TECHNICAL", subject: "SERVICES" },

  { phrase: "what devices", intent: "TECHNICAL", subject: "DEVICES" },
  { phrase: "which devices", intent: "TECHNICAL", subject: "DEVICES" },
  { phrase: "what device", intent: "TECHNICAL", subject: "DEVICES" },
  { phrase: "which device", intent: "TECHNICAL", subject: "DEVICES" },
  { phrase: "what did you scan", intent: "TECHNICAL", subject: "DEVICES" },
  { phrase: "what was checked", intent: "TECHNICAL", subject: "DEVICES" },
  { phrase: "how many devices were assessed", intent: "TECHNICAL", subject: "DEVICES" },
  { phrase: "how many devices", intent: "TECHNICAL", subject: "DEVICES" },
  { phrase: "how many assets were assessed", intent: "TECHNICAL", subject: "DEVICES" },
  { phrase: "how many assets", intent: "TECHNICAL", subject: "DEVICES" },
  { phrase: "what assets were assessed", intent: "TECHNICAL", subject: "DEVICES" },
  { phrase: "what assets", intent: "TECHNICAL", subject: "DEVICES" },
  { phrase: "what infrastructure was assessed", intent: "TECHNICAL", subject: "DEVICES" },
  { phrase: "what infrastructure", intent: "TECHNICAL", subject: "DEVICES" },
  { phrase: "which infrastructure", intent: "TECHNICAL", subject: "DEVICES" },

  { phrase: "what vulnerabilities", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "which vulnerabilities", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "any vulnerabilities", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "security problems", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "security issues were found", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "show me the findings", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "show the findings", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what findings", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what did you find", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what did the scan find", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what did the check find", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what did the mqtt broker find", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what did mqtt broker find", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what did the broker find", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what did broker find", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what did esp32 01 find", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what did esp32 02 find", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what did my latest security check find", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what did the latest security check find", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what did latest security check find", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what did my latest check find", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what did my check find", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what was found", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "security issues", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "security issue", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what are these security", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what is this security", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what is these security", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what does this security mean", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "these issues", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "these problems", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "these findings", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what issues", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "which issues", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what problems", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "which problems", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "any issues", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "any issue", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "any problems", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "any problem", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "issues were found", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "problems were found", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what are the issues", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "what are the problems", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "show me the issues", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "show me the problems", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "show the issues", intent: "TECHNICAL", subject: "FINDINGS" },
  { phrase: "show the problems", intent: "TECHNICAL", subject: "FINDINGS" },
  ...[...FINDING_COUNT_PHRASES, ...ALL_FINDINGS_PHRASES].map(
    (phrase): IntentPhrase => ({ phrase, intent: "TECHNICAL", subject: "FINDINGS" }),
  ),

  { phrase: "what evidence", intent: "TECHNICAL", subject: "EVIDENCE" },
  { phrase: "which evidence", intent: "TECHNICAL", subject: "EVIDENCE" },
  { phrase: "show me the evidence", intent: "TECHNICAL", subject: "EVIDENCE" },
  { phrase: "how do you know", intent: "TECHNICAL", subject: "EVIDENCE" },
  { phrase: "why did you flag", intent: "TECHNICAL", subject: "EVIDENCE" },
  { phrase: "why did you mark", intent: "TECHNICAL", subject: "EVIDENCE" },
  { phrase: "what did you observe", intent: "TECHNICAL", subject: "EVIDENCE" },
  { phrase: "what was observed", intent: "TECHNICAL", subject: "EVIDENCE" },
  { phrase: "what did the scan observe", intent: "TECHNICAL", subject: "EVIDENCE" },
  { phrase: "what did the scan actually observe", intent: "TECHNICAL", subject: "EVIDENCE" },

  { phrase: "why is my risk", intent: "TECHNICAL", subject: "RISK_FACTORS" },
  { phrase: "why is my risk high", intent: "TECHNICAL", subject: "RISK_FACTORS" },
  { phrase: "why is my risk so high", intent: "TECHNICAL", subject: "RISK_FACTORS" },
  { phrase: "why is my risk score", intent: "TECHNICAL", subject: "RISK_FACTORS" },
  { phrase: "why is the risk", intent: "TECHNICAL", subject: "RISK_FACTORS" },
  { phrase: "why is risk", intent: "TECHNICAL", subject: "RISK_FACTORS" },
  { phrase: "why is the score", intent: "TECHNICAL", subject: "RISK_FACTORS" },
  { phrase: "what makes my risk", intent: "TECHNICAL", subject: "RISK_FACTORS" },
  { phrase: "why is my score", intent: "TECHNICAL", subject: "RISK_FACTORS" },
  { phrase: "why is my score so high", intent: "TECHNICAL", subject: "RISK_FACTORS" },
  { phrase: "what contributes to my risk", intent: "TECHNICAL", subject: "RISK_FACTORS" },
  { phrase: "what affects my risk", intent: "TECHNICAL", subject: "RISK_FACTORS" },
  { phrase: "risk factors", intent: "TECHNICAL", subject: "RISK_FACTORS" },
];

/** A negation before the matched phrase makes the request unclear. */
const NEGATIONS = ["dont", "do not", "never", "stop", "cancel", "no need to"];

const LEADING_FILLER = ["please", "can you", "could you", "would you"];
const TRAILING_FILLER = ["please", "for me", "now"];

export const MAX_REQUEST_LENGTH = 300;

/** Reason of an UNKNOWN result when no listed phrase occurs at all (not negated, not ambiguous). */
export const NO_PHRASE_REASON = "No supported request phrase was found.";

/** Common misspellings and chat shorthand, replaced word by word. */
const WORD_FIXES: Record<string, string> = {
  securty: "security",
  secuirty: "security",
  secutiry: "security",
  securiy: "security",
  securtiy: "security",
  isues: "issues",
  issus: "issues",
  issuse: "issues",
  isue: "issue",
  problms: "problems",
  probelms: "problems",
  vulnerabilites: "vulnerabilities",
  vulnerabilties: "vulnerabilities",
  netwrok: "network",
  netowrk: "network",
  nework: "network",
  rsik: "risk",
  wat: "what",
  wht: "what",
  whta: "what",
  waht: "what",
  wats: "whats",
  teh: "the",
  u: "you",
  ur: "your",
  pls: "please",
  plz: "please",
};

/** Lowercase, apostrophes dropped, punctuation to spaces, single-spaced, common typos fixed. */
export function normalizeRequest(text: string): string {
  return text
    .toLowerCase()
    .replace(/[\u2018\u2019'`]/g, "")
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .split(" ")
    .map((word) => WORD_FIXES[word] ?? word)
    .join(" ");
}

/** "Is 8883 open?" names a port without the word "port". */
const BARE_PORT_QUESTION = /(?:^| )(?:is|are) (?:port )?\d{1,5} (?:open|closed|listening|reachable)(?= |$)/;

function stripFiller(text: string): string {
  let value = text;
  for (const filler of LEADING_FILLER) {
    if (value.startsWith(`${filler} `)) value = value.slice(filler.length + 1);
  }
  for (const filler of TRAILING_FILLER) {
    if (value.endsWith(` ${filler}`)) value = value.slice(0, -(filler.length + 1));
  }
  return value;
}

/** `start`/`end` are character offsets of the phrase within the normalized text. */
type Match = { rule: IntentPhrase; start: number; end: number };

function findMatches(text: string): Match[] {
  const padded = ` ${text} `;
  const matches: Match[] = [];
  for (const rule of INTENT_PHRASES) {
    const needle = ` ${rule.phrase} `;
    let index = padded.indexOf(needle);
    while (index !== -1) {
      matches.push({ rule, start: index, end: index + rule.phrase.length });
      index = padded.indexOf(needle, index + 1);
    }
  }
  return matches;
}

function containsWord(text: string, words: string): boolean {
  return ` ${text} `.includes(` ${words} `);
}

/** TECHNICAL questions and status questions; anything else is an explicit task. */
function isFactQuestion(rule: IntentPhrase): boolean {
  return rule.intent === "TECHNICAL" || (rule.intent === "SUMMARY" && STATUS_PHRASES.includes(rule.phrase));
}

function technicalPorts(text: string, phrase: string): AssistantIntentResult {
  const exact = stripFiller(text) === phrase;
  return {
    intent: "TECHNICAL",
    confidence: exact ? "HIGH" : "MEDIUM",
    matchedPhrase: phrase,
    subject: "PORTS",
    ...INTENT_REQUIREMENTS.TECHNICAL,
    reason: `Request asks whether a numbered port ("${phrase}") is open (TECHNICAL).`,
  };
}

function unknown(reason: string): AssistantIntentResult {
  return {
    intent: "UNKNOWN",
    confidence: "LOW",
    matchedPhrase: null,
    subject: null,
    ...INTENT_REQUIREMENTS.UNKNOWN,
    reason,
  };
}

export function classifyAssistantIntent(input: string): AssistantIntentResult {
  if (input.length > MAX_REQUEST_LENGTH) {
    return unknown(`Request is longer than ${MAX_REQUEST_LENGTH} characters.`);
  }
  const text = normalizeRequest(input);
  if (!text) return unknown("Request is empty.");

  const all = findMatches(text);
  // A phrase inside, or sharing words with, a longer matched phrase does not
  // count on its own, e.g. "check again" within "check again after fixing" or
  // "risk score" within "why is my risk score high".
  const outranks = (other: Match, m: Match) =>
    other.end - other.start > m.end - m.start ||
    (other.end - other.start === m.end - m.start && other.start < m.start);
  let matches = all.filter(
    (m) => !all.some((other) => other !== m && other.start < m.end && m.start < other.end && outranks(other, m)),
  );
  if (matches.length === 0) {
    const port = ` ${text} `.match(BARE_PORT_QUESTION)?.[0].trim() ?? null;
    if (port) return technicalPorts(text, port);
    return unknown(NO_PHRASE_REASON);
  }

  // Explicit tasks come before questions about recorded results ("How do I fix
  // these security issues?" is FIX), and recorded facts before status
  // questions. Two different tasks in one request stay ambiguous.
  const primary = matches.filter((m) => !isFactQuestion(m.rule));
  if (primary.length) {
    if (new Set(primary.map((m) => m.rule.intent)).size === 1) matches = primary;
  } else {
    const technical = matches.filter((m) => m.rule.intent === "TECHNICAL");
    if (technical.length) matches = technical;
  }

  const intents = [...new Set(matches.map((m) => m.rule.intent))];
  if (intents.length > 1) {
    const listed = matches
      .map((m) => `${m.rule.intent} ("${m.rule.phrase}")`)
      .filter((value, index, list) => list.indexOf(value) === index)
      .join(", ");
    return unknown(`Request matches more than one intent: ${listed}.`);
  }

  const best = [...matches].sort(
    (a, b) => b.end - b.start - (a.end - a.start) || a.start - b.start,
  )[0];
  const before = text.slice(0, best.start);
  const negation = NEGATIONS.find((word) => containsWord(before, word));
  if (negation) {
    return unknown(`"${best.rule.phrase}" is preceded by "${negation}".`);
  }

  const intent = best.rule.intent;
  const exact = stripFiller(text) === best.rule.phrase;
  return {
    intent,
    confidence: exact ? "HIGH" : "MEDIUM",
    matchedPhrase: best.rule.phrase,
    subject: SUBJECTED_INTENTS.includes(intent) ? (best.rule.subject ?? null) : null,
    ...INTENT_REQUIREMENTS[intent],
    reason: exact
      ? `Request is the phrase "${best.rule.phrase}" (${intent}).`
      : `Request contains the phrase "${best.rule.phrase}" (${intent}).`,
  };
}

/** Intent chosen directly by the user (e.g. a shortcut), not classified from text. */
export function selectedIntent(
  intent: SupportedIntent,
  subject: IntentSubject,
  label: string,
): AssistantIntentResult {
  return {
    intent,
    confidence: "HIGH",
    matchedPhrase: null,
    subject: SUBJECTED_INTENTS.includes(intent) ? subject : null,
    ...INTENT_REQUIREMENTS[intent],
    reason: `Chosen from the "${label}" shortcut.`,
  };
}
