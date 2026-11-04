/**
 * Reference resolution: which issues "these two", "both", "the first one",
 * "the other one", "the HIGH one" or "the password one" mean, given what the
 * conversation last showed. Detection reads only the words; binding uses the
 * issues of the latest complete check that the last issue list displayed.
 * Single pronouns ("this", "it") are left to the issue under discussion.
 * Nothing here calls a model, reads the backend or decides severity.
 */
import type { AssistantIssue } from "./context";
import { normalizeRequest } from "./intents";

/** What the conversation currently has on screen. */
export type ConversationContext = {
  /** Issues the last issue list showed, in display order. */
  shown: readonly AssistantIssue[];
  /** Issue under discussion, if any. */
  selected: AssistantIssue | null;
  /** All important issues of the latest complete check. */
  important: readonly AssistantIssue[];
};

/** A referring phrase found in the request, before it is bound to issues. */
export type ReferenceMatch =
  | { kind: "GROUP"; phrase: string; count: number | null }
  | { kind: "ORDINAL"; phrase: string; index: number }
  | { kind: "OTHER"; phrase: string }
  | { kind: "SEVERITY"; phrase: string; severity: string }
  | { kind: "KEYWORDS"; phrase: string; words: string[] };

/** What a referring phrase stands for in the current conversation. */
export type Reference =
  | { kind: "ISSUE"; issue: AssistantIssue }
  | { kind: "ISSUES"; issues: AssistantIssue[] }
  /** More than one issue fits; ask which. */
  | { kind: "AMBIGUOUS"; candidates: AssistantIssue[] }
  /** Nothing on screen to refer to. */
  | { kind: "UNBOUND" }
  /** "The LOW one" when no important issue has that severity. */
  | { kind: "NO_SEVERITY"; severity: string }
  /** Descriptive words that match no issue: not a reference after all. */
  | { kind: "NONE" };

/** What the request asks about the referenced issues. */
export type ReferenceAspect = "MEANING" | "WHY" | "SEVERITY" | "FIX" | "MOST_SERIOUS" | "EVIDENCE" | "TECHNICAL" | "VERIFY";

export type ResolvedReference = { match: ReferenceMatch; aspect: ReferenceAspect };

const B = "(?:^| )";
const E = "(?= |$)";
const NOUN = "(?:one|issue|problem|finding)";
const PLURAL_NOUN = "(?:issues|problems|findings|ones)";
const COUNTS: Record<string, number> = { two: 2, three: 3, both: 2 };
const ORDINALS: Record<string, number> = { first: 0, "1st": 0, top: 0, second: 1, "2nd": 1, third: 2, "3rd": 2, last: -1 };

/** "the two checks", "these ports": the phrase is about something other than issues. */
const OTHER_NOUNS = new Set([
  "check", "checks", "scan", "scans", "assessment", "assessments", "port", "ports", "service", "services",
  "device", "devices", "target", "targets", "result", "results", "factor", "factors", "score", "scores",
  "security", "details", "steps", "settings", "values", "numbers",
]);

const GROUP = new RegExp(
  `${B}((?:all )?(?:these|those|the) (two|three)(?: ${PLURAL_NOUN})?|(both)(?: of (?:them|these|those))?(?: ${PLURAL_NOUN})?|all of (?:them|these|those)|each of (?:them|these|those)|each one)${E}`,
);
const OTHER = new RegExp(`${B}(the other(?: ${NOUN})?)${E}`);
const ORDINAL = new RegExp(`${B}((?:the )?(first|1st|second|2nd|third|3rd|last|top) ${NOUN}|(?:issue|problem|finding|number|option) (?:number )?([1-9]))${E}`);
const ORDINAL_ALONE = /^(?:the )?(first|second|third|last)(?: one)?$|^([1-9])$/;
const SEVERITY = new RegExp(`${B}(the (critical|high|medium|low)(?: severity| risk)? ${NOUN})${E}`);
const KEYWORDS = [
  new RegExp(`${B}(the ((?:[a-z0-9]+ ){0,2}[a-z0-9]+) ${NOUN})${E}`),
  new RegExp(`${B}(the one (?:about|with|for|on) ((?:[a-z0-9]+ ){0,2}[a-z0-9]+))$`),
];
const PRONOUN = new RegExp(`${B}((them|they|these|those)(?: ${PLURAL_NOUN})?)${E}`);

const KEYWORD_STOP = new Set([
  "a", "an", "the", "one", "other", "same", "main", "big", "bigger", "biggest", "bad", "worse", "worst", "most", "more",
  "serious", "important", "urgent", "next", "this", "that", "these", "those", "first", "second", "third", "last", "top",
  "critical", "high", "medium", "low", "severity", "risk", "about", "with", "for", "on", "of", "my", "your", "security",
  "new", "old", "real", "only", "two", "three", "is", "it",
]);

function nextWord(text: string, phrase: string): string | null {
  const at = ` ${text} `.indexOf(` ${phrase} `);
  if (at < 0) return null;
  return text.slice(at + phrase.length).trim().split(" ")[0] || null;
}

/** The referring phrase of a normalized request, or null. */
export function detectReference(input: string): ReferenceMatch | null {
  const text = normalizeRequest(input);
  if (!text) return null;
  const aboutIssues = (phrase: string) => {
    const next = nextWord(text, phrase);
    return !next || !OTHER_NOUNS.has(next);
  };

  const group = text.match(GROUP);
  if (group && aboutIssues(group[1])) {
    const word = group[2] ?? group[3] ?? null;
    return { kind: "GROUP", phrase: group[1], count: word ? COUNTS[word] : null };
  }
  const other = text.match(OTHER);
  if (other && aboutIssues(other[1])) return { kind: "OTHER", phrase: other[1] };
  const ordinal = text.match(ORDINAL);
  if (ordinal && aboutIssues(ordinal[1])) {
    return { kind: "ORDINAL", phrase: ordinal[1], index: ordinal[2] ? ORDINALS[ordinal[2]] : Number(ordinal[3]) - 1 };
  }
  const alone = text.match(ORDINAL_ALONE);
  if (alone) return { kind: "ORDINAL", phrase: text, index: alone[1] ? ORDINALS[alone[1]] : Number(alone[2]) - 1 };
  const severity = text.match(SEVERITY);
  if (severity) return { kind: "SEVERITY", phrase: severity[1], severity: severity[2].toUpperCase() };
  for (const pattern of KEYWORDS) {
    const found = text.match(pattern);
    const words = found ? found[2].split(" ").filter((word) => !KEYWORD_STOP.has(word)) : [];
    if (found && words.length) return { kind: "KEYWORDS", phrase: found[1], words };
  }
  const pronoun = text.match(PRONOUN);
  if (pronoun && (pronoun[2] === "them" || pronoun[2] === "they" || aboutIssues(pronoun[1]))) {
    return { kind: "GROUP", phrase: pronoun[1], count: null };
  }
  return null;
}

const SYNONYMS: Record<string, string> = {
  password: "password", passwords: "password", auth: "password", authentication: "password",
  authenticated: "password", unauthenticated: "password", login: "password", logins: "password",
  anonymous: "password", credential: "password", credentials: "password", username: "password",
  encrypted: "encrypt", encryption: "encrypt", unencrypted: "encrypt", encrypt: "encrypt", tls: "encrypt",
  ssl: "encrypt", plaintext: "encrypt", cleartext: "encrypt", https: "encrypt",
  administrative: "admin", administration: "admin", admin: "admin",
};
const canonical = (word: string) => SYNONYMS[word] ?? word.replace(/(?:ing|ed|es|s)$/, "");

function issueWords(issue: AssistantIssue): Set<string> {
  const text = normalizeRequest(`${issue.title} ${issue.meaning ?? ""}`);
  return new Set(text.split(" ").filter((word) => word.length > 2).map(canonical));
}

/** The issues a referring phrase stands for, given what was last shown. */
export function bindReference(match: ReferenceMatch, conversation: ConversationContext): Reference {
  const { shown, selected, important } = conversation;
  const pool = shown.length ? shown : important;
  const one = (issues: readonly AssistantIssue[]): Reference =>
    issues.length === 1 ? { kind: "ISSUE", issue: issues[0] } : { kind: "AMBIGUOUS", candidates: [...issues] };

  switch (match.kind) {
    case "GROUP":
      if (!shown.length) return { kind: "UNBOUND" };
      if (shown.length === 1) return { kind: "ISSUE", issue: shown[0] };
      if (match.count !== null && match.count < shown.length) return { kind: "AMBIGUOUS", candidates: [...shown] };
      return { kind: "ISSUES", issues: [...shown] };
    case "ORDINAL": {
      if (!shown.length) return { kind: "UNBOUND" };
      const issue = match.index === -1 ? shown[shown.length - 1] : shown[match.index];
      return issue ? { kind: "ISSUE", issue } : { kind: "AMBIGUOUS", candidates: [...shown] };
    }
    case "OTHER": {
      if (!shown.length) return { kind: "UNBOUND" };
      const rest = selected ? shown.filter((issue) => issue.checkId !== selected.checkId) : [...shown];
      return rest.length === shown.length - 1 ? one(rest) : { kind: "AMBIGUOUS", candidates: [...shown] };
    }
    case "SEVERITY": {
      let found = pool.filter((issue) => issue.severity.toUpperCase() === match.severity);
      if (!found.length && pool !== important) found = important.filter((issue) => issue.severity.toUpperCase() === match.severity);
      return found.length ? one(found) : { kind: "NO_SEVERITY", severity: match.severity };
    }
    case "KEYWORDS": {
      const wanted = match.words.map(canonical);
      const fits = (issues: readonly AssistantIssue[]) =>
        issues.filter((issue) => {
          const words = issueWords(issue);
          return wanted.every((word) => words.has(word));
        });
      let found = fits(pool);
      if (!found.length && pool !== important) found = fits(important);
      return found.length ? one(found) : { kind: "NONE" };
    }
  }
}

/** What is asked about the referenced issues, read from the request without the referring phrase. */
export function referenceAspect(input: string, phrase: string): ReferenceAspect {
  const rest = ` ${` ${normalizeRequest(input)} `.replace(` ${phrase} `, " ").trim()} `;
  if (/ did i (fix|solve|resolve)| (fixed|resolved|gone|verify|verified) /.test(rest)) return "VERIFY";
  if (/ (which|worse|worst|first) | (more|most) (serious|important|dangerous|urgent|risky) /.test(rest)) return "MOST_SERIOUS";
  if (/ (fix|fixing|solve|resolve|remediate|repair|secure|address|patch) | what (should|can|do) i do /.test(rest)) return "FIX";
  if (/ technical | details? /.test(rest)) return "TECHNICAL";
  if (/ evidence | how do you know | proof | observed | flag | flagged /.test(rest)) return "EVIDENCE";
  if (/ why | matter | matters | impact /.test(rest)) return "WHY";
  if (/ bad | serious | dangerous | urgent | worry | worried | severe | risky | problem | problems /.test(rest)) return "SEVERITY";
  return "MEANING";
}

/** Detected phrase plus what is asked about it, or null when the request refers to nothing. */
export function resolveReferenceRequest(input: string): ResolvedReference | null {
  const match = detectReference(input);
  return match ? { match, aspect: referenceAspect(input, match.phrase) } : null;
}
