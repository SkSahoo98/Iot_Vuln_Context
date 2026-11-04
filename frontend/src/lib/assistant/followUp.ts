/**
 * Short follow-ups ("What is this?", "Why?", "Is it bad?") that only make sense
 * together with what the conversation is currently about. They are matched as
 * whole listed phrases after normalization, and only when the main classifier
 * found no request phrase; the conversation decides what they refer to.
 */
import { normalizeRequest } from "./intents";

export type FollowUpKind =
  /** "What is this?", "What does it mean?" */
  | "MEANING"
  /** "Why?", "Why is this a problem?" */
  | "WHY"
  /** "Is it bad?", "Is this dangerous?" */
  | "SEVERITY"
  /** "Which one is more serious?" */
  | "MOST_SERIOUS"
  /** "How?", "What now?" */
  | "HOW"
  /** "Tell me more", "Explain" */
  | "MORE"
  /** "What is on that port?" */
  | "SERVICE_THERE"
  /** "Show technical details" */
  | "TECHNICAL_DETAILS"
  /** A question about security results without a specific subject, e.g. "Tell me about security." */
  | "TOPIC";

const FOLLOW_UPS: Record<Exclude<FollowUpKind, "TOPIC">, readonly string[]> = {
  MEANING: [
    "what", "this", "that", "it", "these", "those",
    "what is this", "what is that", "what is it", "whats this", "whats that", "whats it",
    "what are these", "what are those", "what are they", "what is this about", "what is that about",
    "what does this mean", "what does that mean", "what does it mean", "what do you mean", "meaning",
    "explain this", "explain that", "explain it", "what is this issue", "what is that issue",
    "what does this issue mean",
  ],
  WHY: [
    "why", "why is this", "why is that", "why is it", "so what", "why should i care",
    "why is this a problem", "why is that a problem", "why is it a problem",
    "why is this bad", "why is that bad", "why is it bad",
    "why is this an issue", "why is that an issue", "why is it an issue",
    "how is this a problem", "how is that a problem", "how is it a problem",
  ],
  SEVERITY: [
    "is it bad", "is this bad", "is that bad", "is it dangerous", "is this dangerous", "is that dangerous",
    "is it serious", "is this serious", "is that serious", "how bad is it", "how bad is this", "how bad is that",
    "how serious is it", "how serious is this", "how serious is that", "should i worry", "should i be worried",
    "is it a problem", "is this a problem", "is that a problem", "is it important", "is this important",
    "is it urgent", "is this urgent",
  ],
  MOST_SERIOUS: [
    "which one is more serious", "which is more serious", "which one is most serious", "which is most serious",
    "which one is the most serious", "which is the most serious", "which one is worse", "which is worse",
    "which one is the worst", "which is the worst", "which one first", "which first",
    "which one should i fix first", "which should i fix first", "what should i fix first",
    "which issue is more serious", "which issue is most serious", "which issue is the most serious",
    "which issue is worse", "which issue should i fix first", "what is the most serious issue",
    "whats the most serious issue", "which one is the most important", "which is the most important",
    "what is the most important issue", "most serious issue", "most important issue",
    "the more serious one", "the most serious one", "more serious one", "the worse one", "the worst one", "worse one",
    "the more important one", "the more dangerous one", "the more urgent one", "the bigger problem", "the bigger issue",
  ],
  HOW: ["how", "how so", "how do i do that", "how do i do it", "how can i do that", "what now", "what next", "then what", "what can i do", "what do i do now"],
  MORE: [
    "more", "tell me more", "more details", "more info", "explain", "explain more", "explain it more",
    "go on", "continue", "elaborate", "in more detail", "explain in more detail",
    "tell me more about it", "tell me more about this", "tell me more about that", "can you explain",
    "explain this in more detail", "explain that in more detail", "explain it in more detail", "explain in detail",
    "explain this in detail", "explain further", "explain this further", "explain that further", "explain it further",
    "more detail", "give me more detail", "give me more details", "give me a deeper explanation", "a deeper explanation",
    "deeper explanation", "go deeper",
  ],
  SERVICE_THERE: [
    "what is on it", "whats on it", "what is on there", "what is there", "what is on that port",
    "whats on that port", "what is on this port", "whats on this port",
  ],
  TECHNICAL_DETAILS: [
    "technical details", "see technical details", "show technical details", "show me technical details",
    "show the technical details", "show me the technical details", "show details", "show me the details",
    "technical", "more technical details",
  ],
};

const LEADING = ["ok", "okay", "so", "and", "but", "hmm", "um", "well", "oh", "please", "can you", "could you"];
const TRAILING = ["please", "then", "now", "exactly", "though", "for me"];

/** Words that make an otherwise unclear request about the user's security results. */
const RESULT_WORDS = new Set([
  "security", "secure", "safe", "safety", "risk", "risks", "risky", "issue", "issues", "problem",
  "problems", "finding", "findings", "vulnerability", "vulnerabilities", "vulnerable", "port", "ports",
  "service", "services", "result", "results", "score", "threat", "threats", "exposure", "exposed",
]);

function trimFiller(text: string): string {
  let value = text;
  let changed = true;
  while (changed) {
    changed = false;
    for (const word of LEADING) {
      if (value.startsWith(`${word} `)) {
        value = value.slice(word.length + 1);
        changed = true;
      }
    }
    for (const word of TRAILING) {
      if (value.endsWith(` ${word}`)) {
        value = value.slice(0, -(word.length + 1));
        changed = true;
      }
    }
  }
  return value;
}

function listedKind(text: string): FollowUpKind | null {
  for (const [kind, phrases] of Object.entries(FOLLOW_UPS) as [FollowUpKind, readonly string[]][]) {
    if (phrases.includes(text)) return kind;
  }
  return null;
}

/** The follow-up kind of an unmatched request, or null when it isn't one. */
export function classifyFollowUp(input: string): FollowUpKind | null {
  const text = normalizeRequest(input);
  if (!text) return null;
  const kind = listedKind(text) ?? listedKind(trimFiller(text));
  if (kind) return kind;
  return text.split(" ").some((word) => RESULT_WORDS.has(word)) ? "TOPIC" : null;
}

export const FOLLOW_UP_PHRASES = FOLLOW_UPS;
