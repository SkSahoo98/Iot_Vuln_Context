/**
 * Assistant shortcuts. Each shortcut is a pre-selected intent and goes through
 * the same resolver as a classified request; nothing here generates answers
 * or interprets free text.
 */
import type { AssistantContext } from "./assistant/context";
import {
  selectedIntent,
  type AssistantIntentResult,
  type IntentSubject,
  type SupportedIntent,
} from "./assistant/intents";
import { resolveAssistantIntent, type AssistantResolution } from "./assistant/resolve";

export type AssistantShortcutId =
  | "check"
  | "whats-wrong"
  | "explain-risk"
  | "fix-issue"
  | "verify"
  | "summary";

export type AssistantShortcut = {
  id: AssistantShortcutId;
  intent: SupportedIntent;
  subject: IntentSubject;
  label: string;
  description: string;
};

export const ASSISTANT_SHORTCUTS: readonly AssistantShortcut[] = [
  {
    id: "check",
    intent: "CHECK",
    subject: null,
    label: "Check my IoT network",
    description: "Run a security check of your authorized target.",
  },
  {
    id: "whats-wrong",
    intent: "EXPLAIN",
    subject: "ISSUES",
    label: "What's wrong?",
    description: "See important issues from your latest check.",
  },
  {
    id: "explain-risk",
    intent: "EXPLAIN",
    subject: "RISK",
    label: "Explain my risk",
    description: "Understand what contributes to your current risk.",
  },
  {
    id: "fix-issue",
    intent: "FIX",
    subject: null,
    label: "Help me fix an issue",
    description: "Get remediation guidance.",
  },
  {
    id: "verify",
    intent: "VERIFY",
    subject: null,
    label: "Check if I fixed it",
    description: "Re-check and compare with your previous result.",
  },
  {
    id: "summary",
    intent: "SUMMARY",
    subject: null,
    label: "Summarize my last check",
    description: "Review the overall result.",
  },
];

export function shortcutById(id: AssistantShortcutId): AssistantShortcut {
  const shortcut = ASSISTANT_SHORTCUTS.find((item) => item.id === id);
  if (!shortcut) throw new Error(`Unknown assistant shortcut: ${id}`);
  return shortcut;
}

export function shortcutIntent(shortcut: AssistantShortcut): AssistantIntentResult {
  return selectedIntent(shortcut.intent, shortcut.subject, shortcut.label);
}

export function resolveShortcut(
  id: AssistantShortcutId,
  context: AssistantContext | null,
): AssistantResolution {
  return resolveAssistantIntent(shortcutIntent(shortcutById(id)), context);
}

/** Short text shown on a shortcut that cannot be used; null when it can. */
export function shortcutHint(resolution: AssistantResolution): string | null {
  if (resolution.state === "READY") return null;
  switch (resolution.blocker) {
    case "ASSESSMENTS_LOADING":
      return "Available once your security checks have loaded.";
    case "NO_ASSESSMENT":
    case "NO_COMPLETE_ASSESSMENT":
      return resolution.intent === "FIX"
        ? "Available after a completed security check with an important issue."
        : "Available after a completed security check.";
    case "LATEST_NOT_COMPLETE":
      return "Available when your latest security check completes.";
    case "ISSUES_LOADING":
      return "Checking your latest results…";
    case "ISSUES_UNAVAILABLE":
      return "Couldn't load the issues from your latest check.";
    case "NO_IMPORTANT_ISSUES":
      return "No important issue was found in your latest check.";
    default:
      return "Not available right now.";
  }
}
