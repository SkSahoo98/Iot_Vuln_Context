/**
 * Removes values that must never reach the assistant: credentials, tokens,
 * URLs and (for runtime error text) filesystem paths.
 */

export const REDACTED = "[redacted]";

const URL_PATTERN = /\b(?:https?|ftp|mqtts?|wss?):\/\/[^\s"'<>]+/gi;
const SECRET_ASSIGNMENT =
  /\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization)(\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)/gi;
const BEARER = /\bbearer\s+[A-Za-z0-9._~+/-]+=*/gi;
const JWT = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
const WINDOWS_PATH = /\b[A-Za-z]:[\\/][^\s"'<>]*/g;
const UNIX_PATH = /(^|[\s("'=])(\/(?:[\w.-]+\/)+[\w.-]*)/g;
const ENV_FILE = /(^|[\s("'=/\\])\.env\b[\w.]*/gi;

/** Credentials, tokens and URLs; safe for backend-authored guidance text. */
export function redactSecrets(value: string): string {
  return value
    .replace(URL_PATTERN, REDACTED)
    .replace(JWT, REDACTED)
    .replace(BEARER, `Bearer ${REDACTED}`)
    .replace(SECRET_ASSIGNMENT, (_match, key: string, separator: string) => `${key}${separator}${REDACTED}`);
}

/** Everything in redactSecrets plus filesystem paths; for runtime error text. */
export function redactRuntimeText(value: string): string {
  return redactSecrets(value)
    .replace(WINDOWS_PATH, REDACTED)
    .replace(UNIX_PATH, (_match, lead: string) => `${lead}${REDACTED}`)
    .replace(ENV_FILE, (_match, lead: string) => `${lead}${REDACTED}`);
}
