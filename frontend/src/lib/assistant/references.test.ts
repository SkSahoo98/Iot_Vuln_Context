/**
 * Checks for reference resolution: which phrases refer to listed issues
 * ("these two", "both", "the first one", "the other one", "the HIGH one",
 * "the password one"), which do not, how they bind to the issues last shown,
 * and what is asked about them. Pure functions; no requests.
 *
 * Run from frontend/:  node src/lib/assistant/references.test.ts
 */
import type { AssistantIssue } from "./context.ts";

declare const process: { cwd(): string };

type ViteServer = {
  ssrLoadModule(url: string): Promise<Record<string, unknown>>;
  close(): Promise<void>;
};
type ReferencesLib = typeof import("./references.ts");
type FsModule = { readFileSync(path: string, encoding: "utf8"): string };

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`FAILED: ${message}`);
}
const results: string[] = [];
const pass = (name: string, note = "") => results.push(`PASS ${name}${note ? ` — ${note}` : ""}`);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

const issue = (checkId: string, severity: string, title: string, meaning: string): AssistantIssue => ({
  checkId, severity, title, meaning, remediation: `Fix for ${checkId}.`, ports: [1883], occurrenceCount: 1,
});
const AUTH = issue("IOT-MQTT-01", "HIGH", "MQTT broker accepts connections without a password", "The broker accepted a connection that supplied no username or password.");
const PLAIN = issue("IOT-MQTT-02", "MEDIUM", "MQTT traffic is not encrypted", "The broker accepted unencrypted MQTT and no encrypted MQTT listener was reachable.");
const WEB = issue("WEB-01", "MEDIUM", "Web interface without HTTPS", "The device's web page is served without encryption.");

const viteModuleName = "vite";
const fsModuleName = "node:fs";
const vite = (await import(viteModuleName)) as { createServer(config: Record<string, unknown>): Promise<ViteServer> };
const fs = (await import(fsModuleName)) as FsModule;
const server = await vite.createServer({
  root: process.cwd(),
  configFile: false,
  logLevel: "error",
  appType: "custom",
  server: { middlewareMode: true, hmr: false },
  optimizeDeps: { noDiscovery: true, include: [] },
});

try {
  const refs = (await server.ssrLoadModule("/src/lib/assistant/references.ts")) as unknown as ReferencesLib;
  const detect = (text: string) => refs.detectReference(text);

  // 1. Referring phrases are found, with what they point at.
  {
    const cases: [string, Record<string, unknown>][] = [
      ["What are these two?", { kind: "GROUP", phrase: "these two", count: 2 }],
      ["what are those two issues", { kind: "GROUP", phrase: "those two issues", count: 2 }],
      ["How do I fix both?", { kind: "GROUP", phrase: "both", count: 2 }],
      ["Explain both of them", { kind: "GROUP", phrase: "both of them", count: 2 }],
      ["What are the two?", { kind: "GROUP", phrase: "the two", count: 2 }],
      ["How do I fix them?", { kind: "GROUP", phrase: "them", count: null }],
      ["Are they dangerous?", { kind: "GROUP", phrase: "they", count: null }],
      ["What do these mean?", { kind: "GROUP", phrase: "these", count: null }],
      ["What are these?", { kind: "GROUP", phrase: "these", count: null }],
      ["Explain each of them", { kind: "GROUP", phrase: "each of them", count: null }],
      ["Tell me about the first one", { kind: "ORDINAL", phrase: "the first one", index: 0 }],
      ["What is the second issue?", { kind: "ORDINAL", phrase: "the second issue", index: 1 }],
      ["number 2", { kind: "ORDINAL", phrase: "number 2", index: 1 }],
      ["Explain issue 1", { kind: "ORDINAL", phrase: "issue 1", index: 0 }],
      ["2", { kind: "ORDINAL", phrase: "2", index: 1 }],
      ["The first one", { kind: "ORDINAL", phrase: "the first one", index: 0 }],
      ["second", { kind: "ORDINAL", phrase: "second", index: 1 }],
      ["What about the last one?", { kind: "ORDINAL", phrase: "the last one", index: -1 }],
      ["What about the other one?", { kind: "OTHER", phrase: "the other one" }],
      ["Is the high one bad?", { kind: "SEVERITY", phrase: "the high one", severity: "HIGH" }],
      ["Explain the medium severity issue", { kind: "SEVERITY", phrase: "the medium severity issue", severity: "MEDIUM" }],
      ["How do I fix the password one?", { kind: "KEYWORDS", phrase: "the password one", words: ["password"] }],
      ["Explain the encryption issue", { kind: "KEYWORDS", phrase: "the encryption issue", words: ["encryption"] }],
      ["What about the one about authentication", { kind: "KEYWORDS", phrase: "the one about authentication", words: ["authentication"] }],
    ];
    for (const [text, expected] of cases) {
      const found = detect(text);
      check(same(found, expected), `"${text}" -> ${JSON.stringify(found)}`);
    }
    pass("1 group, ordinal, \"other\", severity and descriptive references are detected", `${cases.length} phrasings`);
  }

  // 2. Phrases that are not references to listed issues.
  {
    const none = [
      "What are these security issues?", "What are these results?", "What is this?", "How do I fix this?", "Why?",
      "Which one is most serious?", "What is the most serious issue?", "What's the biggest problem?",
      "What changed between the two checks?", "Compare the two scans", "Is port 1883 open?", "What are these ports?",
      "Show me the issues", "What did you find?", "Check my network", "What should I fix first?", "Is my network safe?",
      "What is the first step?", "What is cybersecurity?",
    ];
    for (const text of none) check(detect(text) === null, `"${text}" -> ${JSON.stringify(detect(text))}`);
    pass("2 single pronouns, issue questions and other nouns (checks, ports, results) are not issue references", `${none.length} phrasings`);
  }

  // 3. Binding to the issues last shown.
  {
    const conv = (shown: AssistantIssue[], selected: AssistantIssue | null = null) => ({ shown, selected, important: [AUTH, PLAIN] });
    const bind = (text: string, c: ReturnType<typeof conv>) => refs.bindReference(detect(text)!, c);
    const two = conv([AUTH, PLAIN]);
    const ids = (r: ReturnType<typeof bind>) =>
      r.kind === "ISSUE" ? r.issue.checkId : r.kind === "ISSUES" ? r.issues.map((i) => i.checkId) : r.kind === "AMBIGUOUS" ? `?${r.candidates.map((i) => i.checkId)}` : r.kind;
    const expected: [string, ReturnType<typeof conv>, unknown][] = [
      ["What are these two?", two, ["IOT-MQTT-01", "IOT-MQTT-02"]],
      ["How do I fix them?", two, ["IOT-MQTT-01", "IOT-MQTT-02"]],
      ["the first one", two, "IOT-MQTT-01"],
      ["the second one", two, "IOT-MQTT-02"],
      ["the last one", two, "IOT-MQTT-02"],
      ["the third one", two, "?IOT-MQTT-01,IOT-MQTT-02"],
      ["the other one", conv([AUTH, PLAIN], AUTH), "IOT-MQTT-02"],
      ["the other one", two, "?IOT-MQTT-01,IOT-MQTT-02"],
      ["the high one", two, "IOT-MQTT-01"],
      ["the medium one", conv([]), "IOT-MQTT-02"],
      ["the low one", two, "NO_SEVERITY"],
      ["the password one", two, "IOT-MQTT-01"],
      ["the authentication one", two, "IOT-MQTT-01"],
      ["the unencrypted one", two, "IOT-MQTT-02"],
      ["the tls issue", two, "IOT-MQTT-02"],
      ["the mqtt one", two, "?IOT-MQTT-01,IOT-MQTT-02"],
      ["the telnet one", two, "NONE"],
      ["What are these two?", conv([]), "UNBOUND"],
      ["the first one", conv([]), "UNBOUND"],
      ["these two", conv([AUTH, PLAIN, WEB]), "?IOT-MQTT-01,IOT-MQTT-02,WEB-01"],
      ["What are these?", conv([PLAIN]), "IOT-MQTT-02"],
    ];
    for (const [text, c, want] of expected) {
      const got = ids(bind(text, c));
      check(same(got, want), `"${text}" with ${c.shown.length} shown -> ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    }
    pass("3 references bind to the issues last shown; unclear ones are AMBIGUOUS, unshown ones UNBOUND", `${expected.length} bindings`);
  }

  // 4. What is asked about the referenced issues.
  {
    const aspects: [string, string][] = [
      ["What are these two?", "MEANING"],
      ["Tell me about both", "MEANING"],
      ["the first one", "MEANING"],
      ["Why do they matter?", "WHY"],
      ["Why are these two a problem?", "WHY"],
      ["Are they dangerous?", "SEVERITY"],
      ["Are these two a problem?", "SEVERITY"],
      ["How do I fix both?", "FIX"],
      ["What should I do about them?", "FIX"],
      ["How do I fix the first one?", "FIX"],
      ["Which of these two is worse?", "MOST_SERIOUS"],
      ["Which of them should I fix first?", "MOST_SERIOUS"],
      ["Show technical details for both", "TECHNICAL"],
      ["What evidence do you have for the second one?", "EVIDENCE"],
      ["Is the second one fixed?", "VERIFY"],
    ];
    for (const [text, want] of aspects) {
      const resolved = refs.resolveReferenceRequest(text);
      check(resolved?.aspect === want, `"${text}" -> ${resolved?.aspect}, want ${want}`);
    }
    pass("4 the request without the referring phrase decides what is asked", `${aspects.length} requests`);
  }

  // 5. Static boundary.
  {
    const text = fs.readFileSync(`${process.cwd()}/src/lib/assistant/references.ts`, "utf8");
    check(!/\bfetch\(|explain|from "\.\.\/\.\.\/api\//.test(text.replace(/\/\*\*[\s\S]*?\*\//g, "")), "references.ts makes no requests");
    check(!/ollama|11434|qwen/i.test(text), "names no model");
    pass("5 reference resolution is local and deterministic");
  }
} finally {
  await server.close();
}

for (const line of results) console.log(line);
console.log(`${results.filter((line) => line.startsWith("PASS")).length} checks passed`);
