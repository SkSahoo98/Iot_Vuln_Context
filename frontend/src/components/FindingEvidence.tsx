import { evidenceDisplay } from "../lib/format";

type Props = {
  evidence: Record<string, unknown>;
};

const PREFERRED_KEYS = [
  "host",
  "port",
  "service",
  "version",
  "tls_enabled",
  "anonymous_allowed",
  "observed_topics",
];

function labelFor(key: string): string {
  return key
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function FindingEvidence({ evidence }: Props) {
  const keys = [
    ...PREFERRED_KEYS.filter((key) => key in evidence),
    ...Object.keys(evidence).filter((key) => !PREFERRED_KEYS.includes(key)),
  ];

  return (
    <div className="glass-inset mt-1 rounded-2xl p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="text-[11px] tracking-[0.12em] text-[var(--muted)] uppercase">
          Evidence
        </h4>
        <p className="text-[11px] text-[var(--accent)]">
          This finding is based on observed evidence.
        </p>
      </div>
      <div className="mt-3 space-y-0">
        {keys.map((key) => (
          <div
            key={key}
            className="grid grid-cols-[140px_1fr] gap-3 border-b border-white/[0.05] py-2.5 text-sm last:border-b-0"
          >
            <dt className="text-[var(--muted)]">{labelFor(key)}</dt>
            <dd className="mono text-[var(--text)]">
              {evidenceDisplay(evidence, key)}
            </dd>
          </div>
        ))}
      </div>
    </div>
  );
}
