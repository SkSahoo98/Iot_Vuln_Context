import type { AssessmentEvidence } from "../../api/types";
import { formatFactorLabel, formatGeneratedAt } from "../../lib/format";
import { resolveAssetIdentity } from "../../lib/assets";
import { StatusBadge } from "../common/StatusBadge";
import {
  REDACTED,
  formatJsonValue,
  formatTargetPort,
  isComplexValue,
  isSensitiveKey,
  redactSensitive,
} from "./detailFormat";

type Props = {
  evidence: AssessmentEvidence[];
};

export function evidenceAnchorId(evidenceId: string): string {
  return `assessment-evidence-${evidenceId}`;
}

function isEmptyValue(value: unknown): boolean {
  return value === null || value === undefined || value === "";
}

type ObservationFieldsProps = {
  observation: Record<string, unknown>;
  /** Omit fields the backend recorded as null or empty. */
  hideEmpty?: boolean;
};

export function ObservationFields({
  observation,
  hideEmpty = false,
}: ObservationFieldsProps) {
  const entries = Object.entries(observation ?? {});
  const inline = entries.filter(
    ([, value]) => !isComplexValue(value) && !(hideEmpty && isEmptyValue(value)),
  );

  if (entries.length === 0) {
    return (
      <p className="mt-3 text-sm text-[var(--muted)]">
        No structured observation recorded.
      </p>
    );
  }

  return (
    <>
      {inline.length ? (
        <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2">
          {inline.map(([key, value]) => (
            <div
              key={key}
              className="flex min-w-0 justify-between gap-3 rounded-xl border border-white/[0.05] bg-white/[0.02] px-3 py-2"
            >
              <dt className="shrink-0 text-[var(--muted)]">
                {formatFactorLabel(key)}
              </dt>
              <dd className="mono min-w-0 break-all text-right">
                {isSensitiveKey(key) ? REDACTED : formatJsonValue(value)}
              </dd>
            </div>
          ))}
        </dl>
      ) : null}

      <details className="mt-3 rounded-xl border border-white/[0.06] bg-white/[0.02]">
        <summary className="cursor-pointer px-3 py-2 text-xs font-medium text-[var(--muted)] hover:text-[var(--text)]">
          Full observation (JSON)
        </summary>
        <pre className="mono max-h-80 overflow-auto whitespace-pre-wrap break-all border-t border-white/[0.06] px-3 py-2 text-xs leading-relaxed text-[var(--muted)]">
          {JSON.stringify(redactSensitive(observation), null, 2)}
        </pre>
      </details>
    </>
  );
}

export function AssessmentEvidenceList({ evidence }: Props) {
  return (
    <ul className="space-y-3">
      {evidence.map((item) => {
        const identity = resolveAssetIdentity(item.target, { port: item.port });
        return (
          <li
            key={item.id}
            id={evidenceAnchorId(item.id)}
            tabIndex={-1}
            className="surface-panel scroll-mt-24 rounded-2xl p-4 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]/50"
          >
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="mono break-all text-sm font-semibold text-[var(--text)]">
                  {item.check_type}
                </p>
                <div className="mt-1 flex flex-wrap items-center gap-x-2 text-xs text-[var(--muted)]">
                  <span className="font-medium text-sky-400">{identity.displayName}</span>
                  <span>•</span>
                  <span className="mono">
                    {formatTargetPort(item.target, item.port)}
                  </span>
                  <span>•</span>
                  <span>Source: </span>
                  <span className="mono">{item.evidence_source}</span>
                  <span>•</span>
                  <span>{formatGeneratedAt(item.observed_at) ?? "Time not recorded"}</span>
                </div>
              </div>
              <StatusBadge label={item.result} tone="info" />
            </div>

            <ObservationFields observation={item.observation} />
          </li>
        );
      })}
    </ul>
  );
}
