import { useId, useState } from "react";
import { severityTone } from "../../lib/format";
import type { SimpleIssue } from "../../lib/securityHome";
import { SeverityBadge } from "../common/SeverityBadge";

const ACCENT: Record<ReturnType<typeof severityTone>, string> = {
  danger: "border-l-[var(--danger)]",
  warn: "border-l-[var(--warn)]",
  ok: "border-l-[var(--border-strong)]",
  default: "border-l-[var(--border-strong)]",
};

export function IssueCard({ issue }: { issue: SimpleIssue }) {
  const [open, setOpen] = useState(false);
  const panelId = useId();

  return (
    <li
      className={`min-w-0 rounded-xl border border-white/[0.06] border-l-[3px] bg-white/[0.02] px-4 py-3.5 ${
        ACCENT[severityTone(issue.severity)]
      }`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={issue.severity} />
        {issue.occurrences > 1 ? (
          <span className="text-xs text-[var(--muted)]">
            Found on {issue.occurrences} services
          </span>
        ) : null}
      </div>
      <p className="mt-2 break-words text-[15px] font-medium leading-snug text-[var(--text)]">
        {issue.title}
      </p>
      {issue.summary ? (
        <p className="mt-1 break-words text-sm leading-relaxed text-[var(--muted)]">
          {issue.summary}
        </p>
      ) : null}

      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-controls={panelId}
        className="btn-soft mt-3 inline-flex min-h-11 items-center rounded-full border border-white/10 bg-white/[0.04] px-4 text-sm font-medium text-[var(--accent)] hover:border-[var(--accent)]/35"
      >
        {open ? "Hide fix" : "How do I fix this?"}
      </button>

      <div id={panelId} hidden={!open} className="mt-3 border-t border-white/[0.06] pt-3">
        <p className="text-[11px] font-medium uppercase tracking-[0.1em] text-[var(--muted)]">
          Recommended fix · from the assessment engine
        </p>
        {issue.remediation ? (
          <p className="mt-1.5 whitespace-pre-wrap break-words text-sm leading-relaxed text-[var(--text)]">
            {issue.remediation}
          </p>
        ) : (
          <p className="mt-1.5 text-sm text-[var(--muted)]">No remediation recorded.</p>
        )}
      </div>
    </li>
  );
}
