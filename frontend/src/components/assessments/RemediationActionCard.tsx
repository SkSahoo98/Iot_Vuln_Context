import { useState } from "react";
import {
  confirmRemediation,
  createRemediation,
  fetchRemediationComparison,
  verifyRemediation,
} from "../../api/remediations";
import type {
  AssessmentFinding,
  RemediationComparison,
  RemediationWorkflow,
} from "../../api/types";
import { StatusBadge } from "../common/StatusBadge";

type Props = {
  finding: AssessmentFinding;
};

const BADGE_MAP: Record<
  string,
  { label: string; tone: "ok" | "warn" | "danger" | "info" | "neutral" }
> = {
  OPEN: { label: "Open", tone: "neutral" },
  GUIDANCE_VIEWED: { label: "Guidance Viewed", tone: "info" },
  REMEDIATION_IN_PROGRESS: { label: "In Progress", tone: "info" },
  READY_FOR_VERIFICATION: { label: "Ready for Verification", tone: "info" },
  VERIFICATION_PENDING: { label: "Verifying...", tone: "warn" },
  VERIFIED_RESOLVED: { label: "Verified Resolved ✓", tone: "ok" },
  STILL_PRESENT: { label: "Still Present ⚠", tone: "warn" },
  PARTIALLY_RESOLVED: { label: "Partially Resolved", tone: "warn" },
  INCONCLUSIVE: { label: "Inconclusive ?", tone: "neutral" },
  VERIFICATION_FAILED: { label: "Verification Failed", tone: "danger" },
};

export function RemediationActionCard({ finding }: Props) {
  const [workflow, setWorkflow] = useState<RemediationWorkflow | null>(null);
  const [comparison, setComparison] = useState<RemediationComparison | null>(null);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [userNotes, setUserNotes] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [showComparison, setShowComparison] = useState(false);

  // Lazy ensure workflow exists
  const ensureWorkflow = async (): Promise<RemediationWorkflow> => {
    if (workflow) return workflow;
    const res = await createRemediation(finding.assessment_id, finding.id);
    setWorkflow(res);
    return res;
  };

  const handleApplyFix = async () => {
    setLoading(true);
    setError(null);
    try {
      const current = await ensureWorkflow();
      const updated = await confirmRemediation(current.id, userNotes || undefined);
      setWorkflow(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to record confirmation");
    } finally {
      setLoading(false);
    }
  };

  const handleStartVerification = async () => {
    setShowModal(false);
    setVerifying(true);
    setError(null);
    try {
      const current = await ensureWorkflow();
      const updated = await verifyRemediation(current.id, "AUTO");
      setWorkflow(updated);

      // Load comparison
      try {
        const comp = await fetchRemediationComparison(updated.id);
        setComparison(comp);
      } catch {
        // Comparison optional
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification check failed");
    } finally {
      setVerifying(false);
    }
  };

  const status = workflow?.status ?? "OPEN";
  const badgeConfig = BADGE_MAP[status] || BADGE_MAP.OPEN;

  return (
    <div
      className="mt-3 min-w-0 space-y-3 rounded-xl border border-white/[0.08] bg-black/20 p-3 sm:p-4"
      data-remediation-card=""
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
            Remediation Lifecycle
          </span>
          <StatusBadge label={badgeConfig.label} tone={badgeConfig.tone} />
        </div>
        {workflow?.user_confirmed_at ? (
          <span className="mono text-[11px] text-[var(--muted)]">
            Confirmed: {new Date(workflow.user_confirmed_at).toLocaleTimeString()}
          </span>
        ) : null}
      </div>

      {error ? (
        <p className="rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/10 px-3 py-1.5 text-xs text-[var(--danger)]">
          {error}
        </p>
      ) : null}

      {/* State A: Open or not yet confirmed */}
      {status === "OPEN" || status === "GUIDANCE_VIEWED" ? (
        <div className="space-y-2">
          <p className="text-xs text-[var(--muted)]">
            After applying the recommended changes in your environment, click below to mark this issue ready for verification.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="text"
              placeholder="Optional notes (e.g. disabled allow_anonymous)"
              value={userNotes}
              onChange={(e) => setUserNotes(e.target.value)}
              className="min-w-0 flex-1 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs text-[var(--text)] placeholder-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
            />
            <button
              type="button"
              disabled={loading}
              onClick={handleApplyFix}
              data-btn-apply-fix=""
              className="btn-soft inline-flex items-center rounded-lg border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-3 py-1.5 text-xs font-medium text-[var(--accent)] hover:bg-[var(--accent)]/20 disabled:opacity-40"
            >
              {loading ? "Recording..." : "I Have Applied the Fix"}
            </button>
          </div>
        </div>
      ) : null}

      {/* State B: Ready for Verification */}
      {status === "READY_FOR_VERIFICATION" ? (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[var(--accent)]/25 bg-[var(--accent)]/[0.04] p-3">
          <div className="min-w-0 space-y-0.5">
            <p className="text-xs font-medium text-[var(--accent)]">
              Remediation applied by user
            </p>
            <p className="text-xs text-[var(--muted)]">
              Explicit user approval is required before running an authorized verification check.
            </p>
          </div>
          <button
            type="button"
            disabled={verifying}
            onClick={() => setShowModal(true)}
            data-btn-verify=""
            className="btn-soft inline-flex items-center rounded-lg border border-[var(--accent)] bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-black hover:opacity-90 disabled:opacity-40"
          >
            {verifying ? "Verifying..." : "Verify Remediation"}
          </button>
        </div>
      ) : null}

      {/* State C: Verification Completed */}
      {workflow?.verification_verdict ? (
        <div
          className={`space-y-2.5 rounded-lg border p-3 ${
            workflow.verification_verdict === "VERIFIED_RESOLVED"
              ? "border-[var(--ok)]/30 bg-[var(--ok)]/[0.05]"
              : workflow.verification_verdict === "STILL_PRESENT"
                ? "border-[var(--warn)]/30 bg-[var(--warn)]/[0.05]"
                : "border-white/10 bg-white/[0.02]"
          }`}
          data-verification-result=""
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs font-semibold uppercase tracking-wider">
              Verification Verdict:{" "}
              <span className="font-bold">{workflow.verification_verdict.replace("_", " ")}</span>
            </p>
            <button
              type="button"
              disabled={verifying}
              onClick={() => setShowModal(true)}
              className="text-xs font-medium text-[var(--accent)] underline hover:opacity-80"
            >
              Re-verify
            </button>
          </div>

          {workflow.verdict_rationale ? (
            <p className="text-xs leading-relaxed text-[var(--text)]/90">
              {workflow.verdict_rationale}
            </p>
          ) : null}

          {/* Coverage & Risk Delta */}
          <div className="grid gap-2 text-xs sm:grid-cols-2">
            <div className="rounded border border-white/[0.06] bg-black/20 p-2">
              <span className="text-[var(--muted)]">Coverage Equivalence:</span>{" "}
              <span className="mono font-medium">
                {workflow.verifications[0]?.coverage_equivalent ? "Equivalent (Evaluated)" : "Inconclusive"}
              </span>
            </div>
            {workflow.verifications[0]?.risk_delta ? (
              <div className="rounded border border-white/[0.06] bg-black/20 p-2">
                <span className="text-[var(--muted)]">Risk Score Impact:</span>{" "}
                <span className="mono font-medium">
                  {workflow.verifications[0].risk_delta.baseline_score ?? "—"} →{" "}
                  {workflow.verifications[0].risk_delta.verification_score ?? "0"}
                  {workflow.verifications[0].risk_delta.delta !== null ? (
                    <span className="text-[var(--ok)]">
                      {" "}
                      ({workflow.verifications[0].risk_delta.delta > 0 ? "+" : ""}
                      {workflow.verifications[0].risk_delta.delta})
                    </span>
                  ) : null}
                </span>
              </div>
            ) : null}
          </div>

          <div className="pt-1">
            <button
              type="button"
              onClick={() => setShowComparison(!showComparison)}
              className="text-xs text-[var(--accent)] underline"
            >
              {showComparison ? "Hide before/after details" : "View before/after comparison details"}
            </button>
          </div>

          {showComparison && comparison ? (
            <div className="mt-2 space-y-2 rounded border border-white/10 bg-black/40 p-2.5 text-xs">
              <p className="font-semibold text-[var(--text)]">Comparison Traceability</p>
              <div className="grid gap-2 sm:grid-cols-2">
                <div>
                  <p className="text-[var(--muted)]">Baseline Run ({comparison.baseline.target})</p>
                  <p className="mono">ID: {comparison.baseline.assessment_id.slice(0, 8)}</p>
                  <p>Severity: {comparison.baseline.finding?.severity ?? "Not recorded"}</p>
                </div>
                <div>
                  <p className="text-[var(--muted)]">Verification Run</p>
                  <p className="mono">ID: {comparison.verification?.assessment_id.slice(0, 8) ?? "—"}</p>
                  <p>
                    Finding detected:{" "}
                    {comparison.verification?.finding_found ? "YES (Still present)" : "NO (Resolved)"}
                  </p>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      ) : null}

      {/* Verification Confirmation Modal */}
      {showModal ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
          <div className="surface-panel w-full max-w-md space-y-4 rounded-2xl border border-white/10 p-5 shadow-2xl">
            <div className="space-y-1">
              <h3 className="font-display text-base font-semibold text-[var(--text)]">
                Explicit Verification Approval
              </h3>
              <p className="text-xs text-[var(--muted)]">
                You are about to launch an authorized security assessment to verify remediation.
              </p>
            </div>

            <dl className="space-y-1.5 rounded-xl border border-white/[0.08] bg-white/[0.02] p-3 text-xs">
              <div className="flex justify-between">
                <dt className="text-[var(--muted)]">Target Asset:</dt>
                <dd className="mono font-semibold">{finding.target}:{finding.port ?? "any"}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-[var(--muted)]">Baseline Finding:</dt>
                <dd className="mono font-semibold">{finding.finding_id} ({finding.severity})</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-[var(--muted)]">Check to Execute:</dt>
                <dd className="mono">Equivalent authorized active probe</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-[var(--muted)]">Allowed Target Scope:</dt>
                <dd className="mono text-[var(--ok)]">Allowlisted lab host only</dd>
              </div>
            </dl>

            <p className="rounded-lg border border-[var(--warn)]/30 bg-[var(--warn)]/10 p-2.5 text-xs text-[var(--warn)]">
              ⚠ The scanner will recheck the target port. Ensure the service has been restarted with your new configuration before proceeding.
            </p>

            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => setShowModal(false)}
                className="btn-soft rounded-lg border border-white/10 px-3 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)]"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleStartVerification}
                data-btn-confirm-verify=""
                className="btn-soft rounded-lg border border-[var(--accent)] bg-[var(--accent)] px-3.5 py-1.5 text-xs font-semibold text-black hover:opacity-90"
              >
                Confirm & Run Verification Check
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

