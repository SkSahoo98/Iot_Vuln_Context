import { useRef, useState, type FormEvent } from "react";
import { createAssessment } from "../../api/assessments";
import type { AssessmentDetail } from "../../api/types";
import { ErrorState } from "../common/ErrorState";

interface NewAssessmentFormProps {
  onCreated: (assessment: AssessmentDetail) => void;
  /** Prefills the target field; the backend still enforces its allowlist. */
  initialTarget?: string;
}

export function NewAssessmentForm({ onCreated, initialTarget }: NewAssessmentFormProps) {
  const [target, setTarget] = useState(initialTarget ?? "");
  const [submitting, setSubmitting] = useState(false);
  const [submittingMode, setSubmittingMode] = useState<"single" | "environment" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AssessmentDetail | null>(null);
  const submittingRef = useRef(false);

  const trimmedTarget = target.trim();

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submittingRef.current) return;
    if (!trimmedTarget) {
      setError("Target is required.");
      return;
    }

    submittingRef.current = true;
    setSubmitting(true);
    setSubmittingMode("single");
    setError(null);
    setResult(null);

    try {
      const assessment = await createAssessment(trimmedTarget);
      setResult(assessment);
      onCreated(assessment);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "Failed to run assessment",
      );
    } finally {
      submittingRef.current = false;
      setSubmitting(false);
      setSubmittingMode(null);
    }
  }

  async function handleRunFullAssessment() {
    if (submittingRef.current) return;
    submittingRef.current = true;
    setSubmitting(true);
    setSubmittingMode("environment");
    setError(null);
    setResult(null);

    try {
      const assessment = await createAssessment({ scope: "AUTHORIZED_IOT" });
      setResult(assessment);
      onCreated(assessment);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "Failed to run full environment assessment",
      );
    } finally {
      submittingRef.current = false;
      setSubmitting(false);
      setSubmittingMode(null);
    }
  }

  const completed = result?.status === "COMPLETE";

  return (
    <section className="surface-panel space-y-5 rounded-2xl px-5 py-5">
      <div>
        <h2 className="text-base font-semibold text-[var(--text)]">
          New security check
        </h2>
        <p className="mt-1 text-sm text-[var(--muted)]">
          The backend verifies that targets are authorized and runs its
          configured deterministic checks.
        </p>
      </div>

      <div className="rounded-xl border border-[var(--accent)]/30 bg-[var(--accent)]/[0.04] p-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-[var(--text)]">
              Authorized IoT Environment
            </h3>
            <p className="mt-0.5 text-xs text-[var(--muted)]">
              Assesses all explicitly authorized IoT devices (ESP32-01: 10.32.252.105, ESP32-02: 10.32.252.57) and infrastructure (MQTT Broker: 10.32.252.85) independently and compiles the overall security posture.
            </p>
          </div>
          <button
            type="button"
            onClick={handleRunFullAssessment}
            disabled={submitting}
            aria-busy={submitting && submittingMode === "environment"}
            className="btn-soft inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-full border border-[var(--accent)]/50 bg-[var(--accent-soft)] px-5 text-sm font-semibold text-[var(--accent)] hover:bg-[var(--accent)]/25 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {submitting && submittingMode === "environment" ? (
              <span
                className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-[var(--accent)]/25 border-t-[var(--accent)]"
                aria-hidden
              />
            ) : null}
            {submitting && submittingMode === "environment"
              ? "Assessing environment..."
              : "Run Full Assessment"}
          </button>
        </div>
      </div>

      <div className="relative flex items-center justify-center">
        <div className="w-full border-t border-white/[0.08]" />
        <span className="absolute bg-[var(--panel)] px-3 text-[11px] font-medium uppercase tracking-[0.1em] text-[var(--muted)]">
          or assess single device
        </span>
      </div>

      <form
        onSubmit={handleSubmit}
        className="flex flex-col gap-3 sm:flex-row sm:items-end"
        noValidate
      >
        <div className="min-w-0 flex-1">
          <label
            htmlFor="assessment-target"
            className="mb-1.5 block text-[11px] font-medium uppercase tracking-[0.1em] text-[var(--muted)]"
          >
            Target
          </label>
          <input
            id="assessment-target"
            type="text"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            disabled={submitting}
            placeholder="IP address or hostname"
            autoComplete="off"
            spellCheck={false}
            aria-invalid={error === "Target is required." ? true : undefined}
            className="glass-inset mono w-full rounded-xl px-3.5 py-2.5 text-sm text-[var(--text)] placeholder:text-[var(--muted)]/70 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]/50 disabled:cursor-not-allowed disabled:opacity-60"
          />
        </div>
        <button
          type="submit"
          disabled={submitting}
          aria-busy={submitting && submittingMode === "single"}
          className="btn-soft inline-flex min-h-11 items-center justify-center gap-2 rounded-full border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-5 text-sm font-medium text-[var(--accent)] hover:bg-[var(--accent)]/20 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {submitting && submittingMode === "single" ? (
            <span
              className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-[var(--accent)]/25 border-t-[var(--accent)]"
              aria-hidden
            />
          ) : null}
          {submitting && submittingMode === "single" ? "Running assessment..." : "Run Assessment"}
        </button>
      </form>

      <div aria-live="polite">
        {submitting ? (
          <p className="text-sm text-[var(--muted)]">
            {submittingMode === "environment"
              ? "Running environment assessment against all authorized IoT devices. This can take several seconds."
              : (
                <>
                  Running assessment against{" "}
                  <span className="mono text-[var(--text)]">{trimmedTarget}</span>.
                  This can take several seconds.
                </>
              )}
          </p>
        ) : null}

        {error ? <ErrorState message={error} /> : null}

        {result && !submitting ? (
          <div
            className={`rounded-xl border px-4 py-3 text-sm ${
              completed
                ? "border-[var(--ok)]/35 bg-[var(--ok)]/10 text-[var(--ok)]"
                : "border-[var(--warn)]/35 bg-[var(--warn)]/10 text-[var(--warn)]"
            }`}
          >
            <p className="font-medium">
              {completed
                ? "Assessment completed"
                : `Assessment created with status ${result.status}`}{" "}
              for <span className="mono">{result.target}</span>.
            </p>
            {result.error_summary ? (
              <p className="mt-1 text-[var(--muted)]">{result.error_summary}</p>
            ) : null}
          </div>
        ) : null}
      </div>
    </section>
  );
}
