import { useEffect, useRef, useState } from "react";
import type { AssessmentSummary, Device, EnvironmentPosture } from "../../api/types";
import { formatNumber } from "./detailFormat";
import { severityTone } from "../../lib/format";
import { selectLatestAssessment } from "../../lib/securityHome";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { KpiCard } from "../common/KpiCard";
import { LoadingState } from "../common/LoadingState";
import { AssessmentComparison } from "./AssessmentComparison";
import { AssessmentDetails } from "./AssessmentDetails";
import { AssessmentList } from "./AssessmentList";
import { LabAssetsSection } from "./LabAssetsSection";
import { NewAssessmentForm } from "./NewAssessmentForm";
import type { ReassessmentPair } from "./reassessment";
import type { NavAnchor } from "../../lib/navigation";

interface AssessmentsPageProps {
  assessments: AssessmentSummary[] | null;
  loading: boolean;
  error: string | null;
  selectedAssessmentId: string | null;
  onSelectAssessment: (assessmentId: string) => void;
  onRefresh: () => void;
  /** Opens the comparison view with this pair preselected. */
  initialComparison?: ReassessmentPair;
  onScrollTo?: (anchor: NavAnchor) => void;
  onOpenResearch?: () => void;
  isReadOnly?: boolean;
  activeAssessmentSupported?: boolean;
  devices?: Device[] | null;
}

type AssessmentView = "history" | "compare";

type ComparisonPreset = ReassessmentPair & { key: number };

const VIEWS: { id: AssessmentView; label: string }[] = [
  { id: "history", label: "Checks & details" },
  { id: "compare", label: "Compare checks" },
];

export function AssessmentsPage({
  assessments,
  loading,
  error,
  selectedAssessmentId,
  onSelectAssessment,
  onRefresh,
  initialComparison,
  onScrollTo,
  onOpenResearch,
  isReadOnly = false,
  activeAssessmentSupported = true,
  devices = null,
}: AssessmentsPageProps) {
  const [view, setView] = useState<AssessmentView>(
    initialComparison ? "compare" : "history",
  );
  const [comparisonPreset, setComparisonPreset] = useState<ComparisonPreset | null>(
    initialComparison ? { ...initialComparison, key: 1 } : null,
  );
  const [showCheckForm, setShowCheckForm] = useState(false);
  const presetCounter = useRef(initialComparison ? 1 : 0);

  const latestAssessment = selectLatestAssessment(assessments ?? []);
  const latestComplete = (assessments ?? []).find(
    (a) => a.status === "COMPLETE",
  );
  const lastTarget = latestAssessment?.target;

  useEffect(() => {
    if (!selectedAssessmentId && assessments?.length) {
      const demoOrLatest =
        assessments.find((a) => a.id === "a921b260-f51d-4f16-9b9f-9acc11decc26") ??
        latestComplete ??
        latestAssessment;
      if (demoOrLatest) {
        onSelectAssessment(demoOrLatest.id);
      }
    }
  }, [assessments, selectedAssessmentId, latestComplete, latestAssessment, onSelectAssessment]);

  // Deriving Section B overall summary from backend assessment posture / latest
  const posture = (latestComplete?.metadata as Record<string, unknown> | undefined)
    ?.posture as EnvironmentPosture | undefined;

  const securityStatus =
    posture?.overall_risk_level ?? latestComplete?.highest_risk_level ?? null;
  const riskScore =
    posture?.overall_risk_score ?? latestComplete?.highest_risk ?? null;
  const totalFindings =
    posture?.total_findings ?? latestComplete?.finding_count ?? 0;
  const infraCount =
    posture?.infrastructure_assessed ?? (posture?.infrastructure_summaries?.length ?? 0);
  const assessedAssets =
    posture?.assets_assessed ??
    (posture?.devices_assessed ? posture.devices_assessed + infraCount : (latestComplete ? 1 : 0));

  function selectAssessment(assessmentId: string) {
    onSelectAssessment(assessmentId);
    onScrollTo?.({ id: "assessment-details" });
  }

  function openComparison(pair: ReassessmentPair) {
    presetCounter.current += 1;
    setComparisonPreset({ ...pair, key: presetCounter.current });
    setView("compare");
  }

  function handleViewLatest() {
    if (latestAssessment) {
      selectAssessment(latestAssessment.id);
    }
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* View Switcher Tabs */}
      <div
        role="tablist"
        aria-label="Assessment views"
        className="inline-flex flex-wrap gap-1 rounded-full border border-white/10 bg-white/[0.03] p-1"
      >
        {VIEWS.map((item) => {
          const active = view === item.id;
          return (
            <button
              key={item.id}
              type="button"
              role="tab"
              id={`assessment-view-${item.id}`}
              aria-selected={active}
              aria-controls={`assessment-panel-${item.id}`}
              onClick={() => setView(item.id)}
              className={`btn-soft inline-flex min-h-11 items-center rounded-full px-4 text-sm font-medium ${
                active
                  ? "border border-[var(--accent)]/40 bg-[var(--accent-soft)] text-[var(--accent)]"
                  : "border border-transparent text-[var(--muted)] hover:text-[var(--text)]"
              }`}
            >
              {item.label}
            </button>
          );
        })}
      </div>

      <div
        role="tabpanel"
        id="assessment-panel-history"
        aria-labelledby="assessment-view-history"
        hidden={view !== "history"}
        className="space-y-8"
      >
        {/* Mode Posture Banner for Cloud Read-Only Mode */}
        {isReadOnly ? (
          <div className="rounded-2xl border border-sky-500/25 bg-sky-500/[0.06] p-4 text-sm text-[var(--text)] flex items-start gap-3.5">
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-sky-500/15 text-sky-400 text-xs font-bold">
              i
            </span>
            <div className="space-y-1">
              <p className="font-semibold text-sky-300">
                Cloud Read-Only Monitoring Mode
              </p>
              <p className="text-xs text-[var(--muted)] leading-relaxed">
                This public dashboard visualizes live IoT device telemetry and past vulnerability assessment records stored in Neon PostgreSQL. Active network assessment probes are physically air-gapped and restricted to the local cybersecurity laboratory.
              </p>
            </div>
          </div>
        ) : null}

        {/* Section A: Page Header */}
        <section className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-white/[0.06] pb-5">
          <div>
            <h1 className="font-display text-2xl font-bold tracking-tight text-[var(--text)] sm:text-3xl">
              Assessment History
            </h1>
            <p className="mt-1 text-sm text-[var(--muted)] max-w-2xl">
              Review previous security assessments, detected vulnerabilities and
              remediation progress across your IoT environment.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {latestAssessment ? (
              <button
                type="button"
                onClick={handleViewLatest}
                className="btn-soft inline-flex min-h-11 items-center rounded-full border border-white/10 bg-white/[0.04] px-4 text-sm font-medium text-[var(--text)] hover:border-white/20 hover:bg-white/[0.08]"
              >
                View Latest Assessment
              </button>
            ) : null}
            {assessments?.some((a) => a.id === "a921b260-f51d-4f16-9b9f-9acc11decc26") ? (
              <button
                type="button"
                onClick={() => selectAssessment("a921b260-f51d-4f16-9b9f-9acc11decc26")}
                className="btn-soft inline-flex min-h-11 items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/10 px-4 text-sm font-semibold text-amber-300 hover:bg-amber-500/20"
              >
                <span>⭐</span>
                <span>Demo Assessment: MQTT Broker (7 Findings · Risk 70.5)</span>
              </button>
            ) : null}
            {!isReadOnly && activeAssessmentSupported ? (
              <button
                type="button"
                onClick={() => setShowCheckForm((prev) => !prev)}
                className="btn-soft inline-flex min-h-11 items-center rounded-full border border-[var(--accent)]/50 bg-[var(--accent-soft)] px-5 text-sm font-semibold text-[var(--accent)] hover:bg-[var(--accent)]/20"
              >
                {showCheckForm ? "Hide Check Form" : "Run Security Assessment"}
              </button>
            ) : null}
          </div>
        </section>

        {/* Section B: Overall Security Summary */}
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-[var(--text)]">
              Overall Security Summary
            </h2>
            <span className="text-xs text-[var(--muted)]">
              Based on the latest completed assessment
            </span>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <KpiCard
              label="Security Status"
              value={securityStatus ?? "—"}
              secondary={securityStatus ? `${securityStatus} Risk Level` : "No completed run"}
              tone={severityTone(securityStatus)}
              stagger={1}
            />
            <KpiCard
              label="Risk Score"
              value={riskScore !== null ? `${formatNumber(riskScore)}` : "—"}
              secondary={riskScore !== null ? "/ 100 on IoT-RISK-v1" : "Not recorded"}
              tone={severityTone(securityStatus)}
              stagger={2}
            />
            <KpiCard
              label="Total Vulnerabilities"
              value={String(totalFindings)}
              secondary={
                totalFindings === 1
                  ? "1 finding detected"
                  : `${totalFindings} findings detected`
              }
              stagger={3}
            />
            <KpiCard
              label="Assessed Assets"
              value={String(assessedAssets)}
              secondary={
                posture
                  ? `${posture.devices_assessed} devices · ${infraCount} infra`
                  : assessedAssets === 1
                    ? "1 target assessed"
                    : "0 assets assessed"
              }
              stagger={4}
            />
          </div>
        </section>

        {/* Section C: Lab Assets */}
        <LabAssetsSection isReadOnly={isReadOnly} devices={devices} />

        {/* Security Check Form Anchor & Form */}
        <div id="new-security-check" className="scroll-mt-24">
          {isReadOnly || !activeAssessmentSupported ? (
            <NewAssessmentForm
              isReadOnly={isReadOnly}
              activeAssessmentSupported={activeAssessmentSupported}
              onCreated={() => {}}
            />
          ) : (
            <details
              open={showCheckForm}
              onToggle={(e) => setShowCheckForm(e.currentTarget.open)}
              className="rounded-2xl border border-white/[0.08] bg-white/[0.02] p-4 transition-colors"
            >
              <summary className="cursor-pointer text-sm font-semibold text-[var(--accent)] hover:underline list-none flex items-center justify-between">
                <span>Run New Security Assessment</span>
                <span className="text-xs text-[var(--muted)]">{showCheckForm ? "▲ Click to collapse" : "▼ Click to expand"}</span>
              </summary>
              <div className="mt-4">
                <NewAssessmentForm
                  initialTarget={lastTarget}
                  isReadOnly={isReadOnly}
                  activeAssessmentSupported={activeAssessmentSupported}
                  onCreated={(assessment) => {
                    onSelectAssessment(assessment.id);
                    onRefresh();
                    setShowCheckForm(false);
                  }}
                />
              </div>
            </details>
          )}
        </div>

        {/* Section D: Assessment History */}
        <section className="space-y-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <h2 className="text-base font-semibold text-[var(--text)]">
                Security checks
              </h2>
              <p className="mt-1 text-sm text-[var(--muted)]">
                Checks run by the assessment engine, newest first. Select one to see
                its details.
              </p>
            </div>
            <div>
              <button
                type="button"
                onClick={onRefresh}
                disabled={loading}
                className="btn-soft inline-flex min-h-11 items-center rounded-full border border-white/10 bg-white/[0.04] px-4 text-sm font-medium text-slate-300 hover:border-[var(--accent)]/35 hover:text-[var(--accent)] disabled:cursor-wait disabled:opacity-50"
              >
                {loading ? "Refreshing..." : "Refresh"}
              </button>
            </div>
          </div>

          {loading && !assessments ? (
            <LoadingState message="Loading your security checks..." />
          ) : error ? (
            <ErrorState message={error} onRetry={onRefresh} />
          ) : !assessments?.length ? (
            <EmptyState message="No security checks have been run yet." />
          ) : (
            <AssessmentList
              assessments={assessments}
              selectedAssessmentId={selectedAssessmentId}
              onSelect={selectAssessment}
            />
          )}
        </section>

        {/* Selected Assessment Details Section */}
        {selectedAssessmentId ? (
          <div id="assessment-details" className="scroll-mt-24 border-t border-white/[0.08] pt-8">
            <div className="mb-4">
              <span className="text-xs font-semibold uppercase tracking-wider text-[var(--accent)]">
                Viewing Assessment Details
              </span>
            </div>
            <AssessmentDetails
              key={selectedAssessmentId}
              assessmentId={selectedAssessmentId}
              history={assessments}
              onReassessmentCreated={onRefresh}
              onReassessmentComplete={openComparison}
              onOpenAssessment={onSelectAssessment}
              onOpenComparison={openComparison}
              onOpenResearch={onOpenResearch}
              isReadOnly={isReadOnly}
            />
          </div>
        ) : null}
      </div>

      <div
        role="tabpanel"
        id="assessment-panel-compare"
        aria-labelledby="assessment-view-compare"
        hidden={view !== "compare"}
        className="space-y-5"
      >
        <AssessmentComparison
          key={comparisonPreset?.key ?? 0}
          assessments={assessments}
          loading={loading}
          error={error}
          onRefresh={onRefresh}
          initialBeforeId={comparisonPreset?.beforeId}
          initialAfterId={comparisonPreset?.afterId}
        />
      </div>
    </div>
  );
}
