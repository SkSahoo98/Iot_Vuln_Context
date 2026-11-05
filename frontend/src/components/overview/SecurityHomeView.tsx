import type { ReactNode } from "react";
import type { NavRequest } from "../../lib/navigation";
import type { AssessmentSummary, EnvironmentPosture } from "../../api/types";
import { formatGeneratedAt, severityTone } from "../../lib/format";
import { pluralize, type HomeState, type IssueSummary } from "../../lib/securityHome";
import { resolveAssetIdentity } from "../../lib/assets";
import { formatNumber } from "../assessments/detailFormat";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { IssueCard } from "./IssueCard";

export type IssuesState =
  | { status: "loading" }
  | { status: "error"; message: string; onRetry: () => void }
  | { status: "ready"; summary: IssueSummary };

export type DeviceContext = { total: number; online: number };

type Props = {
  state: HomeState;
  issues: IssuesState | null;
  deviceContext: DeviceContext | null;
  onCheckSecurity: (assessmentId: string | null) => void;
  onShowDetails: (assessmentId: string) => void;
  isReadOnly?: boolean;
  onNavigate?: (request: NavRequest) => void;
};

const HEADLINE_TONE: Record<ReturnType<typeof severityTone>, string> = {
  danger: "text-[var(--danger)]",
  warn: "text-[var(--warn)]",
  ok: "text-[var(--ok)]",
  default: "text-[var(--text)]",
};

const primaryButton =
  "btn-soft inline-flex min-h-11 items-center justify-center rounded-full border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-5 text-sm font-medium text-[var(--accent)] hover:bg-[var(--accent)]/20";
const secondaryButton =
  "btn-soft inline-flex min-h-11 items-center justify-center rounded-full border border-white/10 bg-white/[0.04] px-5 text-sm font-medium text-[var(--text)] hover:border-[var(--accent)]/35";

function checkedAt(latest: AssessmentSummary): string | null {
  return formatGeneratedAt(latest.completed_at ?? latest.started_at);
}

function Facts({ items }: { items: (ReactNode | null)[] }) {
  const shown = items.filter(Boolean);
  if (!shown.length) return null;
  return (
    <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-sm text-[var(--muted)]">
      {shown.map((item, index) => (
        <li key={index} className="min-w-0 break-words">
          {item}
        </li>
      ))}
    </ul>
  );
}

function Headline({ children }: { children: ReactNode }) {
  return (
    <h2 className="font-display mt-1 break-words text-2xl font-semibold leading-tight tracking-tight text-[var(--text)] sm:text-3xl">
      {children}
    </h2>
  );
}

function StatusSurface({
  state,
  issues,
  onShowDetails,
}: {
  state: HomeState;
  issues: IssuesState | null;
  onShowDetails: (id: string) => void;
}) {
  let body: ReactNode;

  if (state.kind === "empty") {
    body = (
      <>
        <Headline>Your network hasn't been checked yet.</Headline>
        <p className="mt-2 text-sm text-[var(--muted)]">
          Run a security check of your authorized IoT target to see its status here.
        </p>
      </>
    );
  } else if (state.kind === "complete") {
    const { latest } = state;
    const posture = (latest.metadata?.posture ?? null) as EnvironmentPosture | null;

    if (posture) {
      const level = posture.overall_risk_level;
      const infraCount =
        posture.infrastructure_assessed ?? (posture.infrastructure_summaries?.length ?? 0);
      const totalAssets =
        posture.assets_assessed ?? (posture.devices_assessed + infraCount);
      body = (
        <div className="space-y-4">
          <div>
            {level ? (
              <Headline>
                Your authorized IoT environment is at{" "}
                <span className={HEADLINE_TONE[severityTone(level)]}>{level}</span> risk.
              </Headline>
            ) : (
              <Headline>Your environment security check finished without an overall risk level.</Headline>
            )}
            <Facts
              items={[
                checkedAt(latest) ? `Last checked ${checkedAt(latest)}` : null,
                <>
                  Scope: <span className="mono text-[var(--text)]">Authorized IoT Environment</span>
                </>,
                posture.overall_risk_score !== null ? (
                  <>
                    Overall risk score{" "}
                    <span className="mono text-[var(--text)]">
                      {formatNumber(posture.overall_risk_score)}
                    </span>{" "}
                    / 100
                  </>
                ) : null,
                <span className="text-[var(--text)]">
                  {totalAssets} {pluralize(totalAssets, "asset")} assessed ({posture.devices_assessed} {pluralize(posture.devices_assessed, "device")}, {infraCount} infrastructure)
                </span>,
                <span className="text-[var(--text)]">
                  {posture.devices_completed} of {posture.devices_assessed} devices completed
                  {posture.devices_failed > 0 ? ` (${posture.devices_failed} failed)` : ""}
                </span>,
                posture.important_findings > 0 ? (
                  <span className="text-[var(--danger)]">
                    {pluralize(posture.important_findings, "important issue")}
                  </span>
                ) : null,
                posture.additional_findings > 0 ? (
                  <span className="text-[var(--muted)]">
                    {pluralize(posture.additional_findings, "additional finding")}
                  </span>
                ) : null,
              ]}
            />
          </div>

          {/* IoT Devices Section */}
          <div className="pt-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)] mb-2">
              IoT Devices ({posture.devices_assessed})
            </h3>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {posture.device_summaries.map((dev) => {
                const devIdentity = resolveAssetIdentity(dev.device_id);
                return (
                  <div
                    key={dev.device_id}
                    className="surface-card flex flex-col justify-between rounded-xl border border-white/[0.08] p-3.5 bg-white/[0.02]"
                  >
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-sm text-[var(--text)]">{devIdentity.displayName}</span>
                        <span
                          className={`text-[11px] font-semibold uppercase px-2 py-0.5 rounded-full ${
                            dev.status === "COMPLETE"
                              ? "bg-[var(--ok)]/15 text-[var(--ok)]"
                              : "bg-[var(--danger)]/15 text-[var(--danger)]"
                          }`}
                        >
                          {dev.status}
                        </span>
                      </div>
                      <div className="mt-1 flex items-center gap-2 text-xs text-[var(--muted)]">
                        <span className="mono font-medium text-[var(--text)]/80">{dev.device_id}</span>
                        <span>•</span>
                        <span className="mono">{dev.ip_address}</span>
                        <span>•</span>
                        <span>{dev.device_type}</span>
                      </div>
                      <div className="mt-3 flex items-center justify-between text-xs">
                        <span className="text-[var(--muted)]">Risk Level:</span>
                        <span
                          className={`font-semibold ${
                            dev.highest_risk_level
                              ? HEADLINE_TONE[severityTone(dev.highest_risk_level)]
                              : "text-[var(--text)]"
                          }`}
                        >
                          {dev.highest_risk_level ?? "None"}
                          {dev.highest_risk !== null
                            ? ` (${formatNumber(dev.highest_risk)}/100)`
                            : ""}
                        </span>
                      </div>
                      <div className="mt-1 flex items-center justify-between text-xs">
                        <span className="text-[var(--muted)]">Findings:</span>
                        <span className="mono text-[var(--text)]">{dev.findings_count}</span>
                      </div>
                    </div>
                    <div className="mt-3 border-t border-white/[0.06] pt-2">
                      <button
                        type="button"
                        onClick={() => onShowDetails(dev.assessment_id)}
                        className="text-xs text-[var(--accent)] hover:underline inline-flex items-center gap-1 font-medium"
                      >
                        View device assessment details &rarr;
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* IoT Infrastructure Section */}
          {(posture.infrastructure_summaries && posture.infrastructure_summaries.length > 0) && (
            <div className="pt-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)] mb-2">
                IoT Infrastructure ({posture.infrastructure_assessed ?? posture.infrastructure_summaries.length})
              </h3>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {posture.infrastructure_summaries.map((infra) => {
                  const infraIdentity = resolveAssetIdentity(infra.asset_id);
                  return (
                    <div
                      key={infra.asset_id}
                      className="surface-card flex flex-col justify-between rounded-xl border border-white/[0.08] p-3.5 bg-white/[0.02]"
                    >
                      <div>
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-sm text-[var(--text)]">{infraIdentity.displayName}</span>
                          <span
                            className={`text-[11px] font-semibold uppercase px-2 py-0.5 rounded-full ${
                              infra.status === "COMPLETE"
                                ? "bg-[var(--ok)]/15 text-[var(--ok)]"
                                : "bg-[var(--danger)]/15 text-[var(--danger)]"
                            }`}
                          >
                            {infra.status}
                          </span>
                        </div>
                        <div className="mt-1 flex items-center gap-2 text-xs text-[var(--muted)]">
                          <span className="mono font-medium text-[var(--text)]/80">{infra.asset_id}</span>
                          <span>•</span>
                          <span className="mono">{infra.ip_address}</span>
                          <span>•</span>
                          <span>{infra.asset_type}</span>
                        </div>
                        <div className="mt-3 flex items-center justify-between text-xs">
                          <span className="text-[var(--muted)]">Risk Level:</span>
                          <span
                            className={`font-semibold ${
                              infra.highest_risk_level
                                ? HEADLINE_TONE[severityTone(infra.highest_risk_level)]
                                : "text-[var(--text)]"
                            }`}
                          >
                            {infra.highest_risk_level ?? "None"}
                            {infra.highest_risk !== null
                              ? ` (${formatNumber(infra.highest_risk)}/100)`
                              : ""}
                          </span>
                        </div>
                        <div className="mt-1 flex items-center justify-between text-xs">
                          <span className="text-[var(--muted)]">Findings:</span>
                          <span className="mono text-[var(--text)]">{infra.findings_count}</span>
                        </div>
                      </div>
                      <div className="mt-3 border-t border-white/[0.06] pt-2">
                        <button
                          type="button"
                          onClick={() => onShowDetails(infra.assessment_id)}
                          className="text-xs text-[var(--accent)] hover:underline inline-flex items-center gap-1 font-medium"
                        >
                          View infrastructure assessment details &rarr;
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <p className="mt-3 text-xs text-[var(--muted)]">
            Based on independent assessments of explicitly authorized IoT devices and infrastructure.
          </p>
        </div>
      );
    } else {
      const level = latest.highest_risk_level;
      const importantCount =
        issues?.status === "ready" ? issues.summary.important.length : null;
      body = (
        <>
          {level ? (
            <Headline>
              Your authorized IoT target is at{" "}
              <span className={HEADLINE_TONE[severityTone(level)]}>{level}</span> risk.
            </Headline>
          ) : (
            <Headline>Your latest security check finished without an overall risk level.</Headline>
          )}
          <Facts
            items={[
              checkedAt(latest) ? `Last checked ${checkedAt(latest)}` : null,
              <>
                Target: <span className="mono text-[var(--text)]">{latest.target}</span>
              </>,
              latest.highest_risk !== null ? (
                <>
                  Risk score{" "}
                  <span className="mono text-[var(--text)]">
                    {formatNumber(latest.highest_risk)}
                  </span>{" "}
                  / 100
                </>
              ) : null,
              importantCount !== null ? (
                <span className="text-[var(--text)]">
                  {pluralize(importantCount, "important issue")}
                </span>
              ) : null,
            ]}
          />
          <p className="mt-3 text-xs text-[var(--muted)]">
            Based on the checks configured for this authorized target only.
          </p>
        </>
      );
    }
  } else {
    const { latest } = state;
    const headline =
      state.kind === "incomplete"
        ? "I could only partially check your authorized target."
        : state.kind === "failed"
          ? "The security check failed."
          : "Your latest security check hasn't finished.";
    const tone =
      state.kind === "failed"
        ? "border-[var(--danger)]/30 bg-[var(--danger)]/[0.07]"
        : "border-[var(--warn)]/30 bg-[var(--warn)]/[0.07]";
    body = (
      <>
        <Headline>{headline}</Headline>
        <Facts
          items={[
            formatGeneratedAt(latest.started_at)
              ? `Started ${formatGeneratedAt(latest.started_at)}`
              : null,
            <>
              Target: <span className="mono text-[var(--text)]">{latest.target}</span>
            </>,
          ]}
        />
        {latest.error_summary ? (
          <div className={`mt-4 rounded-xl border px-4 py-3 text-sm ${tone}`}>
            <p className="text-[11px] font-medium uppercase tracking-[0.1em] text-[var(--muted)]">
              Reported by the assessment engine
            </p>
            <p className="mt-1 break-words text-[var(--text)]">{latest.error_summary}</p>
          </div>
        ) : null}
        <p className="mt-3 text-sm text-[var(--muted)]">
          No current risk level is shown because this check did not complete.
        </p>
      </>
    );
  }

  return (
    <section
      aria-labelledby="security-status-heading"
      className="surface-panel rounded-2xl px-5 py-5 sm:px-6 sm:py-6"
    >
      <p
        id="security-status-heading"
        className="text-[11px] font-medium uppercase tracking-[0.14em] text-[var(--muted)]"
      >
        Security status
      </p>
      {body}
    </section>
  );
}

function IssuesSection({ issues }: { issues: IssuesState }) {
  let body: ReactNode;
  if (issues.status === "loading") {
    body = <LoadingState message="Loading the issues from your latest assessment…" />;
  } else if (issues.status === "error") {
    body = (
      <ErrorState
        message={`Couldn't load the issues from your latest assessment. ${issues.message}`}
        onRetry={issues.onRetry}
      />
    );
  } else {
    const { important, minor, observationCount } = issues.summary;
    body = (
      <div className="space-y-3">
        {important.length ? (
          <ul className="space-y-3">
            {important.map((issue) => (
              <IssueCard key={issue.key} issue={issue} />
            ))}
          </ul>
        ) : (
          <p className="text-sm text-[var(--muted)]">
            No important issues were reported in the latest check.
          </p>
        )}

        {minor.length ? (
          <details className="rounded-xl border border-white/[0.06] bg-white/[0.02]">
            <summary className="flex min-h-11 cursor-pointer items-center px-4 text-sm font-medium text-[var(--muted)] hover:text-[var(--text)]">
              Show {pluralize(minor.length, "minor issue")}
            </summary>
            <ul className="space-y-3 border-t border-white/[0.06] p-3">
              {minor.map((issue) => (
                <IssueCard key={issue.key} issue={issue} />
              ))}
            </ul>
          </details>
        ) : null}

        {observationCount ? (
          <p className="text-xs text-[var(--muted)]">
            {pluralize(observationCount, "informational observation")} recorded.
            They are listed in the technical details.
          </p>
        ) : null}
      </div>
    );
  }

  return (
    <section
      id="security-issues"
      aria-labelledby="security-issues-heading"
      className="scroll-mt-24 space-y-3"
    >
      <h2 id="security-issues-heading" className="font-display text-base font-semibold">
        What needs attention
      </h2>
      {body}
    </section>
  );
}

function ActionsSection({
  state,
  onCheckSecurity,
  onShowDetails,
  isReadOnly = false,
  onNavigate,
}: Pick<Props, "state" | "onCheckSecurity" | "onShowDetails" | "isReadOnly" | "onNavigate">) {
  const latestId = state.kind === "empty" ? null : state.latest.id;

  if (isReadOnly) {
    return (
      <section aria-labelledby="security-actions-heading" className="space-y-3">
        <h2 id="security-actions-heading" className="font-display text-base font-semibold">
          What you can explore
        </h2>
        <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
          <button
            type="button"
            onClick={() => onCheckSecurity(latestId)}
            className={primaryButton}
          >
            View Security History
          </button>
          {onNavigate ? (
            <button
              type="button"
              onClick={() => onNavigate({ section: "devices" })}
              className={secondaryButton}
            >
              View IoT Devices
            </button>
          ) : null}
          {latestId ? (
            <button
              type="button"
              onClick={() => onShowDetails(latestId)}
              className={secondaryButton}
            >
              Show technical details
            </button>
          ) : null}
          {onNavigate ? (
            <button
              type="button"
              onClick={() => onNavigate({ section: "assistant" })}
              className={secondaryButton}
            >
              Ask AI Assistant
            </button>
          ) : null}
        </div>
        <p className="text-xs text-[var(--muted)]">
          Cloud Read-Only Mode: Live telemetry is actively monitored. Active scans run only through the local laboratory environment.
        </p>
      </section>
    );
  }
  const primaryLabel =
    state.kind === "empty"
      ? "Check security"
      : state.kind === "complete"
        ? "Check again"
        : "Run another check";

  return (
    <section aria-labelledby="security-actions-heading" className="space-y-3">
      <h2 id="security-actions-heading" className="font-display text-base font-semibold">
        What you can do next
      </h2>
      <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
        <button
          type="button"
          onClick={() => onCheckSecurity(latestId)}
          className={primaryButton}
        >
          {primaryLabel}
        </button>
        {latestId ? (
          <button
            type="button"
            onClick={() => onShowDetails(latestId)}
            className={secondaryButton}
          >
            Show technical details
          </button>
        ) : null}
      </div>
      <p className="text-xs text-[var(--muted)]">
        {state.kind === "complete"
          ? "Checks run from History and only against authorized targets."
          : "Opens History, where checks run against authorized targets only."}
      </p>
    </section>
  );
}

export function SecurityHomeView({
  state,
  issues,
  deviceContext,
  onCheckSecurity,
  onShowDetails,
  isReadOnly = false,
  onNavigate,
}: Props) {
  const latest = state.kind === "empty" ? null : state.latest;
  const posture = (latest?.metadata?.posture ?? null) as EnvironmentPosture | null;
  const infraCount =
    posture?.infrastructure_assessed ?? (posture?.infrastructure_summaries?.length ?? 0);
  const totalAssets = posture
    ? (posture.assets_assessed ?? (posture.devices_assessed + infraCount))
    : 0;

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-4 text-xs text-[var(--muted)]">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="font-semibold text-[var(--text)]">{isReadOnly ? "Monitored Targets:" : "Authorized Targets:"}</span>
            {posture ? (
              <>
                <span className="mono">
                  {posture.device_summaries.map((d) => `${resolveAssetIdentity(d.device_id).displayName} (${d.ip_address})`).join(", ")}
                </span>
                {infraCount > 0 ? (
                  <>
                    <span>•</span>
                    <span className="font-semibold text-[var(--text)]">Infrastructure:</span>
                    <span className="mono">
                      {(posture.infrastructure_summaries ?? []).map((i) => `${resolveAssetIdentity(i.asset_id).displayName} (${i.ip_address})`).join(", ")}
                    </span>
                  </>
                ) : null}
              </>
            ) : latest ? (
              <span className="mono">
                {resolveAssetIdentity(latest.target).displayName !== "Unknown asset"
                  ? `${resolveAssetIdentity(latest.target).displayName} (${latest.target})`
                  : latest.target}
              </span>
            ) : (
              <span className="mono">Allowlisted IoT targets</span>
            )}
          </div>
          <div className="text-[11px] text-[var(--muted)]">
            {posture ? (
              <span>
                {totalAssets} {pluralize(totalAssets, "asset")} assessed ({posture.devices_assessed} {pluralize(posture.devices_assessed, "device")}, {infraCount} infrastructure)
              </span>
            ) : (
              <span>Explicit allowlist verification</span>
            )}
          </div>
        </div>
      </div>

      <StatusSurface state={state} issues={issues} onShowDetails={onShowDetails} />
      {state.kind === "complete" && issues ? <IssuesSection issues={issues} /> : null}
      <ActionsSection
        state={state}
        onCheckSecurity={onCheckSecurity}
        onShowDetails={onShowDetails}
        isReadOnly={isReadOnly}
        onNavigate={onNavigate}
      />
      {deviceContext && deviceContext.total > 0 ? (
        <p className="border-t border-white/[0.06] pt-4 text-xs text-[var(--muted)]">
          Device telemetry: {deviceContext.online} of{" "}
          {pluralize(deviceContext.total, "registered device")} online. Telemetry is
          not part of the security check.
        </p>
      ) : null}
    </div>
  );
}
