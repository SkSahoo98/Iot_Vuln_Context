import type { Explanation, Finding, RiskItem } from "../../api/types";
import { FindingEvidence } from "../FindingEvidence";
import { Drawer } from "../common/Drawer";
import { SeverityBadge } from "../common/SeverityBadge";
import { RemediationList } from "../RemediationList";

type Props = {
  finding: Finding | null;
  riskItem: RiskItem | null;
  explanation: Explanation | null;
  explanationLoading: boolean;
  open: boolean;
  onClose: () => void;
  onOpenAi: () => void;
};

function SectionTitle({
  children,
  note,
}: {
  children: React.ReactNode;
  note?: string;
}) {
  return (
    <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
      <h3 className="text-[11px] font-medium tracking-[0.12em] text-[var(--muted)] uppercase">
        {children}
      </h3>
      {note ? (
        <span className="text-[11px] text-[var(--muted)]">{note}</span>
      ) : null}
    </div>
  );
}

export function FindingDetailsDrawer({
  finding,
  riskItem,
  explanation,
  explanationLoading,
  open,
  onClose,
  onOpenAi,
}: Props) {
  if (!finding) return null;

  return (
    <Drawer open={open} title={finding.title} onClose={onClose} wide>
      <div className="mb-5 flex flex-wrap items-center gap-2">
        <SeverityBadge severity={finding.severity} />
        {riskItem ? (
          <span className="premium-badge rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-0.5 text-[11px]">
            Authoritative risk:{" "}
            <span className="mono font-semibold">
              {riskItem.score} {riskItem.risk_level}
            </span>
          </span>
        ) : null}
      </div>

      <section className="mb-5">
        <SectionTitle>What was detected?</SectionTitle>
        <p className="text-sm text-[var(--muted)]">{finding.description}</p>
      </section>

      <section className="mb-5">
        <SectionTitle>Why does it matter?</SectionTitle>
        <p className="text-sm text-[var(--muted)]">
          {explanation?.why_it_matters || finding.impact}
        </p>
      </section>

      <section className="mb-5">
        <SectionTitle>Application Evidence (Authoritative)</SectionTitle>
        <FindingEvidence evidence={finding.evidence} />
      </section>

      <section className="mb-5">
        <SectionTitle>IoT Context</SectionTitle>
        {riskItem ? (
          <ul className="glass-inset space-y-1 rounded-2xl px-3.5 py-2">
            {Object.entries(riskItem.factors).map(([key, value]) => (
              <li
                key={key}
                className="flex justify-between gap-3 border-b border-white/[0.05] py-2 text-sm last:border-b-0"
              >
                <span className="text-[var(--muted)]">
                  {key.split("_").join(" ")}
                </span>
                <span className="mono text-[var(--text)]">{value}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-[var(--muted)]">
            {explanation?.iot_context || "Not available"}
          </p>
        )}
      </section>

      <section className="mb-5 glass-inset relative overflow-hidden rounded-2xl p-4">
        <div
          className="pointer-events-none absolute -right-8 -top-10 h-28 w-28 rounded-full bg-[var(--accent)]/15 blur-2xl"
          aria-hidden
        />
        <SectionTitle>Authoritative risk</SectionTitle>
        <p className="relative mono text-3xl font-semibold">
          {riskItem?.score ?? "—"}
        </p>
        <p className="relative mt-1 text-sm">{riskItem?.risk_level ?? "Not available"}</p>
        <p className="relative mt-1 mono text-xs text-[var(--muted)]">
          {riskItem?.score_version ?? "—"}
        </p>
      </section>

      <section className="mb-5">
        <SectionTitle>Potential Impact</SectionTitle>
        <p className="text-sm text-[var(--muted)]">
          {explanation?.potential_impact || finding.impact}
        </p>
      </section>

      <section className="mb-5">
        <SectionTitle note="Potential scenario — not an observed attack">
          Potential Attack Scenario
        </SectionTitle>
        <p className="text-sm text-[var(--muted)]">
          {explanationLoading
            ? "Loading explanation…"
            : explanation?.attack_scenario ||
              "Open AI Analysis for a full evidence-grounded scenario."}
        </p>
      </section>

      <section className="mb-5">
        <SectionTitle>Recommended Remediation</SectionTitle>
        {explanation?.remediation?.length ? (
          <RemediationList items={explanation.remediation} />
        ) : (
          <p className="text-sm text-[var(--muted)]">{finding.recommendation}</p>
        )}
      </section>

      <section className="glass-inset rounded-2xl p-4">
        <SectionTitle>AI Analysis</SectionTitle>
        <p className="text-sm text-[var(--muted)]">
          {explanation?.summary ||
            "View the full evidence-grounded AI explanation."}
        </p>
        <button
          type="button"
          onClick={onOpenAi}
          className="btn-soft mt-3 rounded-full border border-[var(--accent)]/40 bg-[var(--accent-soft)] px-3.5 py-1.5 text-xs font-medium text-[var(--accent)] hover:bg-[var(--accent)]/20"
        >
          Open AI Analysis
        </button>
      </section>
    </Drawer>
  );
}
