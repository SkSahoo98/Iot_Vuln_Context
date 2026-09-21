import { useEffect } from "react";

type Props = {
  open: boolean;
  onClose: () => void;
  apiOnline: boolean | null;
  mqttAvailable: boolean;
  aiLabel: string;
  aiOk: boolean | null;
  riskModel: string | null;
};

function Row({
  label,
  value,
  ok,
  delay,
}: {
  label: string;
  value: string;
  ok: boolean | null;
  delay: number;
}) {
  const tone =
    ok === true ? "ok" : ok === false ? "danger" : "neutral";

  return (
    <div
      className={`status-row animate-rise-in stagger-${delay}`}
      data-tone={tone}
    >
      <div className="flex items-center gap-3">
        <span className={`status-row__dot ${ok === true ? "status-pulse" : ""}`} />
        <span className="text-sm text-[var(--muted)]">{label}</span>
      </div>
      <span className="text-sm font-medium text-[var(--text)]">{value}</span>
    </div>
  );
}

export function SystemStatusModal({
  open,
  onClose,
  apiOnline,
  mqttAvailable,
  aiLabel,
  aiOk,
  riskModel,
}: Props) {
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-end p-4 pt-16 sm:p-5 sm:pt-20">
      <button
        type="button"
        className="absolute inset-0 bg-black/45 backdrop-blur-[4px] animate-fade-in"
        aria-label="Close status modal"
        onClick={onClose}
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="System Status"
        className="glass-popover relative w-full max-w-sm animate-modal-in"
      >
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <p className="text-[10px] font-medium tracking-[0.16em] text-[var(--muted)] uppercase">
              Live checks
            </p>
            <h2 className="font-display mt-0.5 text-base font-semibold">
              System Status
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="premium-close"
            aria-label="Close"
          >
            <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="none" aria-hidden>
              <path
                d="M6 6l12 12M18 6 6 18"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
              />
            </svg>
          </button>
        </div>

        <div className="space-y-2">
          <Row
            label="API"
            value={
              apiOnline === null
                ? "Checking…"
                : apiOnline
                  ? "Available"
                  : "Unavailable"
            }
            ok={apiOnline}
            delay={1}
          />
          <Row
            label="MQTT Evidence"
            value={mqttAvailable ? "Available" : "Not available"}
            ok={mqttAvailable ? true : apiOnline === false ? false : null}
            delay={2}
          />
          <Row label="AI / Ollama" value={aiLabel} ok={aiOk} delay={3} />
          <Row
            label="Risk Engine"
            value={riskModel ?? "Not available"}
            ok={riskModel ? true : null}
            delay={4}
          />
        </div>
      </div>
    </div>
  );
}
