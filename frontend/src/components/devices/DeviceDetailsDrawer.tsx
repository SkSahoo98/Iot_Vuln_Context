import type { Device, Finding } from "../../api/types";
import { displayOrNotRecorded, formatTelemetrySummary } from "../../lib/format";
import { Drawer } from "../common/Drawer";
import { SeverityBadge } from "../common/SeverityBadge";
import { StatusBadge } from "../common/StatusBadge";

type Props = {
  device: Device | null;
  findings: Finding[];
  open: boolean;
  onClose: () => void;
};

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid grid-cols-[7.5rem_1fr] gap-2 border-b border-white/[0.05] py-2.5 text-sm last:border-b-0">
      <dt className="text-[var(--muted)]">{label}</dt>
      <dd className="mono text-[var(--text)]">{value}</dd>
    </div>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="mb-2.5 text-[11px] font-medium tracking-[0.12em] text-[var(--muted)] uppercase">
      {children}
    </h3>
  );
}

export function DeviceDetailsDrawer({
  device,
  findings,
  open,
  onClose,
}: Props) {
  if (!device) return null;

  const telemetry = device.latest_telemetry;
  const telemetrySummary = formatTelemetrySummary(telemetry);
  const status = (device.status || "UNKNOWN").toUpperCase();
  const statusTone =
    status === "ONLINE" ? "ok" : status === "OFFLINE" ? "danger" : "neutral";

  return (
    <Drawer open={open} title={device.device_id} onClose={onClose}>
      <div className="mb-5 flex flex-wrap items-center gap-2">
        <StatusBadge label={status} tone={statusTone} />
        <span className="text-sm text-[var(--muted)]">{device.device_type}</span>
      </div>

      <section className="mb-5">
        <SectionTitle>Device Information</SectionTitle>
        <dl className="glass-inset rounded-2xl px-3.5">
          <InfoRow label="Device ID" value={device.device_id} />
          <InfoRow label="Type" value={device.device_type} />
          <InfoRow
            label="IP"
            value={displayOrNotRecorded(device.ip_address)}
          />
          <InfoRow
            label="MAC"
            value={displayOrNotRecorded(device.mac_address)}
          />
          <InfoRow
            label="Firmware"
            value={displayOrNotRecorded(device.firmware_version)}
          />
          <InfoRow label="Status" value={status} />
        </dl>
      </section>

      <section className="mb-5">
        <SectionTitle>Latest Telemetry</SectionTitle>
        <dl className="glass-inset rounded-2xl px-3.5">
          <InfoRow
            label="Temperature"
            value={
              telemetry
                ? `${telemetry.temperature.toFixed(1)}°C`
                : "No valid telemetry recorded"
            }
          />
          <InfoRow
            label="Humidity"
            value={
              telemetry ? `${telemetry.humidity.toFixed(1)}%` : "No valid telemetry recorded"
            }
          />
          <InfoRow
            label="Last recorded"
            value={telemetrySummary.lastRecorded ?? "No valid telemetry recorded"}
          />
        </dl>
        {!telemetry ? (
          <p className="mt-2 text-xs text-[var(--muted)]">
            No valid telemetry recorded for this device.
          </p>
        ) : status === "OFFLINE" ? (
          <p className="mt-2 text-xs text-[var(--muted)]">
            Device is offline. Showing the last recorded valid reading (not live).
          </p>
        ) : null}
      </section>

      <section className="mb-5">
        <SectionTitle>Security Findings</SectionTitle>
        {findings.length === 0 ? (
          <p className="text-sm text-[var(--muted)]">No findings recorded.</p>
        ) : (
          <ul className="space-y-2">
            {findings.map((finding) => (
              <li
                key={finding.finding_type}
                className="glass-inset rounded-2xl px-3.5 py-3"
              >
                <SeverityBadge severity={finding.severity} />
                <p className="mt-1.5 text-sm font-medium">{finding.title}</p>
                <p className="mt-1 text-xs text-[var(--muted)]">
                  Lab MQTT broker finding (shared environment evidence).
                </p>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <SectionTitle>Security Context</SectionTitle>
        <div className="glass-inset rounded-2xl px-3.5 py-3">
          <p className="text-sm text-[var(--muted)]">
            Device-specific context fields are not recorded on this endpoint.
            IoT context used for risk scoring comes from the risk engine response.
          </p>
        </div>
      </section>
    </Drawer>
  );
}
