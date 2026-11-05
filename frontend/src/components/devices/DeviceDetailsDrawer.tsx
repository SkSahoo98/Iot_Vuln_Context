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
  isReadOnly?: boolean;
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
  isReadOnly = false,
}: Props) {
  if (!device) return null;

  const telemetry = device.latest_telemetry;
  const telemetrySummary = formatTelemetrySummary(telemetry);
  const status = (device.status || "UNKNOWN").toUpperCase();
  const statusTone =
    status === "ONLINE" ? "ok" : status === "OFFLINE" ? "danger" : "neutral";

  const authLabel = isReadOnly
    ? device.is_authorized
      ? "Authorized for Assessment"
      : status === "ONLINE"
        ? "Monitoring Only (Cloud Restricted)"
        : "Assessment Restricted"
    : device.is_authorized
      ? "Authorized for Assessment"
      : "Assessment Restricted";

  const displayIp = isReadOnly
    ? "Private Laboratory LAN"
    : displayOrNotRecorded(device.ip_address);

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
          <InfoRow label="IP Address" value={displayIp} />
          <InfoRow
            label="MAC Address"
            value={displayOrNotRecorded(device.mac_address)}
          />
          <InfoRow
            label="Firmware"
            value={displayOrNotRecorded(device.firmware_version)}
          />
          <InfoRow label="Status" value={status} />
          <InfoRow label="Assessment" value={authLabel} />
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
        <SectionTitle>Security & Assessment Context</SectionTitle>
        <div className="glass-inset rounded-2xl px-3.5 py-3">
          <p className="text-sm text-[var(--muted)]">
            {isReadOnly
              ? "This device streams live telemetry to the cloud monitoring platform. Active vulnerability assessments are restricted to the local laboratory environment."
              : device.is_authorized
                ? "This device is explicitly authorized for security assessments and vulnerability probing in the local cybersecurity lab."
                : "This device is not included in the current assessment target allowlist. Update ASSESSMENT_ALLOWED_TARGETS to enable scanning."}
          </p>
        </div>
      </section>
    </Drawer>
  );
}
