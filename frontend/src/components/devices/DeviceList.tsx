import type { Device } from "../../api/types";
import { displayOrNotRecorded, formatTelemetrySummary } from "../../lib/format";
import { StatusBadge } from "../common/StatusBadge";

type Props = {
  devices: Device[];
  findingsCount: number;
  onSelect: (device: Device) => void;
  isReadOnly?: boolean;
};

function statusTone(
  status: string,
): "ok" | "warn" | "danger" | "neutral" {
  const value = status.toUpperCase();
  if (value === "ONLINE") return "ok";
  if (value === "OFFLINE") return "danger";
  return "neutral";
}

export function DeviceList({
  devices,
  findingsCount,
  onSelect,
  isReadOnly = false,
}: Props) {
  return (
    <div className="surface-panel overflow-x-auto rounded-2xl">
      <table className="min-w-full text-left text-sm">
        <thead className="border-b border-white/[0.06] text-[var(--muted)]">
          <tr>
            <th className="px-4 py-3.5 text-[11px] font-medium tracking-[0.1em] uppercase">Device</th>
            <th className="px-4 py-3.5 text-[11px] font-medium tracking-[0.1em] uppercase">Type</th>
            <th className="px-4 py-3.5 text-[11px] font-medium tracking-[0.1em] uppercase">Status</th>
            <th className="px-4 py-3.5 text-[11px] font-medium tracking-[0.1em] uppercase">Assessment</th>
            <th className="px-4 py-3.5 text-[11px] font-medium tracking-[0.1em] uppercase">IP</th>
            <th className="px-4 py-3.5 text-[11px] font-medium tracking-[0.1em] uppercase">Firmware</th>
            <th className="px-4 py-3.5 text-[11px] font-medium tracking-[0.1em] uppercase">Latest Telemetry</th>
            <th className="px-4 py-3.5 text-[11px] font-medium tracking-[0.1em] uppercase">Findings</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((device) => {
            const telemetry = formatTelemetrySummary(device.latest_telemetry);
            const status = (device.status || "UNKNOWN").toUpperCase();

            const authLabel = isReadOnly
              ? device.is_authorized
                ? "Authorized"
                : status === "ONLINE"
                  ? "Monitoring Only"
                  : "Restricted"
              : device.is_authorized
                ? "Authorized"
                : "Restricted";

            const authTone = device.is_authorized
              ? "ok"
              : isReadOnly && status === "ONLINE"
                ? "neutral"
                : "warn";

            const displayIp = isReadOnly
              ? "Private LAN"
              : displayOrNotRecorded(device.ip_address);

            return (
              <tr
                key={device.id}
                tabIndex={0}
                role="button"
                onClick={() => onSelect(device)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onSelect(device);
                  }
                }}
                className="list-row cursor-pointer border-b border-white/[0.04] last:border-b-0"
              >
                <td className="px-4 py-3 mono font-medium">{device.device_id}</td>
                <td className="px-4 py-3">{device.device_type}</td>
                <td className="px-4 py-3">
                  <StatusBadge label={status} tone={statusTone(status)} />
                </td>
                <td className="px-4 py-3">
                  <StatusBadge label={authLabel} tone={authTone} />
                </td>
                <td className="px-4 py-3 mono text-[var(--muted)]">
                  {displayIp}
                </td>
                <td className="px-4 py-3 mono">
                  {displayOrNotRecorded(device.firmware_version)}
                </td>
                <td className="px-4 py-3">
                  {device.latest_telemetry ? (
                    <>
                      <div className="mono text-[var(--text)]">
                        {telemetry.primary}
                      </div>
                      {telemetry.lastRecorded ? (
                        <div className="mt-0.5 text-[11px] text-[var(--muted)]">
                          Last recorded · {telemetry.lastRecorded}
                        </div>
                      ) : null}
                    </>
                  ) : (
                    <div className="text-[var(--muted)]">
                      No valid telemetry recorded
                    </div>
                  )}
                </td>
                <td className="px-4 py-3 text-[var(--muted)]">
                  {findingsCount > 0
                    ? `${findingsCount} lab MQTT`
                    : "None recorded"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
