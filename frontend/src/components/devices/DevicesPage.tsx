import type { Device, Finding } from "../../api/types";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { DeviceList } from "./DeviceList";

type Props = {
  devices: Device[] | null;
  loading: boolean;
  error: string | null;
  onRetry: () => void;
  findings: Finding[];
  onSelect: (device: Device) => void;
  isReadOnly?: boolean;
};

export function DevicesPage({
  devices,
  loading,
  error,
  onRetry,
  findings,
  onSelect,
  isReadOnly = false,
}: Props) {
  if (loading && !devices) return <LoadingState />;
  if (error && !devices) return <ErrorState message={error} onRetry={onRetry} />;
  if (!devices || devices.length === 0) {
    return <EmptyState message="No IoT devices registered." />;
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-sm text-[var(--muted)]">
          Select a device to view details. Latest telemetry shows the most recent
          recorded sensor_data values when available.
        </p>
        {isReadOnly ? (
          <span className="mono text-xs text-[var(--accent)] bg-[var(--accent-soft)] px-3 py-1 rounded-full border border-[var(--accent)]/30 self-start sm:self-auto">
            Cloud Monitoring Mode
          </span>
        ) : null}
      </div>
      <DeviceList
        devices={devices}
        findingsCount={findings.length}
        onSelect={onSelect}
        isReadOnly={isReadOnly}
      />
    </div>
  );
}
