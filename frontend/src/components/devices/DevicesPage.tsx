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
};

export function DevicesPage({
  devices,
  loading,
  error,
  onRetry,
  findings,
  onSelect,
}: Props) {
  if (loading && !devices) return <LoadingState />;
  if (error && !devices) return <ErrorState message={error} onRetry={onRetry} />;
  if (!devices || devices.length === 0) {
    return <EmptyState message="No IoT devices registered." />;
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <p className="text-sm text-[var(--muted)]">
        Select a device to view details. Latest telemetry shows the most recent
        recorded sensor_data values when available.
      </p>
      <DeviceList
        devices={devices}
        findingsCount={findings.length}
        onSelect={onSelect}
      />
    </div>
  );
}
