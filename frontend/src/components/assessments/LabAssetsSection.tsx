import { getLabAssets, type AssetIdentity } from "../../lib/assets";
import type { Device } from "../../api/types";

interface LabAssetsSectionProps {
  isReadOnly?: boolean;
  devices?: Device[] | null;
}

function getAssetIcon(category: AssetIdentity["category"], assetType: string) {
  if (category === "ENVIRONMENT") {
    // Network icon
    return (
      <svg
        className="h-5 w-5 text-[var(--accent)]"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
        aria-hidden="true"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="2"
          d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"
        />
      </svg>
    );
  }
  if (category === "IOT_INFRASTRUCTURE" || assetType === "MQTT_BROKER") {
    // Server icon
    return (
      <svg
        className="h-5 w-5 text-sky-400"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
        aria-hidden="true"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="2"
          d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"
        />
      </svg>
    );
  }
  // Microchip / CPU icon for IoT devices
  return (
    <svg
      className="h-5 w-5 text-emerald-400"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2"
        d="M9 3v2m6-2v2M9 19v2m6-2v2M3 9h2m-2 6h2m14-6h2m-2 6h2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"
      />
    </svg>
  );
}

export function LabAssetsSection({ isReadOnly = false, devices = null }: LabAssetsSectionProps) {
  const assets = getLabAssets({ isReadOnly, devices });

  const headingTitle = isReadOnly ? "Monitored IoT Assets" : "Your IoT Lab Assets";
  const headingDesc = isReadOnly
    ? "These IoT devices are connected to the monitoring platform and provide live telemetry. Active vulnerability assessments are restricted to the local laboratory environment."
    : "The physical devices and infrastructure components configured in this cybersecurity lab.";

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-base font-semibold text-[var(--text)]">
          {headingTitle}
        </h2>
        <p className="mt-1 text-sm text-[var(--muted)] max-w-3xl">
          {headingDesc}
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {assets.map((asset) => {
          const isEnv = asset.category === "ENVIRONMENT";

          const badgeClasses = asset.isAuthorized
            ? "border-emerald-500/30 bg-emerald-500/15 text-emerald-400"
            : asset.statusLabel === "Telemetry Active"
              ? "border-[var(--accent)]/30 bg-[var(--accent)]/15 text-[var(--accent)]"
              : asset.statusLabel === "Assessment Restricted"
                ? "border-amber-500/30 bg-amber-500/15 text-amber-300"
                : "border-white/10 bg-white/[0.06] text-[var(--muted)]";

          return (
            <div
              key={asset.id}
              className={`flex flex-col justify-between rounded-2xl border p-4 transition-colors ${
                isEnv
                  ? "border-[var(--accent)]/30 bg-[var(--accent)]/[0.04]"
                  : "border-white/[0.07] bg-white/[0.02] hover:border-white/15"
              }`}
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-white/[0.05]">
                      {getAssetIcon(asset.category, asset.assetType)}
                    </span>
                    <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
                      {asset.categoryLabel}
                    </span>
                  </div>
                  <span className="mono rounded bg-white/[0.05] px-2 py-0.5 text-[11px] text-[var(--muted)]">
                    {asset.id}
                  </span>
                </div>

                <div>
                  <h3 className="text-sm font-semibold text-[var(--text)]">
                    {asset.displayName}
                  </h3>
                  <p className="mono mt-0.5 text-xs text-[var(--muted)]">
                    {asset.secondaryInfo}
                  </p>
                </div>

                {asset.statusLabel ? (
                  <div>
                    <span
                      className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${badgeClasses}`}
                    >
                      {asset.statusLabel}
                    </span>
                  </div>
                ) : null}

                <p className="text-xs leading-relaxed text-[var(--muted)]">
                  {asset.description}
                </p>
              </div>

              <div className="mt-4 border-t border-white/[0.05] pt-3 text-[11px] text-[var(--muted)]">
                <span className="font-medium text-[var(--text)]/80">Purpose: </span>
                {asset.purpose}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
