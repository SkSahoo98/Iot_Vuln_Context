import { severityBadgeClass } from "../../lib/format";

type Props = {
  severity: string | null | undefined;
};

export function SeverityBadge({ severity }: Props) {
  return (
    <span
      className={`premium-badge inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-semibold tracking-wide ${severityBadgeClass(
        severity,
      )}`}
    >
      {severity || "Unknown"}
    </span>
  );
}
