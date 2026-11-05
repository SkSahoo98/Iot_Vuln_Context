import type { ReassessmentPair } from "../components/assessments/reassessment";

export type PrimarySection = "assistant" | "security" | "history" | "more";

/** Pages reached from "More"; they are not primary navigation items. */
export type SecondarySection = "devices" | "findings" | "risk" | "ai";

export type AppSection = PrimarySection | SecondarySection;

export const PRIMARY_SECTIONS: readonly PrimarySection[] = [
  "assistant",
  "security",
  "history",
  "more",
];

const SECONDARY_SECTIONS: readonly SecondarySection[] = [
  "devices",
  "findings",
  "risk",
  "ai",
];

export function isSecondarySection(section: AppSection): section is SecondarySection {
  return (SECONDARY_SECTIONS as readonly string[]).includes(section);
}

/** Primary item that is highlighted while `section` is shown. */
export function primarySectionOf(section: AppSection): PrimarySection {
  return isSecondarySection(section) ? "more" : section;
}

export const DEFAULT_SECTION: AppSection = "assistant";

/** Section names used before the UX-2 navigation, kept so old links still land. */
const LEGACY_ALIASES: Record<string, AppSection> = {
  overview: "security",
  assessments: "history",
};

export function sectionFromHash(hash: string): AppSection {
  const name = hash.replace(/^#\/?/, "").split("?")[0].trim().toLowerCase();
  if ((PRIMARY_SECTIONS as readonly string[]).includes(name)) return name as AppSection;
  if ((SECONDARY_SECTIONS as readonly string[]).includes(name)) return name as AppSection;
  return LEGACY_ALIASES[name] ?? DEFAULT_SECTION;
}

/** Element to bring into view after navigating; `focusId` receives focus. */
export type NavAnchor = { id: string; focusId?: string };

export type NavRequest = {
  section: AppSection;
  /** Assessment to select in History. */
  assessmentId?: string;
  anchor?: NavAnchor;
  /** Open the technical details of the latest assessment in Security. */
  securityTechnical?: boolean;
  /** Open History's comparison with these assessments preselected. */
  comparison?: ReassessmentPair;
};

export const SECTION_META: Record<AppSection, { title: string; subtitle: string }> = {
  assistant: {
    title: "Security Assistant",
    subtitle: "Start a security task for your authorized IoT target.",
  },
  security: {
    title: "Security",
    subtitle: "Latest security check of your authorized IoT target.",
  },
  history: {
    title: "History",
    subtitle: "Security checks run against your authorized targets.",
  },
  more: {
    title: "More",
    subtitle: "Devices, advanced views and system tools.",
  },
  devices: {
    title: "Devices",
    subtitle: "IoT assets registered in the authorized lab.",
  },
  findings: {
    title: "Technical Findings (legacy)",
    subtitle: "Findings from the earlier telemetry pipeline.",
  },
  risk: {
    title: "Risk & Research",
    subtitle: "How dynamic risk is calculated and what the experiment shows.",
  },
  ai: {
    title: "AI Analysis (legacy)",
    subtitle: "Evidence-grounded explanation of legacy findings.",
  },
};
