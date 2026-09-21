export type AppSection = "overview" | "devices" | "findings" | "risk" | "ai";

export const SECTION_META: Record<
  AppSection,
  { title: string; subtitle: string }
> = {
  overview: {
    title: "Security Overview",
    subtitle: "Current security posture of your monitored IoT environment.",
  },
  devices: {
    title: "Devices",
    subtitle: "IoT assets registered in the authorized lab.",
  },
  findings: {
    title: "Findings",
    subtitle: "Security problems detected from observed evidence.",
  },
  risk: {
    title: "Risk & Research",
    subtitle: "How dynamic risk is calculated and what the experiment shows.",
  },
  ai: {
    title: "AI Analysis",
    subtitle: "Evidence-grounded explanation of verified findings.",
  },
};
