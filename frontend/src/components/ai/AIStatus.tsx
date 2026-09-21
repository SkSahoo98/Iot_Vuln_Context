import type { Explanation } from "../../api/types";
import { StatusBadge } from "../common/StatusBadge";

type Props = {
  explanation: Explanation | null;
  loading: boolean;
};

export function AIStatus({ explanation, loading }: Props) {
  const source = explanation?.source;
  const isOllama = source === "ollama";
  const isFallback = source === "fallback";

  return (
    <div className="flex flex-wrap gap-2">
      {isFallback ? (
        <>
          <StatusBadge label="AI Engine: Rule-Based Fallback" tone="warn" />
          <StatusBadge label="Provider: Application" tone="neutral" />
        </>
      ) : (
        <>
          <StatusBadge label="AI Engine: Qwen3:8b" tone="info" />
          <StatusBadge label="Provider: Local Ollama" tone="info" />
        </>
      )}
      <StatusBadge label="Mode: Evidence-Grounded" tone="ok" />
      <StatusBadge
        label={
          loading
            ? "Status: Analyzing…"
            : isOllama
              ? "Status: Available (Ollama)"
              : isFallback
                ? "Status: Fallback"
                : "Status: Ready"
        }
        tone={isOllama ? "ok" : isFallback ? "warn" : "neutral"}
      />
    </div>
  );
}
