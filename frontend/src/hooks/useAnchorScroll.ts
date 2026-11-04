import { useEffect } from "react";
import type { NavAnchor } from "../lib/navigation";

const RETRY_MS = 100;
const MAX_ATTEMPTS = 40;

/**
 * Scrolls to `anchor.id` once it exists (content may still be loading) and
 * focuses `anchor.focusId`. A new request object restarts the search.
 */
export function useAnchorScroll(anchor: NavAnchor | null): void {
  useEffect(() => {
    if (!anchor) return;
    let attempts = 0;
    let timer = 0;

    const attempt = () => {
      const target = document.getElementById(anchor.id);
      if (target) {
        target.scrollIntoView({ behavior: "smooth", block: "start" });
        if (anchor.focusId) {
          document.getElementById(anchor.focusId)?.focus({ preventScroll: true });
        }
        return;
      }
      attempts += 1;
      if (attempts < MAX_ATTEMPTS) timer = window.setTimeout(attempt, RETRY_MS);
    };

    timer = window.setTimeout(attempt, 0);
    return () => window.clearTimeout(timer);
  }, [anchor]);
}
