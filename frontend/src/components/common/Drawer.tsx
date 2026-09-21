import { useEffect } from "react";

type Props = {
  open: boolean;
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  wide?: boolean;
};

export function Drawer({ open, title, onClose, children, wide = false }: Props) {
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = prev;
      window.removeEventListener("keydown", onKey);
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <button
        type="button"
        aria-label="Close drawer backdrop"
        className="absolute inset-0 bg-black/50 backdrop-blur-[6px] animate-fade-in"
        onClick={onClose}
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={`glass-sheet relative flex h-full w-full flex-col animate-drawer-in ${
          wide ? "max-w-xl" : "max-w-lg"
        } sm:max-w-md md:max-w-lg ${wide ? "lg:max-w-xl" : ""}`}
      >
        <div className="glass-sheet__header flex items-start justify-between gap-3 px-5 py-4">
          <div className="min-w-0">
            <p className="text-[10px] font-medium tracking-[0.16em] text-[var(--muted)] uppercase">
              Details
            </p>
            <h2 className="font-display mt-0.5 text-lg font-semibold leading-snug">
              {title}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close drawer"
            className="premium-close"
          >
            <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="none" aria-hidden>
              <path
                d="M6 6l12 12M18 6 6 18"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
              />
            </svg>
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-5 py-5">{children}</div>
      </aside>
    </div>
  );
}
