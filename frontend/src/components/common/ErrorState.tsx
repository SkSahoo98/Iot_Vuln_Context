type Props = {
  message?: string;
  onRetry?: () => void;
};

export function ErrorState({
  message = "Unable to load this information.",
  onRetry,
}: Props) {
  return (
    <div className="rounded-2xl border border-[var(--danger)]/30 bg-[var(--danger)]/[0.08] px-5 py-5 text-sm text-[var(--danger)] shadow-[0_0_32px_rgba(251,113,133,0.08)] animate-fade-in">
      <div className="flex items-start gap-3">
        <span
          className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-[var(--danger)]/35 bg-[var(--danger)]/10"
          aria-hidden
        >
          <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="none">
            <path
              d="M12 3.5 20 19H4L12 3.5Z"
              stroke="currentColor"
              strokeWidth="1.7"
              strokeLinejoin="round"
            />
            <path
              d="M12 10v4.5M12 17.5h.01"
              stroke="currentColor"
              strokeWidth="1.7"
              strokeLinecap="round"
            />
          </svg>
        </span>
        <div className="min-w-0 flex-1">
          <p className="font-medium">{message}</p>
          {onRetry ? (
            <button
              type="button"
              onClick={onRetry}
              className="btn-soft mt-3 rounded-full border border-[var(--danger)]/40 bg-[var(--danger)]/10 px-3.5 py-1.5 text-xs font-medium hover:bg-[var(--danger)]/15"
            >
              Retry
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}
