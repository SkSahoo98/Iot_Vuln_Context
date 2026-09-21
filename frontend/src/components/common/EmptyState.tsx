type Props = {
  message: string;
};

export function EmptyState({ message }: Props) {
  return (
    <div className="glass-inset rounded-2xl border-dashed px-5 py-10 text-center animate-fade-in">
      <div
        className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-full border border-white/10 bg-white/[0.04] text-[var(--muted)]"
        aria-hidden
      >
        <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none">
          <circle cx="12" cy="12" r="8" stroke="currentColor" strokeWidth="1.7" />
          <path
            d="M12 8v4.5M12 16h.01"
            stroke="currentColor"
            strokeWidth="1.7"
            strokeLinecap="round"
          />
        </svg>
      </div>
      <p className="text-sm text-[var(--muted)]">{message}</p>
    </div>
  );
}
