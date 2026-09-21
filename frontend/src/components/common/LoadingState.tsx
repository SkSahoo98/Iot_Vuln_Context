type Props = {
  message?: string;
};

export function LoadingState({ message = "Loading security data..." }: Props) {
  return (
    <div className="glass-inset flex items-center gap-3.5 rounded-2xl px-5 py-7 text-sm text-[var(--muted)] animate-fade-in">
      <span className="relative flex h-5 w-5 items-center justify-center">
        <span className="absolute inset-0 rounded-full border border-[var(--accent)]/25" />
        <span className="h-5 w-5 animate-spin rounded-full border-2 border-[var(--accent)]/25 border-t-[var(--accent)]" />
      </span>
      <span>{message}</span>
    </div>
  );
}
