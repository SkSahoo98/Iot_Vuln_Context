type Props = {
  items: string[];
};

export function RemediationList({ items }: Props) {
  return (
    <ol className="mt-2 list-decimal space-y-2 pl-5 text-sm leading-relaxed">
      {items.map((item, index) => (
        <li key={`${index}-${item}`}>{item}</li>
      ))}
    </ol>
  );
}
