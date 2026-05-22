interface MetaItemProps {
  label: string;
  value: string | number;
  color?: string;
}

function MetaItem({ label, value, color }: MetaItemProps) {
  return (
    <div className="meta-item">
      <div className="mk">{label}</div>
      <div className={`mv${color ? ' ' + color : ''}`}>{String(value ?? '—')}</div>
    </div>
  );
}

export { MetaItem };

interface MetaGridProps {
  items: MetaItemProps[];
}

export function MetaGrid({ items }: MetaGridProps) {
  return (
    <div className="meta-grid">
      {items.map((item, i) => (
        <MetaItem key={i} {...item} />
      ))}
    </div>
  );
}
