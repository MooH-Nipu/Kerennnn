import { CopyButton } from './CopyButton';

interface Props {
  value: string;
  rows?: number;
  placeholder?: string;
  className?: string;
  copyLabel?: string;
  copyLabelDone?: string;
}

export function OutputBox({
  value,
  rows = 12,
  placeholder,
  className,
  copyLabel = 'COPY',
  copyLabelDone = '✓',
}: Props) {
  return (
    <div className="output-box">
      {value && (
        <CopyButton
          text={value}
          label={copyLabel}
          labelDone={copyLabelDone}
          variant="overlay"
          className="output-box__copy"
        />
      )}
      <textarea
        className={`form-textarea form-textarea--output${className ? ` ${className}` : ''}`}
        readOnly
        value={value}
        placeholder={placeholder}
        rows={rows}
      />
    </div>
  );
}
