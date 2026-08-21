import { CopyButton } from './CopyButton';

interface Props {
  value: string;
  displayValue?: string;
  rows?: number;
  placeholder?: string;
  className?: string;
  copyLabel?: string;
  copyLabelDone?: string;
  ariaLabel?: string;
}

export function OutputBox({
  value,
  displayValue,
  rows = 12,
  placeholder,
  className,
  copyLabel = 'COPY',
  copyLabelDone = '✓',
  ariaLabel = 'Output',
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
        aria-label={ariaLabel}
        className={`form-textarea form-textarea--output${className ? ` ${className}` : ''}`}
        readOnly
        value={displayValue ?? value}
        placeholder={placeholder}
        rows={rows}
      />
    </div>
  );
}
