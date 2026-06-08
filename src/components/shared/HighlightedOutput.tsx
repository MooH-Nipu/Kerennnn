import type { ReactNode } from 'react';
import { CopyButton } from './CopyButton';
import { findIOCMatches } from '../../lib/ioc';

interface Props {
  value: string;
  rows?: number;
  placeholder?: string;
  copyLabel?: string;
  copyLabelDone?: string;
}

// Split `value` into plain segments + <mark> spans wrapping each IOC, so the
// SOC analyst can spot indicators (IPs, domains, URLs, hashes, emails) at a
// glance inside the log. Copy still yields the raw, unhighlighted text.
function highlight(value: string): ReactNode {
  const matches = findIOCMatches(value);
  if (matches.length === 0) return value;

  const nodes: ReactNode[] = [];
  let last = 0;
  matches.forEach((m, i) => {
    if (m.start > last) nodes.push(value.slice(last, m.start));
    nodes.push(
      <mark key={i} className="ioc-mark" title={m.type.toUpperCase()}>
        {value.slice(m.start, m.end)}
      </mark>
    );
    last = m.end;
  });
  if (last < value.length) nodes.push(value.slice(last));
  return nodes;
}

// Read-only output that renders text with IOCs highlighted in red. Mirrors
// OutputBox (copy button + .form-textarea--output styling) but uses a <pre>
// because a <textarea> can't colour individual substrings.
export function HighlightedOutput({
  value,
  placeholder,
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
      <pre className="form-textarea form-textarea--output ioc-output" aria-readonly="true">
        {value ? highlight(value) : <span className="ioc-output__placeholder">{placeholder}</span>}
      </pre>
    </div>
  );
}
