import { useState } from 'react';
import { copyToClipboard } from '../../lib/utils';

interface Props {
  text: string;
  label?: string;
  labelDone?: string;
  className?: string;
}

export function CopyButton({ text, label = 'Copy', labelDone = 'Copied!', className }: Props) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  return (
    <button
      className={`btn btn-ghost ${copied ? 'btn-ghost--done' : ''} ${className ?? ''}`}
      onClick={handleCopy}
      disabled={!text}
    >
      {copied ? labelDone : label}
    </button>
  );
}
