import { useState } from 'react';
import { copyToClipboard } from '../../lib/utils';

interface Props {
  text: string;
  label?: string;
  labelDone?: string;
  className?: string;
  variant?: 'default' | 'overlay';
}

export function CopyButton({
  text,
  label = 'Copy',
  labelDone = 'Copied!',
  className,
  variant = 'default',
}: Props) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  const baseClass =
    variant === 'overlay'
      ? `copy-btn${copied ? ' copied' : ''}`
      : `btn btn-ghost${copied ? ' btn-ghost--done' : ''}`;

  return (
    <button
      type="button"
      className={`${baseClass}${className ? ` ${className}` : ''}`}
      onClick={handleCopy}
      disabled={!text}
    >
      {copied ? labelDone : label}
    </button>
  );
}
