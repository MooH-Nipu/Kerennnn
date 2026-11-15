export function newSalt(): Uint8Array;
export function legend(): string;
export function redact(
  text: string,
  salt: Uint8Array,
  opts?: { strict?: boolean; entities?: string[]; terms?: string[] },
): Promise<{ text: string; stats: Record<string, number> }>;
