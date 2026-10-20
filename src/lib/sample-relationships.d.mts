import type { PassiveDnsResponse } from '../types/api';

export const MAX_SAMPLE_BYTES: number;
export const MAX_REVERSE_CANDIDATES: number;
export const MAX_RELATION_EDGES: number;
export function sha256Sample(file: Pick<File, 'size' | 'arrayBuffer'>, cryptoApi?: Crypto): Promise<string>;
export function reverseCandidates(response: Pick<PassiveDnsResponse, 'records'>): string[];
export function resolutionEdges(root: string, type: 'ip' | 'domain', responses: PassiveDnsResponse[]): Array<{ domain: string; ip: string }>;
