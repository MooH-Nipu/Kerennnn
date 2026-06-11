import { useReducer, useCallback, useRef } from 'react';
import { parseIocList, confToVerdict } from '../lib/ioc';
import { api } from '../lib/api';
import type { ScanItem } from '../types/vt';
import type { IocType } from '../types/vt';

const VT_CONCURRENCY = 2;
// Retry budget per IOC when all VT keys are rate-limited, and default cooldown
// (used when the server sends no Retry-After) matching VT's 60s per-minute window.
const VT_MAX_RETRIES = 6;
const VT_RATE_LIMIT_BACKOFF_MS = 60_000;

export interface ScanFilters {
  clean: boolean;
  lowrisk: boolean;
  suspicious: boolean;
  malicious: boolean;
}

export type CountryMode = 'include' | 'exclude';
export interface CountryFilterEntry {
  code: string;
  mode: CountryMode;
}

interface VtScanState {
  items: ScanItem[];
  filters: ScanFilters;
  countryFilters: CountryFilterEntry[]; // Kibana-style include/exclude per 2-letter code
  scanning: boolean;
  progress: { done: number; total: number };
  statusMsg: string | null;
  statusType: 'loading' | 'success' | 'error' | null;
}

type Action =
  | { type: 'START'; total: number }
  | { type: 'ADD_PENDING'; id: string; ioc: string; iocType: IocType }
  | { type: 'RESOLVE'; id: string; result: ScanItem['result'] }
  | { type: 'RESOLVE_ERROR'; id: string; error: string }
  | { type: 'UPDATE_CORR'; id: string; correlation: ScanItem['correlation'] }
  | { type: 'SET_FILTER'; key: keyof ScanFilters; value: boolean }
  | { type: 'SET_COUNTRY_FILTERS'; value: CountryFilterEntry[] }
  | { type: 'SET_STATUS'; msg: string | null; statusType: VtScanState['statusType'] }
  | { type: 'CLEAR' };

const initial: VtScanState = {
  items: [],
  filters: { clean: true, lowrisk: true, suspicious: true, malicious: true },
  countryFilters: [],
  scanning: false,
  progress: { done: 0, total: 0 },
  statusMsg: null,
  statusType: null,
};

/** Reads the 2-letter country code from a resolved VT result (IPs only). */
function getItemCountry(item: ScanItem): string {
  const result = item.result as Record<string, unknown> | null;
  const data = result?.data as Record<string, unknown> | undefined;
  const attrs = data?.attributes as Record<string, unknown> | undefined;
  const c = attrs?.country;
  return typeof c === 'string' ? c.toUpperCase() : '';
}

/** Whether an item passes the verdict (malicious/suspicious/clean) chips. */
function passesVerdictFilter(item: ScanItem, filters: ScanFilters): boolean {
  if (item.pending || item.error) return true;
  if (item.correlationLoading) return true;
  if (item.correlation !== null) {
    const conf = (item.correlation as unknown as Record<string, unknown>)?.confidence as number | null ?? null;
    const { label } = confToVerdict(conf);
    if (label === 'MALICIOUS') return filters.malicious;
    if (label === 'SUSPICIOUS') return filters.suspicious;
    if (label === 'LOW RISK') return filters.lowrisk;
    return filters.clean; // CLEAN / UNKNOWN
  }
  // Fallback: VT-only verdict when correlation unavailable.
  const result = item.result as Record<string, unknown> | null;
  const attrs = result?.data as Record<string, unknown> | null;
  const stats = (attrs?.attributes as Record<string, unknown>)?.last_analysis_stats as Record<string, number> | undefined;
  const mal = stats?.malicious ?? 0;
  const sus = stats?.suspicious ?? 0;
  const total = Object.values(stats ?? {}).reduce((a, b) => a + b, 0);
  if (!total) return filters.clean;
  if (mal >= 5) return filters.malicious;
  if (mal >= 1 || sus >= 3) return filters.suspicious;
  return filters.clean;
}

function reducer(state: VtScanState, action: Action): VtScanState {
  switch (action.type) {
    case 'START':
      return { ...state, items: [], countryFilters: [], scanning: true, progress: { done: 0, total: action.total }, statusMsg: null, statusType: 'loading' };
    case 'ADD_PENDING':
      return {
        ...state,
        items: [...state.items, {
          id: action.id,
          ioc: action.ioc,
          type: action.iocType,
          result: null,
          correlation: null,
          correlationLoading: true,
          error: null,
          pending: true,
        }],
      };
    case 'RESOLVE':
      return {
        ...state,
        progress: { ...state.progress, done: state.progress.done + 1 },
        items: state.items.map(it => it.id === action.id ? { ...it, result: action.result, pending: false } : it),
      };
    case 'RESOLVE_ERROR':
      return {
        ...state,
        progress: { ...state.progress, done: state.progress.done + 1 },
        items: state.items.map(it => it.id === action.id ? { ...it, error: action.error, pending: false } : it),
      };
    case 'UPDATE_CORR':
      return {
        ...state,
        items: state.items.map(it => it.id === action.id
          ? { ...it, correlation: action.correlation, correlationLoading: false }
          : it
        ),
      };
    case 'SET_FILTER':
      return { ...state, filters: { ...state.filters, [action.key]: action.value } };
    case 'SET_COUNTRY_FILTERS':
      return { ...state, countryFilters: action.value };
    case 'SET_STATUS':
      return { ...state, statusMsg: action.msg, statusType: action.statusType, scanning: action.statusType === 'loading' };
    case 'CLEAR':
      return { ...initial, filters: state.filters };
    default:
      return state;
  }
}

export function useVtScan() {
  const [state, dispatch] = useReducer(reducer, initial);
  const abortRef = useRef(false);
  const cacheRef = useRef<Map<string, ScanItem['result']>>(new Map());
  // Shared rate-limit cooldown: when any VT request is 429'd, every worker waits
  // until this timestamp before its next call (VT free tier = 4 req/min per key).
  const pauseUntilRef = useRef(0);

  const runScan = useCallback(async (rawInput: string) => {
    const parsed = parseIocList(rawInput);
    if (!parsed.length) {
      dispatch({ type: 'SET_STATUS', msg: 'No valid IOCs found.', statusType: 'error' });
      return;
    }

    abortRef.current = false;
    pauseUntilRef.current = 0;
    dispatch({ type: 'START', total: parsed.length });

    // Pool: run VT_CONCURRENCY at a time
    let idx = 0;

    // Block until any shared rate-limit cooldown elapses (or scan is aborted).
    async function awaitCooldown() {
      let paused = false;
      while (!abortRef.current && Date.now() < pauseUntilRef.current) {
        paused = true;
        const secs = Math.ceil((pauseUntilRef.current - Date.now()) / 1000);
        dispatch({ type: 'SET_STATUS', msg: `⏳ VirusTotal rate limit — pausing ${secs}s before retrying…`, statusType: 'loading' });
        await new Promise(r => setTimeout(r, 1000));
      }
      if (paused && !abortRef.current) {
        dispatch({ type: 'SET_STATUS', msg: 'Resuming scan…', statusType: 'loading' });
      }
    }

    // VT fetch with shared cooldown + retry-on-429 so a per-minute burst self-throttles
    // instead of failing the IOC. Cache hits and non-429 errors return/throw immediately.
    async function fetchVt(ioc: string): Promise<ScanItem['result']> {
      const hit = cacheRef.current.get(ioc);
      if (hit) return hit;
      for (let attempt = 0; attempt <= VT_MAX_RETRIES; attempt++) {
        await awaitCooldown();
        if (abortRef.current) throw new Error('aborted');
        try {
          const res = await api.scan.vt(ioc) as unknown as ScanItem['result'];
          cacheRef.current.set(ioc, res);
          return res;
        } catch (err) {
          const status = (err as { status?: number })?.status;
          if (status === 429 && attempt < VT_MAX_RETRIES) {
            const ra = (err as { retryAfter?: number })?.retryAfter;
            const backoffMs = ra && ra > 0 ? ra * 1000 : VT_RATE_LIMIT_BACKOFF_MS;
            pauseUntilRef.current = Math.max(pauseUntilRef.current, Date.now() + backoffMs);
            continue; // wait out the shared cooldown, then retry the same IOC
          }
          throw err;
        }
      }
      throw new Error('VirusTotal rate limit — retries exhausted. Try again later.');
    }

    async function worker() {
      while (idx < parsed.length && !abortRef.current) {
        const i = idx++;
        const { ioc, type } = parsed[i];
        const id = `${i}-${ioc}`;

        dispatch({ type: 'ADD_PENDING', id, ioc, iocType: type });

        // VT scan
        let result: ScanItem['result'];
        try {
          result = await fetchVt(ioc);
        } catch (err) {
          if (abortRef.current) return;
          dispatch({ type: 'RESOLVE_ERROR', id, error: err instanceof Error ? err.message : String(err) });
          continue;
        }

        dispatch({ type: 'RESOLVE', id, result });

        // If VT was served from cache and correlation was previously saved, skip fresh API calls.
        const meta = (result as unknown as Record<string, unknown>)?._meta as Record<string, unknown> | undefined;
        const cacheMeta = meta?.cache as Record<string, unknown> | undefined;
        const cachedCorr = cacheMeta?.fromCache && cacheMeta?.corrPayload
          ? cacheMeta.corrPayload as ScanItem['correlation']
          : null;

        if (cachedCorr) {
          dispatch({ type: 'UPDATE_CORR', id, correlation: cachedCorr });
        } else {
          api.scan.correlate(ioc)
            .then(corr => {
              dispatch({ type: 'UPDATE_CORR', id, correlation: corr as unknown as ScanItem['correlation'] });
              api.ipCache.saveCorrelation(ioc, corr).catch(() => {});
            })
            .catch(() => dispatch({ type: 'UPDATE_CORR', id, correlation: null }));
        }
      }
    }

    const workers = Array.from({ length: VT_CONCURRENCY }, () => worker());
    await Promise.all(workers);

    if (!abortRef.current) {
      dispatch({
        type: 'SET_STATUS',
        msg: `✓ Scan complete — ${parsed.length} IOCs processed.`,
        statusType: 'success',
      });
    }
  }, []);

  const clear = useCallback(() => {
    abortRef.current = true;
    dispatch({ type: 'CLEAR' });
  }, []);

  const setFilter = useCallback((key: keyof ScanFilters, value: boolean) => {
    dispatch({ type: 'SET_FILTER', key, value });
  }, []);

  const setCountryFilters = useCallback((value: CountryFilterEntry[]) => {
    dispatch({ type: 'SET_COUNTRY_FILTERS', value });
  }, []);

  // Countries present in the current results, with counts (IP results only).
  const countryCounts = new Map<string, number>();
  for (const item of state.items) {
    const c = getItemCountry(item);
    if (c) countryCounts.set(c, (countryCounts.get(c) ?? 0) + 1);
  }
  const availableCountries = [...countryCounts.entries()]
    .map(([code, count]) => ({ code, count }))
    .sort((a, b) => b.count - a.count || a.code.localeCompare(b.code));

  const includeCodes = state.countryFilters.filter(f => f.mode === 'include').map(f => f.code);
  const excludeCodes = state.countryFilters.filter(f => f.mode === 'exclude').map(f => f.code);

  const visibleItems = state.items.filter(item => {
    if (!passesVerdictFilter(item, state.filters)) return false;

    // Country filter — Kibana style: include = OR allowlist, exclude = denylist.
    if (includeCodes.length || excludeCodes.length) {
      const c = getItemCountry(item);
      if (!c) {
        if (item.pending) return true;        // keep unresolved items while scanning
        return includeCodes.length === 0;     // resolved non-IP hidden only when an include is active
      }
      if (excludeCodes.includes(c)) return false;
      if (includeCodes.length && !includeCodes.includes(c)) return false;
    }
    return true;
  });

  return { ...state, visibleItems, availableCountries, runScan, clear, setFilter, setCountryFilters };
}
