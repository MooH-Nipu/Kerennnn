import { useReducer, useCallback, useRef } from 'react';
import { parseIocList, confToVerdict } from '../lib/ioc';
import { api } from '../lib/api';
import type { ScanItem } from '../types/vt';
import type { IocType } from '../types/vt';

const VT_CONCURRENCY = 2;

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
  | { type: 'RESOLVE_WITH_CORR'; id: string; result: ScanItem['result']; correlation: ScanItem['correlation'] }
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
    case 'RESOLVE_WITH_CORR':
      return {
        ...state,
        progress: { ...state.progress, done: state.progress.done + 1 },
        items: state.items.map(it => it.id === action.id
          ? { ...it, result: action.result, pending: false, correlation: action.correlation, correlationLoading: false }
          : it
        ),
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

  const runScan = useCallback(async (rawInput: string) => {
    const parsed = parseIocList(rawInput);
    if (!parsed.length) {
      dispatch({ type: 'SET_STATUS', msg: 'No valid IOCs found.', statusType: 'error' });
      return;
    }

    abortRef.current = false;
    dispatch({ type: 'START', total: parsed.length });

    // Pool: run VT_CONCURRENCY at a time
    let idx = 0;

    async function worker() {
      while (idx < parsed.length && !abortRef.current) {
        const i = idx++;
        const { ioc, type } = parsed[i];
        const id = `${i}-${ioc}`;

        dispatch({ type: 'ADD_PENDING', id, ioc, iocType: type });

        // VT scan
        let result: ScanItem['result'];
        try {
          let cached = cacheRef.current.get(ioc);
          if (!cached) {
            cached = await api.scan.vt(ioc) as unknown as ScanItem['result'];
            cacheRef.current.set(ioc, cached);
          }
          result = cached;
        } catch (err) {
          dispatch({ type: 'RESOLVE_ERROR', id, error: err instanceof Error ? err.message : String(err) });
          continue;
        }

        // Await all TI sources before showing the card — correlation waits for
        // every configured source to respond (or time out).
        let corr: ScanItem['correlation'] = null;
        try {
          const corrResult = await api.scan.correlate(ioc);
          corr = corrResult as unknown as ScanItem['correlation'];
          // Persist so the Deep Analysis page can render it later.
          api.ipCache.saveCorrelation(ioc, corrResult).catch(() => {});
        } catch {
          // Correlation failed — show card with VT result only, no TI panel.
        }

        dispatch({ type: 'RESOLVE_WITH_CORR', id, result, correlation: corr });
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
