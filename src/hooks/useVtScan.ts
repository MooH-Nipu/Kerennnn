import { useReducer, useCallback, useRef } from 'react';
import { parseIocList, confToVerdict } from '../lib/ioc';
import { api } from '../lib/api';
import type { ScanItem } from '../types/vt';
import type { IocType } from '../types/vt';

const VT_CONCURRENCY = 2;

export interface ScanFilters {
  clean: boolean;
  suspicious: boolean;
  malicious: boolean;
}

interface VtScanState {
  items: ScanItem[];
  filters: ScanFilters;
  countryFilter: string; // '' = all countries; otherwise a 2-letter code
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
  | { type: 'SET_COUNTRY'; value: string }
  | { type: 'SET_STATUS'; msg: string | null; statusType: VtScanState['statusType'] }
  | { type: 'CLEAR' };

const initial: VtScanState = {
  items: [],
  filters: { clean: true, suspicious: true, malicious: true },
  countryFilter: '',
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
    return filters.clean; // LOW RISK / CLEAN / UNKNOWN
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
      return { ...state, items: [], countryFilter: '', scanning: true, progress: { done: 0, total: action.total }, statusMsg: null, statusType: 'loading' };
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
    case 'SET_COUNTRY':
      return { ...state, countryFilter: action.value };
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
      dispatch({ type: 'SET_STATUS', msg: 'Tidak ada IOC valid yang ditemukan.', statusType: 'error' });
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

        try {
          // Check local cache first
          let result = cacheRef.current.get(ioc);

          if (!result) {
            // Not cached, call API and cache the result
            result = await api.scan.vt(ioc) as unknown as ScanItem['result'];
            cacheRef.current.set(ioc, result);
          }

          dispatch({ type: 'RESOLVE', id, result });
        } catch (err) {
          dispatch({ type: 'RESOLVE_ERROR', id, error: err instanceof Error ? err.message : String(err) });
        }

        // Fire correlation async — don't await
        api.scan.correlate(ioc)
          .then(corr => dispatch({ type: 'UPDATE_CORR', id, correlation: corr as unknown as ScanItem['correlation'] }))
          .catch(() => dispatch({ type: 'UPDATE_CORR', id, correlation: null }));
      }
    }

    const workers = Array.from({ length: VT_CONCURRENCY }, () => worker());
    await Promise.all(workers);

    if (!abortRef.current) {
      dispatch({
        type: 'SET_STATUS',
        msg: `✓ Scan selesai — ${parsed.length} IOC diproses.`,
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

  const setCountry = useCallback((value: string) => {
    dispatch({ type: 'SET_COUNTRY', value });
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

  const visibleItems = state.items.filter(item => {
    if (!passesVerdictFilter(item, state.filters)) return false;

    // Country filter (applies to resolved IP results; loading/pending stay visible).
    if (state.countryFilter) {
      const c = getItemCountry(item);
      if (c) return c === state.countryFilter;
      return item.pending; // unresolved items remain while scanning; resolved non-IP hidden
    }
    return true;
  });

  return { ...state, visibleItems, availableCountries, runScan, clear, setFilter, setCountry };
}
