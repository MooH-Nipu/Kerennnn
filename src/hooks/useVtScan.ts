import { useReducer, useCallback, useRef } from 'react';
import { parseIocList } from '../lib/ioc';
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
  | { type: 'SET_STATUS'; msg: string | null; statusType: VtScanState['statusType'] }
  | { type: 'CLEAR' };

const initial: VtScanState = {
  items: [],
  filters: { clean: true, suspicious: true, malicious: true },
  scanning: false,
  progress: { done: 0, total: 0 },
  statusMsg: null,
  statusType: null,
};

function reducer(state: VtScanState, action: Action): VtScanState {
  switch (action.type) {
    case 'START':
      return { ...state, items: [], scanning: true, progress: { done: 0, total: action.total }, statusMsg: null, statusType: 'loading' };
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
          const result = await api.scan.vt(ioc) as unknown as ScanItem['result'];
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

  const visibleItems = state.items.filter(item => {
    if (item.pending || item.error) return true;
    const result = item.result as Record<string, unknown> | null;
    const attrs = result?.data as Record<string, unknown> | null;
    const stats = (attrs?.attributes as Record<string, unknown>)?.last_analysis_stats as Record<string, number> | undefined;
    const mal = stats?.malicious ?? 0;
    const sus = stats?.suspicious ?? 0;
    const total = Object.values(stats ?? {}).reduce((a, b) => a + b, 0);
    if (!total) return state.filters.clean;
    if (mal > 3) return state.filters.malicious;
    if (mal > 0 || sus > 3) return state.filters.suspicious;
    return state.filters.clean;
  });

  return { ...state, visibleItems, runScan, clear, setFilter };
}
