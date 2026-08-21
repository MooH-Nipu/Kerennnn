import React, { createContext, useContext, useReducer, useCallback, useEffect } from 'react';
import type { Role, Team, TeamAccess } from '../types/api';
import { api, type ApiError } from '../lib/api';
import { formatApiError } from '../lib/utils';

export interface AuthState {
  ready: boolean;
  authed: boolean;
  role: Role | null;
  username: string | null;
  assignedTeam: Team | null;
  allowedTeams: Team[];
  canSwitchTeam: boolean;
  activeTeam: Team | null;
  pending: boolean;
  loginError: string | null;
  sessionExpired: boolean;
}

interface AuthActions {
  checkAuth: () => Promise<void>;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  clearError: () => void;
  setActiveTeam: (team: Team) => void;
}

type Action =
  | { type: 'CHECK_START' }
  | { type: 'CHECK_OK'; role: Role; username: string; access: TeamAccess }
  | { type: 'CHECK_FAIL'; expired?: boolean }
  | { type: 'LOGIN_START' }
  | { type: 'LOGIN_OK'; role: Role; username: string; access: TeamAccess }
  | { type: 'LOGIN_FAIL'; error: string }
  | { type: 'LOGOUT' }
  | { type: 'CLEAR_ERROR' }
  | { type: 'SET_TEAM'; team: Team };

const initialState: AuthState = {
  ready: false,
  authed: false,
  role: null,
  username: null,
  assignedTeam: null,
  allowedTeams: [],
  canSwitchTeam: false,
  activeTeam: null,
  pending: false,
  loginError: null,
  sessionExpired: false,
};

function reducer(state: AuthState, action: Action): AuthState {
  switch (action.type) {
    case 'CHECK_START':
      return { ...state, pending: true };
    case 'CHECK_OK':
      return { ...state, ready: true, authed: true, role: action.role, username: action.username, ...action.access, activeTeam: action.access.assignedTeam ?? action.access.allowedTeams[0] ?? null, pending: false, sessionExpired: false };
    case 'CHECK_FAIL':
      return { ...state, ready: true, authed: false, role: null, username: null, pending: false, sessionExpired: action.expired === true };
    case 'LOGIN_START':
      return { ...state, pending: true, loginError: null };
    case 'LOGIN_OK':
      return { ...state, ready: true, authed: true, role: action.role, username: action.username, ...action.access, activeTeam: action.access.assignedTeam ?? action.access.allowedTeams[0] ?? null, pending: false, loginError: null };
    case 'LOGIN_FAIL':
      return { ...state, pending: false, loginError: action.error };
    case 'LOGOUT':
      return { ...initialState, ready: true };
    case 'CLEAR_ERROR':
      return { ...state, loginError: null };
    case 'SET_TEAM':
      return state.canSwitchTeam && state.allowedTeams.includes(action.team) ? { ...state, activeTeam: action.team } : state;
    default:
      return state;
  }
}

const AuthStateCtx = createContext<AuthState>(initialState);
const AuthActionsCtx = createContext<AuthActions>({
  checkAuth: async () => {},
  login: async () => {},
  logout: async () => {},
  clearError: () => {},
  setActiveTeam: () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState);

  const checkAuth = useCallback(async () => {
    dispatch({ type: 'CHECK_START' });
    try {
      const res = await api.auth.me();
      dispatch({ type: 'CHECK_OK', role: res.role, username: res.username, access: res });
    } catch (err) {
      const expired = err instanceof Error && (err as ApiError).status === 401;
      dispatch({ type: 'CHECK_FAIL', expired });
    }
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    dispatch({ type: 'LOGIN_START' });
    try {
      const res = await api.auth.login(username, password);
      dispatch({ type: 'LOGIN_OK', role: res.role, username: res.username, access: res });
    } catch (err) {
      dispatch({ type: 'LOGIN_FAIL', error: formatApiError(err) });
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.auth.logout();
    } catch {
      // ignore
    }
    dispatch({ type: 'LOGOUT' });
  }, []);

  const clearError = useCallback(() => dispatch({ type: 'CLEAR_ERROR' }), []);
  const setActiveTeam = useCallback((team: Team) => dispatch({ type: 'SET_TEAM', team }), []);

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  return (
    <AuthStateCtx.Provider value={state}>
      <AuthActionsCtx.Provider value={{ checkAuth, login, logout, clearError, setActiveTeam }}>
        {children}
      </AuthActionsCtx.Provider>
    </AuthStateCtx.Provider>
  );
}

export function useAuthState(): AuthState {
  return useContext(AuthStateCtx);
}

export function useAuthActions(): AuthActions {
  return useContext(AuthActionsCtx);
}
