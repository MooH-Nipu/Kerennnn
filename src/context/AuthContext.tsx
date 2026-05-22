import React, { createContext, useContext, useReducer, useCallback, useEffect } from 'react';
import type { Role } from '../types/api';
import { api } from '../lib/api';
import { formatApiError } from '../lib/utils';

export interface AuthState {
  ready: boolean;
  authed: boolean;
  role: Role | null;
  username: string | null;
  pending: boolean;
  loginError: string | null;
}

interface AuthActions {
  checkAuth: () => Promise<void>;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  clearError: () => void;
}

type Action =
  | { type: 'CHECK_START' }
  | { type: 'CHECK_OK'; role: Role; username: string }
  | { type: 'CHECK_FAIL' }
  | { type: 'LOGIN_START' }
  | { type: 'LOGIN_OK'; role: Role; username: string }
  | { type: 'LOGIN_FAIL'; error: string }
  | { type: 'LOGOUT' }
  | { type: 'CLEAR_ERROR' };

const initialState: AuthState = {
  ready: false,
  authed: false,
  role: null,
  username: null,
  pending: false,
  loginError: null,
};

function reducer(state: AuthState, action: Action): AuthState {
  switch (action.type) {
    case 'CHECK_START':
      return { ...state, pending: true };
    case 'CHECK_OK':
      return { ...state, ready: true, authed: true, role: action.role, username: action.username, pending: false };
    case 'CHECK_FAIL':
      return { ...state, ready: true, authed: false, role: null, username: null, pending: false };
    case 'LOGIN_START':
      return { ...state, pending: true, loginError: null };
    case 'LOGIN_OK':
      return { ...state, authed: true, role: action.role, username: action.username, pending: false, loginError: null };
    case 'LOGIN_FAIL':
      return { ...state, pending: false, loginError: action.error };
    case 'LOGOUT':
      return { ...initialState, ready: true };
    case 'CLEAR_ERROR':
      return { ...state, loginError: null };
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
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState);

  const checkAuth = useCallback(async () => {
    dispatch({ type: 'CHECK_START' });
    try {
      const res = await api.auth.me();
      dispatch({ type: 'CHECK_OK', role: res.role, username: res.username });
    } catch {
      dispatch({ type: 'CHECK_FAIL' });
    }
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    dispatch({ type: 'LOGIN_START' });
    try {
      const res = await api.auth.login(username, password);
      dispatch({ type: 'LOGIN_OK', role: res.role, username: res.username });
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

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  return (
    <AuthStateCtx.Provider value={state}>
      <AuthActionsCtx.Provider value={{ checkAuth, login, logout, clearError }}>
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
