import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { decodeJwt } from "jose";
import { getToken, requestToken, setToken } from "../api/client";

interface AuthState {
  token: string | null;
  username: string | null;
  role: string | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

/** True when the JWT is absent, malformed, or past its `exp`. */
function isExpired(token: string | null): boolean {
  if (!token) return true;
  try {
    const { exp } = decodeJwt(token);
    return typeof exp !== "number" || exp * 1000 <= Date.now();
  } catch {
    return true;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setTokenState] = useState<string | null>(() => {
    const existing = getToken();
    return isExpired(existing) ? null : existing;
  });

  // On mount, drop a token that has expired since the tab was last open.
  useEffect(() => {
    if (token && isExpired(token)) {
      setToken(null);
      setTokenState(null);
    }
  }, [token]);

  const login = useCallback(async (username: string, password: string) => {
    const fresh = await requestToken(username, password);
    setToken(fresh);
    setTokenState(fresh);
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setTokenState(null);
  }, []);

  const value = useMemo<AuthState>(() => {
    const claims = token && !isExpired(token) ? decodeJwt(token) : null;
    return {
      token: token && !isExpired(token) ? token : null,
      username: (claims?.sub as string) ?? null,
      role: (claims?.role as string) ?? null,
      login,
      logout,
    };
  }, [token, login, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
