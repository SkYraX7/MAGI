import axios from "axios";

// Token lives in sessionStorage only (never localStorage) — cleared when the tab closes.
export const TOKEN_KEY = "magi.token";

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null): void {
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

// Origin-relative base URL — the Vite dev proxy / nginx forwards to the backend.
export const api = axios.create({ baseURL: import.meta.env.VITE_API_BASE ?? "" });

// Auto-attach the bearer token to every request.
api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

export async function requestToken(username: string, password: string): Promise<string> {
  const { data } = await api.post<TokenResponse>("/auth/token", { username, password });
  return data.access_token;
}
