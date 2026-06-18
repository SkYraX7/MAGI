import { useState } from "react";
import type { CSSProperties, FormEvent } from "react";
import { useAuth } from "./AuthContext";

export function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(username, password);
    } catch {
      setError("Invalid username or password");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={styles.wrap}>
      <form onSubmit={onSubmit} style={styles.card}>
        <h1 style={styles.title}>MAGI</h1>
        <p style={styles.subtitle}>Multi-source Adaptive Graph Intelligence</p>
        <input
          style={styles.input}
          aria-label="username"
          placeholder="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="username"
        />
        <input
          style={styles.input}
          aria-label="password"
          type="password"
          placeholder="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
        />
        {error && (
          <div role="alert" style={styles.error}>
            {error}
          </div>
        )}
        <button type="submit" disabled={busy} style={styles.button}>
          {busy ? "Authenticating…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}

const styles: Record<string, CSSProperties> = {
  wrap: { height: "100%", display: "grid", placeItems: "center" },
  card: {
    display: "flex",
    flexDirection: "column",
    gap: 12,
    width: 320,
    padding: 32,
    background: "#0b1020",
    border: "1px solid #1e2a44",
    borderRadius: 12,
    boxShadow: "0 12px 40px rgba(0,0,0,0.5)",
  },
  title: { margin: 0, letterSpacing: 6, color: "#ff8800", textAlign: "center" },
  subtitle: { margin: "0 0 12px", fontSize: 12, color: "#6b7aa3", textAlign: "center" },
  input: {
    padding: "10px 12px",
    background: "#05070d",
    border: "1px solid #1e2a44",
    borderRadius: 8,
    color: "#cdd6f4",
  },
  button: {
    padding: "10px 12px",
    background: "#4488cc",
    border: 0,
    borderRadius: 8,
    color: "white",
    cursor: "pointer",
    fontWeight: 600,
  },
  error: { color: "#ff6b6b", fontSize: 13 },
};
