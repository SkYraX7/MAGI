import { useEffect } from "react";
import type { CSSProperties } from "react";
import { useAuth } from "./auth/AuthContext";
import { LoginPage } from "./auth/LoginPage";
import { ThreatGraph } from "./graph/ThreatGraph";
import { useWsGraph } from "./graph/useWsGraph";
import { requestNotificationPermission } from "./graph/notifications";

export default function App() {
  const { token, username, role, logout } = useAuth();
  if (!token) return <LoginPage />;
  return <Dashboard username={username} role={role} onLogout={logout} token={token} />;
}

function Dashboard({
  token,
  username,
  role,
  onLogout,
}: {
  token: string;
  username: string | null;
  role: string | null;
  onLogout: () => void;
}) {
  const { graphData, status, nodeMap } = useWsGraph(token);

  // Ask for OS-notification permission once the operator is in.
  useEffect(() => {
    void requestNotificationPermission();
  }, []);

  return (
    <div style={{ height: "100%", position: "relative" }}>
      <ThreatGraph nodes={graphData.nodes} links={graphData.links} nodeMap={nodeMap} />

      <header style={styles.header}>
        <span style={styles.brand}>MAGI</span>
        <span style={styles.meta}>
          {graphData.nodes.length} nodes · {graphData.links.length} edges
        </span>
        <span style={{ flex: 1 }} />
        <span style={styles.user}>
          {username} ({role})
        </span>
        <button style={styles.logout} onClick={onLogout}>
          Sign out
        </button>
      </header>

      {status !== "open" && (
        <div role="status" style={styles.banner}>
          {status === "connecting" ? "Connecting…" : "Reconnecting…"}
        </div>
      )}
    </div>
  );
}

const styles: Record<string, CSSProperties> = {
  header: {
    position: "absolute",
    top: 0,
    left: 0,
    right: 0,
    display: "flex",
    alignItems: "center",
    gap: 14,
    padding: "10px 16px",
    background: "linear-gradient(#05070dcc, #05070d00)",
    pointerEvents: "none",
  },
  brand: { letterSpacing: 4, fontWeight: 700, color: "#ff8800", pointerEvents: "auto" },
  meta: { fontSize: 12, color: "#6b7aa3" },
  user: { fontSize: 13, color: "#8aa0c8" },
  logout: {
    pointerEvents: "auto",
    background: "transparent",
    border: "1px solid #1e2a44",
    color: "#cdd6f4",
    borderRadius: 6,
    padding: "4px 10px",
    cursor: "pointer",
  },
  banner: {
    position: "absolute",
    bottom: 16,
    left: "50%",
    transform: "translateX(-50%)",
    background: "#ff880022",
    border: "1px solid #ff8800",
    color: "#ffb866",
    padding: "6px 14px",
    borderRadius: 20,
    fontSize: 13,
  },
};
