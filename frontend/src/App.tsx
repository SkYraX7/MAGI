import { useEffect, useRef } from "react";
import type { CSSProperties, PointerEvent as ReactPointerEvent } from "react";
import { useAuth } from "./auth/AuthContext";
import { LoginPage } from "./auth/LoginPage";
import { ThreatGraph } from "./graph/ThreatGraph";
import { LogTrail } from "./graph/LogTrail";
import { useWsGraph } from "./graph/useWsGraph";
import { requestNotificationPermission } from "./graph/notifications";
import type { Dock } from "./graph/types";
import { DockPanel } from "./ui/DockPanel";
import { useElementSize, usePersisted } from "./ui/hooks";

export default function App() {
  const { token, username, role, logout } = useAuth();
  if (!token) return <LoginPage />;
  return <Dashboard token={token} username={username} role={role} onLogout={logout} />;
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
  const { graphData, status, nodeMap, log, clearLog } = useWsGraph(token);
  const [dock, setDock] = usePersisted<Dock>("magi.dock", "right");
  const [size, setSize] = usePersisted<number>("magi.panelSize", 380);
  const graphRef = useRef<HTMLDivElement>(null);
  const dims = useElementSize(graphRef);

  useEffect(() => {
    void requestNotificationPermission();
  }, []);

  const isRow = dock !== "bottom";
  const panel = (
    <div
      style={{
        ...styles.panelSlot,
        flexShrink: 0,
        width: isRow ? size : "auto",
        height: isRow ? "auto" : size,
      }}
    >
      <DockPanel dock={dock} onDock={setDock} title="Live telemetry">
        <LogTrail log={log} onClear={clearLog} />
      </DockPanel>
    </div>
  );
  const divider = <Divider dock={dock} size={size} setSize={setSize} />;

  return (
    <div style={{ ...styles.root, flexDirection: isRow ? "row" : "column" }}>
      {dock === "left" && panel}
      {dock === "left" && divider}

      <div ref={graphRef} style={styles.graphArea}>
        {dims.w > 0 && dims.h > 0 && (
          <ThreatGraph
            nodes={graphData.nodes}
            links={graphData.links}
            nodeMap={nodeMap}
            width={dims.w}
            height={dims.h}
          />
        )}
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

      {(dock === "right" || dock === "bottom") && divider}
      {(dock === "right" || dock === "bottom") && panel}
    </div>
  );
}

/** Draggable divider that resizes the panel (col-resize for side docks, row-resize for bottom). */
function Divider({
  dock,
  size,
  setSize,
}: {
  dock: Dock;
  size: number;
  setSize: (n: number) => void;
}) {
  const isRow = dock !== "bottom";
  const onDown = (e: ReactPointerEvent) => {
    e.preventDefault();
    const start = isRow ? e.clientX : e.clientY;
    const startSize = size;
    const move = (ev: PointerEvent) => {
      const cur = isRow ? ev.clientX : ev.clientY;
      let delta = cur - start;
      // For right/bottom docks the panel grows as the divider moves toward the start.
      if (dock === "right" || dock === "bottom") delta = -delta;
      const max = (isRow ? window.innerWidth : window.innerHeight) * 0.7;
      setSize(Math.max(240, Math.min(startSize + delta, max)));
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };
  return (
    <div
      onPointerDown={onDown}
      style={{ ...styles.divider, ...(isRow ? styles.dividerV : styles.dividerH) }}
    />
  );
}

const styles: Record<string, CSSProperties> = {
  root: { height: "100%", display: "flex" },
  graphArea: { flex: 1, position: "relative", minWidth: 0, minHeight: 0 },
  panelSlot: { display: "flex", background: "#070b14" },
  divider: { background: "#1e2a44", flexShrink: 0 },
  dividerV: { width: 6, cursor: "col-resize", alignSelf: "stretch" },
  dividerH: { height: 6, cursor: "row-resize", width: "100%" },
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
