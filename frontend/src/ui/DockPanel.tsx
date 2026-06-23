import { useState } from "react";
import type { CSSProperties, PointerEvent as ReactPointerEvent, ReactNode } from "react";
import type { Dock } from "../graph/types";

interface Props {
  dock: Dock;
  onDock: (d: Dock) => void;
  title: string;
  children: ReactNode;
}

/** Nearest dock edge for a pointer position (top is not a dock target). */
function nearestEdge(x: number, y: number): Dock {
  const dl = x;
  const dr = window.innerWidth - x;
  const db = window.innerHeight - y;
  const m = Math.min(dl, dr, db);
  if (m === db) return "bottom";
  return m === dl ? "left" : "right";
}

/**
 * A docked panel with a draggable title bar: drag it toward any edge to re-snap
 * (left / right / bottom), or use the dock buttons. Shows a snap preview while dragging.
 */
export function DockPanel({ dock, onDock, title, children }: Props) {
  const [preview, setPreview] = useState<Dock | null>(null);

  const startDrag = (e: ReactPointerEvent) => {
    e.preventDefault();
    const move = (ev: PointerEvent) => setPreview(nearestEdge(ev.clientX, ev.clientY));
    const up = (ev: PointerEvent) => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      setPreview(null);
      onDock(nearestEdge(ev.clientX, ev.clientY));
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  return (
    <div style={styles.panel}>
      <div style={styles.header} onPointerDown={startDrag} title="Drag to re-dock">
        <span style={styles.grip}>⠿</span>
        <span style={styles.title}>{title}</span>
        <span style={{ flex: 1 }} />
        <DockButton edge="left" active={dock === "left"} onDock={onDock} label="◧" />
        <DockButton edge="bottom" active={dock === "bottom"} onDock={onDock} label="⬓" />
        <DockButton edge="right" active={dock === "right"} onDock={onDock} label="◨" />
      </div>
      <div style={styles.body}>{children}</div>
      {preview && <SnapPreview edge={preview} />}
    </div>
  );
}

function DockButton({
  edge,
  active,
  onDock,
  label,
}: {
  edge: Dock;
  active: boolean;
  onDock: (d: Dock) => void;
  label: string;
}) {
  return (
    <button
      onPointerDown={(e) => e.stopPropagation()} // don't start a header drag
      onClick={() => onDock(edge)}
      title={`Dock ${edge}`}
      style={{ ...styles.dockBtn, ...(active ? styles.dockBtnActive : null) }}
    >
      {label}
    </button>
  );
}

function SnapPreview({ edge }: { edge: Dock }) {
  const byEdge: Record<Dock, CSSProperties> = {
    left: { left: 0, top: 0, bottom: 0, width: "33vw" },
    right: { right: 0, top: 0, bottom: 0, width: "33vw" },
    bottom: { left: 0, right: 0, bottom: 0, height: "33vh" },
  };
  return <div style={{ ...styles.snap, ...byEdge[edge] }} />;
}

const styles: Record<string, CSSProperties> = {
  panel: {
    width: "100%",
    height: "100%",
    display: "flex",
    flexDirection: "column",
    minWidth: 0,
    minHeight: 0,
    background: "#070b14",
    color: "#cdd6f4",
  },
  header: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    padding: "6px 8px",
    background: "#0b1020",
    borderBottom: "1px solid #1e2a44",
    cursor: "grab",
    userSelect: "none",
  },
  grip: { color: "#46527a", fontSize: 14 },
  title: { fontSize: 12, letterSpacing: 1, color: "#8aa0c8", textTransform: "uppercase" },
  body: { flex: 1, minHeight: 0, minWidth: 0, overflow: "hidden" },
  dockBtn: {
    background: "transparent",
    border: "1px solid #1e2a44",
    color: "#8aa0c8",
    borderRadius: 5,
    width: 24,
    height: 22,
    cursor: "pointer",
    fontSize: 12,
    lineHeight: 1,
  },
  dockBtnActive: { borderColor: "#4488cc", color: "#cfe3ff", background: "#13315533" },
  snap: {
    position: "fixed",
    background: "#4488cc26",
    border: "2px solid #4488cc",
    pointerEvents: "none",
    zIndex: 1000,
  },
};
