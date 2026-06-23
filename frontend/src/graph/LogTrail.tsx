import { useEffect, useRef, useState } from "react";
import type { CSSProperties } from "react";
import type { LogEntry } from "./types";

const SEV_COLOR: Record<string, string> = {
  info: "#8aa0c8",
  warn: "#ffb866",
  threat: "#ff6b6b",
};

/** Scrolling, terminal-style feed of live WebSocket telemetry events. */
export function LogTrail({ log, onClear }: { log: LogEntry[]; onClear: () => void }) {
  const [threatsOnly, setThreatsOnly] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const stick = useRef(true); // auto-follow unless the user scrolls up

  const shown = threatsOnly ? log.filter((e) => e.severity === "threat") : log;

  useEffect(() => {
    const el = scrollRef.current;
    if (el && stick.current) el.scrollTop = el.scrollHeight;
  }, [log, threatsOnly]);

  const onScroll = () => {
    const el = scrollRef.current;
    if (el) stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  };

  return (
    <div style={styles.wrap}>
      <div style={styles.toolbar}>
        <label style={styles.toggle}>
          <input
            type="checkbox"
            checked={threatsOnly}
            onChange={(e) => setThreatsOnly(e.target.checked)}
          />
          threats only
        </label>
        <span style={{ flex: 1 }} />
        <span style={styles.count}>{log.length} events</span>
        <button style={styles.clear} onClick={onClear} title="Clear the trail">
          clear
        </button>
      </div>
      <div ref={scrollRef} onScroll={onScroll} style={styles.list}>
        {shown.length === 0 ? (
          <div style={styles.empty}>waiting for telemetry…</div>
        ) : (
          shown.map((e) => (
            <div
              key={e.id}
              style={{ ...styles.line, ...(e.severity === "threat" ? styles.threatLine : null) }}
            >
              <span style={styles.time}>{new Date(e.ts).toLocaleTimeString()}</span>
              <span style={{ color: SEV_COLOR[e.severity] ?? "#cdd6f4" }}>{e.text}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

const styles: Record<string, CSSProperties> = {
  wrap: { display: "flex", flexDirection: "column", height: "100%", minHeight: 0 },
  toolbar: {
    display: "flex",
    alignItems: "center",
    gap: 10,
    padding: "5px 8px",
    borderBottom: "1px solid #131c30",
    fontSize: 12,
    color: "#6b7aa3",
  },
  toggle: { display: "flex", alignItems: "center", gap: 5, cursor: "pointer", userSelect: "none" },
  count: { fontVariantNumeric: "tabular-nums" },
  clear: {
    background: "transparent",
    border: "1px solid #1e2a44",
    color: "#8aa0c8",
    borderRadius: 5,
    padding: "2px 8px",
    cursor: "pointer",
  },
  list: {
    flex: 1,
    minHeight: 0,
    overflowY: "auto",
    padding: "4px 8px",
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
    fontSize: 12,
    lineHeight: 1.55,
  },
  line: { display: "flex", gap: 10, whiteSpace: "pre", overflow: "hidden", textOverflow: "ellipsis" },
  threatLine: { background: "#ff4d4d12", borderRadius: 3 },
  time: { color: "#46527a", flexShrink: 0 },
  empty: { color: "#46527a", padding: 12, fontStyle: "italic" },
};
