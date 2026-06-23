import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { showThreatToast } from "./notifications";
import type { GraphLink, GraphNode, LogEntry, LogSeverity, WsMessage } from "./types";
import { linkId } from "./types";

export type WsStatus = "connecting" | "open" | "reconnecting";

const BASE_MS = 500;
const MAX_MS = 30_000;
const MAX_LOG = 300;

function short(s: string, n = 16): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

function wsUrl(token: string): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const base = import.meta.env.VITE_WS_BASE ?? `${proto}//${window.location.host}`;
  return `${base}/ws/live-threats?token=${encodeURIComponent(token)}`;
}

interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

/**
 * Live graph + telemetry trail over the WebSocket. Reconnects with exponential backoff
 * + jitter and preserves the last-known graph across the gap so the view never wipes;
 * the backend replays current nodes/edges on (re)connect.
 */
export function useWsGraph(token: string | null) {
  // Stable maps so react-force-graph keeps node positions across updates.
  const nodes = useRef(new Map<string, GraphNode>());
  const links = useRef(new Map<string, GraphLink>());
  const [version, setVersion] = useState(0);
  const [status, setStatus] = useState<WsStatus>("connecting");

  // Bounded telemetry log, versioned separately so log updates don't rebuild graphData.
  const logRef = useRef<LogEntry[]>([]);
  const logSeq = useRef(0);
  const [logVersion, setLogVersion] = useState(0);

  const wsRef = useRef<WebSocket | null>(null);
  const attempt = useRef(0);
  const timer = useRef<number | undefined>(undefined);
  const closedByUs = useRef(false);

  const bump = useCallback(() => setVersion((v) => v + 1), []);

  const pushLog = useCallback((severity: LogSeverity, kind: string, text: string) => {
    const arr = logRef.current;
    arr.push({ id: logSeq.current++, ts: Date.now(), severity, kind, text });
    if (arr.length > MAX_LOG) arr.splice(0, arr.length - MAX_LOG);
    setLogVersion((v) => v + 1);
  }, []);

  const clearLog = useCallback(() => {
    logRef.current = [];
    setLogVersion((v) => v + 1);
  }, []);

  const applyMessage = useCallback(
    (msg: WsMessage) => {
      switch (msg.type) {
        case "node_add": {
          const existing = nodes.current.get(msg.data.id);
          if (existing) {
            existing.label = msg.data.label;
            existing.properties = { ...existing.properties, ...msg.data.properties };
          } else {
            nodes.current.set(msg.data.id, {
              id: msg.data.id,
              label: msg.data.label,
              properties: msg.data.properties,
            });
            const p = msg.data.properties || {};
            const name = (p.name as string) || (p.address as string) || short(msg.data.id);
            pushLog("info", "node_add", `NODE   ${msg.data.label}  ${name}`);
          }
          bump();
          break;
        }
        case "edge_add": {
          const id = linkId(msg.data.source, msg.data.target, msg.data.rel);
          if (!links.current.has(id)) {
            links.current.set(id, {
              id,
              source: msg.data.source,
              target: msg.data.target,
              rel: msg.data.rel,
            });
            pushLog(
              "info",
              "edge_add",
              `EDGE   ${short(msg.data.source)} —${msg.data.rel}→ ${short(msg.data.target)}`,
            );
            bump();
          }
          break;
        }
        case "threat_flag": {
          const node = nodes.current.get(msg.data.node_id);
          if (node) {
            node.malicious = true;
            node.campaign = msg.data.campaign;
            node.confidence = msg.data.confidence;
            node.properties = { ...node.properties, is_malicious: true };
            bump();
          }
          pushLog(
            "threat",
            "threat_flag",
            `THREAT ${msg.data.node_id}  ${msg.data.campaign}  ${Math.round(msg.data.confidence * 100)}%`,
          );
          showThreatToast(msg.data);
          break;
        }
        case "prune": {
          let changed = false;
          for (const id of msg.data.removed_edge_ids) {
            if (links.current.delete(id)) changed = true;
          }
          if (changed) {
            pushLog("warn", "prune", `PRUNE  removed ${msg.data.removed_edge_ids.length} edge(s)`);
            bump();
          }
          break;
        }
        default:
          break; // pong / unknown
      }
    },
    [bump, pushLog],
  );

  useEffect(() => {
    if (!token) return;
    closedByUs.current = false;

    const connect = () => {
      setStatus(attempt.current === 0 ? "connecting" : "reconnecting");
      const ws = new WebSocket(wsUrl(token));
      wsRef.current = ws;

      ws.onopen = () => {
        attempt.current = 0; // reset backoff on a successful open
        setStatus("open");
      };
      ws.onmessage = (ev) => {
        try {
          applyMessage(JSON.parse(ev.data) as WsMessage);
        } catch {
          /* ignore malformed frame */
        }
      };
      ws.onclose = () => {
        if (closedByUs.current) return;
        const delay = Math.min(BASE_MS * 2 ** attempt.current + Math.random() * 1000, MAX_MS);
        attempt.current += 1;
        setStatus("reconnecting");
        timer.current = window.setTimeout(connect, delay);
      };
      ws.onerror = () => ws.close();
    };

    // Keepalive ping every 25s.
    const ping = window.setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: "ping" }));
      }
    }, 25_000);

    connect();

    return () => {
      closedByUs.current = true;
      window.clearInterval(ping);
      if (timer.current) window.clearTimeout(timer.current);
      wsRef.current?.close();
    };
  }, [token, applyMessage]);

  const graphData = useMemo<GraphData>(
    () => ({ nodes: [...nodes.current.values()], links: [...links.current.values()] }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [version],
  );

  const log = useMemo<LogEntry[]>(
    () => logRef.current.slice(),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [logVersion],
  );

  return { graphData, status, nodeMap: nodes.current, log, clearLog };
}
