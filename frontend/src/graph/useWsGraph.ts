import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { showThreatToast } from "./notifications";
import type { GraphLink, GraphNode, WsMessage } from "./types";
import { linkId } from "./types";

export type WsStatus = "connecting" | "open" | "reconnecting";

const BASE_MS = 500;
const MAX_MS = 30_000;

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
 * Live graph over the WebSocket. Reconnects with exponential backoff + jitter and
 * preserves the last-known graph across the gap so the view never wipes; the backend
 * replays current nodes/edges on (re)connect.
 */
export function useWsGraph(token: string | null) {
  // Stable maps so react-force-graph keeps node positions across updates.
  const nodes = useRef(new Map<string, GraphNode>());
  const links = useRef(new Map<string, GraphLink>());
  const [version, setVersion] = useState(0);
  const [status, setStatus] = useState<WsStatus>("connecting");

  const wsRef = useRef<WebSocket | null>(null);
  const attempt = useRef(0);
  const timer = useRef<number | undefined>(undefined);
  const closedByUs = useRef(false);

  const bump = useCallback(() => setVersion((v) => v + 1), []);

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
          showThreatToast(msg.data);
          break;
        }
        case "prune": {
          let changed = false;
          for (const id of msg.data.removed_edge_ids) {
            if (links.current.delete(id)) changed = true;
          }
          if (changed) bump();
          break;
        }
        default:
          break; // pong / unknown
      }
    },
    [bump],
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

  return { graphData, status, nodeMap: nodes.current };
}
