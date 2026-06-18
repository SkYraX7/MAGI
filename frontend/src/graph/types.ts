// Shared graph + WebSocket message types.

export type NodeLabel =
  | "Host"
  | "Process"
  | "IP_Address"
  | "Domain"
  | "Threat_Campaign";

export interface GraphNode {
  id: string;
  label: NodeLabel | string;
  properties: Record<string, unknown>;
  malicious?: boolean;
  campaign?: string;
  confidence?: number;
}

export interface GraphLink {
  id: string; // `${source}|${target}|${rel}` — matches the backend prune id
  source: string;
  target: string;
  rel: string;
}

// Server -> client WebSocket messages (mirrors the backend realtime contract).
export type WsMessage =
  | { type: "node_add"; data: { id: string; label: string; properties: Record<string, unknown> } }
  | { type: "edge_add"; data: { source: string; target: string; rel: string } }
  | { type: "threat_flag"; data: { node_id: string; campaign: string; confidence: number } }
  | { type: "prune"; data: { removed_edge_ids: string[] } }
  | { type: "pong" };

export function linkId(source: string, target: string, rel: string): string {
  return `${source}|${target}|${rel}`;
}
