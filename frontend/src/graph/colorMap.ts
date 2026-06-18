import type { GraphLink, GraphNode } from "./types";

// Node / link colour rules — CLAUDE.md "UI colour semantics".
export const COLORS = {
  host: "#4488cc", // blue
  process: "#336699", // muted blue
  ipUnenriched: "#888888", // grey
  ipMalicious: "#ff4444", // red
  campaign: "#ff8800", // neon orange
  domain: "#9b6bcc", // purple (not in the table; distinct hue)
  linkDefault: "#33415588",
  linkThreat: "#ff8800", // orange path to compromised infra
} as const;

export function nodeColor(node: GraphNode): string {
  switch (node.label) {
    case "Host":
      return COLORS.host;
    case "Process":
      return COLORS.process;
    case "IP_Address":
      return node.malicious || node.properties?.is_malicious ? COLORS.ipMalicious : COLORS.ipUnenriched;
    case "Domain":
      return node.malicious || node.properties?.is_malicious ? COLORS.ipMalicious : COLORS.domain;
    case "Threat_Campaign":
      return COLORS.campaign;
    default:
      return COLORS.ipUnenriched;
  }
}

/** Relative node radius — campaigns render larger; malicious nodes a touch larger. */
export function nodeVal(node: GraphNode): number {
  if (node.label === "Threat_Campaign") return 8;
  if (node.label === "Host") return 5;
  if (node.malicious || node.properties?.is_malicious) return 4;
  return 2;
}

function isMaliciousId(id: string, nodes: Map<string, GraphNode>): boolean {
  const n = nodes.get(id);
  return Boolean(n && (n.malicious || n.properties?.is_malicious || n.label === "Threat_Campaign"));
}

/** Links touching a malicious/campaign node glow orange; others are muted. */
export function linkColor(link: GraphLink, nodes: Map<string, GraphNode>): string {
  const s = typeof link.source === "string" ? link.source : (link.source as GraphNode).id;
  const t = typeof link.target === "string" ? link.target : (link.target as GraphNode).id;
  if (link.rel === "PART_OF_CAMPAIGN" || link.rel === "TARGETS") return COLORS.linkThreat;
  if (isMaliciousId(s, nodes) || isMaliciousId(t, nodes)) return COLORS.linkThreat;
  return COLORS.linkDefault;
}
