import ForceGraph3D from "react-force-graph-3d";
import { linkColor, nodeColor, nodeVal } from "./colorMap";
import type { GraphLink, GraphNode } from "./types";

interface Props {
  nodes: GraphNode[];
  links: GraphLink[];
  nodeMap: Map<string, GraphNode>;
}

/** react-force-graph-3d wrapper applying MAGI's colour + size semantics. */
export function ThreatGraph({ nodes, links, nodeMap }: Props) {
  return (
    <ForceGraph3D
      graphData={{ nodes, links }}
      backgroundColor="#05070d"
      nodeColor={(n) => nodeColor(n as GraphNode)}
      nodeVal={(n) => nodeVal(n as GraphNode)}
      nodeLabel={(n) => nodeLabelHtml(n as GraphNode)}
      nodeOpacity={0.95}
      nodeResolution={12}
      linkColor={(l) => linkColor(l as GraphLink, nodeMap)}
      linkWidth={(l) => ((l as GraphLink).rel === "PART_OF_CAMPAIGN" ? 2 : 0.5)}
      linkDirectionalParticles={(l) => (isThreatLink(l as GraphLink, nodeMap) ? 4 : 0)}
      linkDirectionalParticleWidth={2}
      linkDirectionalParticleColor={() => "#ff8800"}
      warmupTicks={20}
      cooldownTime={4000}
    />
  );
}

function isThreatLink(link: GraphLink, nodes: Map<string, GraphNode>): boolean {
  const s = typeof link.source === "string" ? link.source : (link.source as GraphNode).id;
  const t = typeof link.target === "string" ? link.target : (link.target as GraphNode).id;
  const mal = (id: string) => {
    const n = nodes.get(id);
    return Boolean(n && (n.malicious || n.properties?.is_malicious || n.label === "Threat_Campaign"));
  };
  return link.rel === "PART_OF_CAMPAIGN" || link.rel === "TARGETS" || mal(s) || mal(t);
}

function nodeLabelHtml(n: GraphNode): string {
  const name = (n.properties?.name as string) || (n.properties?.address as string) || n.id;
  const extra = n.malicious ? ` — ⚠ ${n.campaign ?? "threat"}` : "";
  return `${n.label}: ${name}${extra}`;
}
