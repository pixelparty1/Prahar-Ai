import { useEffect, useRef } from "react";
import * as d3 from "d3";
import type { BattleState, NetworkConnection, NetworkNode } from "@shared/battle";

interface NetworkGraphProps {
  state: BattleState | null;
}

type SimNode = NetworkNode & d3.SimulationNodeDatum;
type SimLink = NetworkConnection & d3.SimulationLinkDatum<SimNode>;

function nodeColor(status: NetworkNode["status"]): string {
  if (status === "under-attack") return getComputedStyle(document.documentElement).getPropertyValue("--theme-danger").trim() || "#ef4444";
  if (status === "defended" || status === "active") return getComputedStyle(document.documentElement).getPropertyValue("--theme-primary").trim() || "#38bdf8";
  return getComputedStyle(document.documentElement).getPropertyValue("--theme-text-secondary").trim() || "#64748b";
}

export function NetworkGraph({ state }: NetworkGraphProps) {
  const svgRef = useRef<SVGSVGElement | null>(null);

  useEffect(() => {
    if (!svgRef.current || !state) return;

    const width = svgRef.current.clientWidth || 500;
    const height = svgRef.current.clientHeight || 330;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const nodes: SimNode[] = state.network.nodes.map((node) => ({ ...node }));
    const links: SimLink[] = state.network.connections.map((edge) => ({
      ...edge,
      source: edge.source,
      target: edge.target,
    }));

    const link = svg
      .append("g")
      .attr("stroke", getComputedStyle(document.documentElement).getPropertyValue("--theme-border").trim() || "#1e293b")
      .attr("stroke-opacity", 0.9)
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke-width", 1.5)
      .attr("stroke-dasharray", "5 3");

    const nodeGroup = svg.append("g").selectAll("g").data(nodes).join("g");

    nodeGroup
      .append("circle")
      .attr("r", 13)
      .attr("fill", (node: SimNode) => nodeColor(node.status))
      .attr("stroke", "#0b1220")
      .attr("stroke-width", 2)
      .append("title")
      .text((node: SimNode) => `${node.name} (${node.ip})`);

    nodeGroup
      .append("text")
      .text((node: SimNode) => node.name)
      .attr("x", 17)
      .attr("y", 4)
      .attr("fill", getComputedStyle(document.documentElement).getPropertyValue("--theme-text-primary").trim() || "#cbd5e1")
      .attr("font-size", "10px")
      .attr("font-family", "JetBrains Mono, monospace");

    const simulation = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3
          .forceLink<SimNode, SimLink>(links)
          .id((node: SimNode) => String(node.id))
          .distance(95),
      )
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide(38))
      .on("tick", () => {
        link
          .attr("x1", (line: SimLink) => (line.source as SimNode).x || 0)
          .attr("y1", (line: SimLink) => (line.source as SimNode).y || 0)
          .attr("x2", (line: SimLink) => (line.target as SimNode).x || 0)
          .attr("y2", (line: SimLink) => (line.target as SimNode).y || 0);

        nodeGroup.attr("transform", (node: SimNode) => `translate(${node.x || 0},${node.y || 0})`);
      });

    return () => {
      simulation.stop();
    };
  }, [state]);

  return (
    <div className="glass-panel rounded-lg p-4 border border-white/10 h-full">
      <h3 className="font-display text-lg mb-2">PRAHAAR NETWORK MONITOR</h3>
      <svg ref={svgRef} className="w-full h-[320px] bg-black/25 border border-white/10 rounded" />
      <div className="text-[10px] mt-2 font-mono text-muted-foreground">
        Real-time node states: red attack, blue defended, gray idle.
      </div>
    </div>
  );
}
