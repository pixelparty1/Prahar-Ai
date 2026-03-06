export type Team = "red" | "blue";

export type BattleMode = "demo" | "production";

export type BattlePhase =
  | "Reconnaissance"
  | "Attack"
  | "Defense"
  | "Recovery"
  | "Completed";

export type EventSeverity = "critical" | "warning" | "info";

export type NodeStatus = "idle" | "under-attack" | "defended" | "active";

export interface NetworkNode {
  id: number;
  name: string;
  ip: string;
  status: NodeStatus;
  vulnerabilities?: string[];
  type?: "defense" | "service";
}

export interface NetworkConnection {
  source: number;
  target: number;
}

export interface BattleEvent {
  id: string;
  battleId: string;
  timestamp: string;
  epochMs: number;
  type: "attack" | "defend" | "oracle" | "phase" | "system" | "end";
  severity: EventSeverity;
  actor: "Ghost" | "Aegis" | "Oracle" | "Phantom Eye" | "System";
  message: string;
  targetNodeId?: number;
  scoreDelta?: {
    red?: number;
    blue?: number;
  };
}

export interface BattleScore {
  red: number;
  blue: number;
}

export interface BattleState {
  battleId: string;
  mode: BattleMode;
  status: "running" | "paused" | "ended";
  phase: BattlePhase;
  startedAt: number;
  elapsedMs: number;
  durationMs: number;
  speed: 1 | 2 | 5;
  score: BattleScore;
  winner?: Team | "draw";
  network: {
    nodes: NetworkNode[];
    connections: NetworkConnection[];
  };
  events: BattleEvent[];
}
