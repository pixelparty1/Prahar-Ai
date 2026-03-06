import { randomUUID } from "crypto";
import type {
  BattleEvent,
  BattleMode,
  BattlePhase,
  BattleState,
  NetworkConnection,
  NetworkNode,
} from "@shared/battle";
import { runGhostAttack } from "../agents/ghost";
import { runAegisDefense } from "../agents/aegis";
import { formatOracleScoreLine, getOraclePhaseLine } from "../agents/oracle";

const PHASE_SEQUENCE: BattlePhase[] = ["Reconnaissance", "Attack", "Defense", "Recovery", "Completed"];

const PRAHAAR_NETWORK_NODES: NetworkNode[] = [
  { id: 1, name: "Web Server", ip: "192.168.1.10", status: "idle", vulnerabilities: ["SQL Injection"], type: "service" },
  { id: 2, name: "Database", ip: "192.168.1.11", status: "idle", vulnerabilities: ["Weak Password"], type: "service" },
  { id: 3, name: "File Server", ip: "192.168.1.15", status: "idle", vulnerabilities: ["Open Port 445"], type: "service" },
  { id: 4, name: "Admin Panel", ip: "192.168.1.20", status: "idle", vulnerabilities: ["XSS"], type: "service" },
  { id: 5, name: "Firewall", ip: "192.168.1.1", status: "active", type: "defense" },
  { id: 6, name: "SOC Console", ip: "192.168.1.30", status: "active", type: "defense" },
];

const PRAHAAR_NETWORK_CONNECTIONS: NetworkConnection[] = [
  { source: 1, target: 2 },
  { source: 1, target: 4 },
  { source: 2, target: 3 },
  { source: 5, target: 1 },
  { source: 5, target: 2 },
  { source: 5, target: 3 },
  { source: 6, target: 5 },
  { source: 6, target: 4 },
];

const DEMO_SEQUENCE = [
  "Ghost: Scanning network for vulnerabilities",
  "Ghost: Open port detected on 192.168.1.10",
  "Ghost: Attempting SQL injection attack",
  "Aegis: Anomaly detected! Analyzing traffic pattern",
  "Aegis: SQL injection blocked - Updating firewall rules",
  "Ghost: Switching to brute force attack on SSH",
  "Ghost: Credentials compromised! Escalating privileges",
  "Aegis: Breach detected - Isolating compromised system",
  "Aegis: Account locked - Rolling back unauthorized changes",
];

interface BattleRuntime {
  state: BattleState;
  timer: NodeJS.Timeout;
  nextAttackAtMs: number;
  scriptedStep: number;
}

type BroadcastFn = (battleId: string, payload: unknown) => void;

export class BattleEngine {
  private readonly battles = new Map<string, BattleRuntime>();

  constructor(private readonly broadcast: BroadcastFn) {}

  start(mode: BattleMode = "demo"): BattleState {
    const battleId = randomUUID();
    const now = Date.now();

    const state: BattleState = {
      battleId,
      mode,
      status: "running",
      phase: "Reconnaissance",
      startedAt: now,
      elapsedMs: 0,
      durationMs: mode === "demo" ? 120_000 : 300_000,
      speed: 1,
      score: { red: 0, blue: 0 },
      network: {
        nodes: PRAHAAR_NETWORK_NODES.map((node) => ({ ...node })),
        connections: PRAHAAR_NETWORK_CONNECTIONS,
      },
      events: [],
    };

    const cadence = mode === "demo" ? 3000 : 5000;
    const timer = setInterval(() => this.tick(battleId, cadence), 500);

    this.battles.set(battleId, {
      state,
      timer,
      nextAttackAtMs: now + cadence,
      scriptedStep: 0,
    });

    this.pushEvent(state, {
      type: "system",
      severity: "info",
      actor: "System",
      message: "[00:00] PRAHAAR battle begins - Network initialized",
    });

    this.pushEvent(state, {
      type: "oracle",
      severity: "info",
      actor: "Oracle",
      message: getOraclePhaseLine("Reconnaissance"),
    });

    this.broadcastState(state);
    return state;
  }

  getStatus(battleId: string): BattleState | undefined {
    return this.battles.get(battleId)?.state;
  }

  pause(battleId: string): BattleState | undefined {
    const runtime = this.battles.get(battleId);
    if (!runtime || runtime.state.status !== "running") {
      return runtime?.state;
    }

    runtime.state.status = "paused";
    this.pushEvent(runtime.state, {
      type: "system",
      severity: "warning",
      actor: "System",
      message: "PRAHAAR simulation paused",
    });
    this.broadcastState(runtime.state);
    return runtime.state;
  }

  resume(battleId: string): BattleState | undefined {
    const runtime = this.battles.get(battleId);
    if (!runtime || runtime.state.status !== "paused") {
      return runtime?.state;
    }

    runtime.state.status = "running";
    runtime.nextAttackAtMs = Date.now() + 1000;
    this.pushEvent(runtime.state, {
      type: "system",
      severity: "info",
      actor: "System",
      message: "PRAHAAR simulation resumed",
    });
    this.broadcastState(runtime.state);
    return runtime.state;
  }

  setSpeed(battleId: string, speed: 1 | 2 | 5): BattleState | undefined {
    const runtime = this.battles.get(battleId);
    if (!runtime) {
      return undefined;
    }

    runtime.state.speed = speed;
    this.pushEvent(runtime.state, {
      type: "system",
      severity: "info",
      actor: "System",
      message: `Simulation speed set to ${speed}x`,
    });
    this.broadcastState(runtime.state);
    return runtime.state;
  }

  reset(battleId: string): void {
    const runtime = this.battles.get(battleId);
    if (!runtime) {
      return;
    }

    clearInterval(runtime.timer);
    this.battles.delete(battleId);
  }

  private tick(battleId: string, attackCadenceMs: number): void {
    const runtime = this.battles.get(battleId);
    if (!runtime) {
      return;
    }

    const { state } = runtime;
    if (state.status !== "running") {
      return;
    }

    const now = Date.now();
    state.elapsedMs = now - state.startedAt;

    if (state.elapsedMs >= state.durationMs) {
      this.finishBattle(runtime);
      return;
    }

    this.updatePhase(state);

    if (now < runtime.nextAttackAtMs) {
      this.broadcastState(state);
      return;
    }

    this.simulateCycle(runtime);
    runtime.nextAttackAtMs = now + Math.max(700, Math.floor(attackCadenceMs / state.speed));

    this.broadcastState(state);
  }

  private simulateCycle(runtime: BattleRuntime): void {
    const { state } = runtime;
    const target = this.getRandomServiceNode(state);

    const ghost = runGhostAttack(runtime.scriptedStep);
    state.score.red += ghost.points;
    target.status = "under-attack";

    this.pushEvent(state, {
      type: "attack",
      severity: "critical",
      actor: "Ghost",
      targetNodeId: target.id,
      scoreDelta: { red: ghost.points },
      message: `🔴 Ghost initiated ${ghost.message.toLowerCase()} on ${target.ip}`,
    });

    this.pushEvent(state, {
      type: "oracle",
      severity: "warning",
      actor: "Oracle",
      message: ghost.oracleLine,
    });

    const responseMs = this.getRandomInt(900, 2800) / state.speed;
    const aegis = runAegisDefense(responseMs, runtime.scriptedStep);
    const bluePoints = aegis.points + aegis.speedBonus;
    state.score.blue += bluePoints;
    target.status = "defended";

    this.pushEvent(state, {
      type: "defend",
      severity: "info",
      actor: "Aegis",
      targetNodeId: target.id,
      scoreDelta: { blue: bluePoints },
      message: `🔵 ${aegis.message} on ${target.ip}`,
    });

    this.pushEvent(state, {
      type: "oracle",
      severity: "info",
      actor: "Oracle",
      message: `${aegis.oracleLine} ${formatOracleScoreLine(0, bluePoints)}`,
    });

    if (state.mode === "demo" && runtime.scriptedStep < DEMO_SEQUENCE.length) {
      this.pushEvent(state, {
        type: "oracle",
        severity: "info",
        actor: "Oracle",
        message: DEMO_SEQUENCE[runtime.scriptedStep],
      });
    }

    runtime.scriptedStep += 1;
    this.resetNodeStates(state);
  }

  private updatePhase(state: BattleState): void {
    const ratio = state.elapsedMs / state.durationMs;
    const phaseIndex = ratio > 0.75 ? 3 : ratio > 0.5 ? 2 : ratio > 0.25 ? 1 : 0;
    const nextPhase = PHASE_SEQUENCE[phaseIndex];

    if (nextPhase !== state.phase) {
      state.phase = nextPhase;
      this.pushEvent(state, {
        type: "phase",
        severity: "warning",
        actor: "Oracle",
        message: getOraclePhaseLine(nextPhase),
      });
    }
  }

  private finishBattle(runtime: BattleRuntime): void {
    const { state } = runtime;
    state.status = "ended";
    state.phase = "Completed";

    if (state.mode === "demo") {
      const diff = state.score.blue - state.score.red;
      if (Math.abs(diff) > 40) {
        state.score.blue = state.score.red + 35;
      }
    }

    state.winner =
      state.score.red > state.score.blue
        ? "red"
        : state.score.blue > state.score.red
          ? "blue"
          : "draw";

    this.pushEvent(state, {
      type: "end",
      severity: "info",
      actor: "Oracle",
      message: `⚖️ Battle concluded! Final Score: Red ${state.score.red} | Blue ${state.score.blue}`,
    });

    clearInterval(runtime.timer);
    this.broadcastState(state);
  }

  private getRandomServiceNode(state: BattleState): NetworkNode {
    const services = state.network.nodes.filter((node) => node.type !== "defense");
    return services[Math.floor(Math.random() * services.length)]!;
  }

  private resetNodeStates(state: BattleState): void {
    for (const node of state.network.nodes) {
      if (node.type === "defense") {
        node.status = "active";
      } else if (node.status !== "under-attack") {
        node.status = "idle";
      }
    }
  }

  private pushEvent(
    state: BattleState,
    input: Omit<BattleEvent, "id" | "battleId" | "timestamp" | "epochMs">,
  ): void {
    const now = Date.now();
    const event: BattleEvent = {
      ...input,
      id: randomUUID(),
      battleId: state.battleId,
      timestamp: new Date(now).toLocaleTimeString("en-US", { hour12: false }),
      epochMs: now,
    };

    state.events.push(event);
    if (state.events.length > 500) {
      state.events.shift();
    }

    this.broadcast(state.battleId, {
      type: "event",
      event,
      state: this.serializeState(state),
    });
  }

  private broadcastState(state: BattleState): void {
    this.broadcast(state.battleId, {
      type: "state",
      state: this.serializeState(state),
    });
  }

  private serializeState(state: BattleState): BattleState {
    return {
      ...state,
      events: state.events.slice(-150),
      network: {
        nodes: state.network.nodes.map((n) => ({ ...n })),
        connections: state.network.connections,
      },
    };
  }

  private getRandomInt(min: number, max: number): number {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }
}
