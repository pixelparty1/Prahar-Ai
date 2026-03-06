import type { BattleState } from "@shared/battle";

interface ScoreboardProps {
  state: BattleState | null;
}

function formatMs(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const min = String(Math.floor(totalSeconds / 60)).padStart(2, "0");
  const sec = String(totalSeconds % 60).padStart(2, "0");
  return `${min}:${sec}`;
}

export function Scoreboard({ state }: ScoreboardProps) {
  if (!state) {
    return (
      <div className="glass-panel rounded-lg p-4 border border-white/10">
        <h2 className="font-display text-xl">PRAHAAR - AUTONOMOUS CYBERWAR SYSTEM</h2>
        <div className="mt-2 text-sm font-mono text-muted-foreground">No active battle. Begin when ready.</div>
      </div>
    );
  }

  const verdict =
    state.status === "ended"
      ? state.winner === "red"
        ? "🔴 Red Team Victory"
        : state.winner === "blue"
          ? "🔵 Blue Team Victory"
          : "⚖️ Draw"
      : "⚔️ Battle in Progress";

  return (
    <div className="glass-panel rounded-lg p-4 border border-white/10" style={{ boxShadow: "0 0 30px var(--theme-border)" }}>
      <h2 className="font-display text-lg md:text-xl mb-3">PRAHAAR - AUTONOMOUS CYBERWAR SYSTEM</h2>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono">
        <div>
          <div className="text-xs" style={{ color: "var(--theme-danger)" }}>🔴 Red Team</div>
          <div className="text-2xl font-bold" style={{ color: "var(--theme-danger)" }}>{state.score.red} pts</div>
        </div>
        <div>
          <div className="text-xs" style={{ color: "var(--theme-primary)" }}>🔵 Blue Team</div>
          <div className="text-2xl font-bold" style={{ color: "var(--theme-primary)" }}>{state.score.blue} pts</div>
        </div>
        <div>
          <div className="text-xs text-muted-foreground">Timer</div>
          <div className="text-2xl font-bold">{formatMs(state.elapsedMs)}</div>
        </div>
        <div>
          <div className="text-xs text-muted-foreground">Phase</div>
          <div className="text-lg font-semibold" style={{ color: "var(--theme-accent)" }}>{state.phase}</div>
        </div>
      </div>
      <div className="mt-3 text-xs font-mono text-muted-foreground uppercase tracking-wider">{verdict}</div>
    </div>
  );
}
