import type { BattleState } from "@shared/battle";

interface ControlsProps {
  mode: "demo" | "production";
  state: BattleState | null;
  connectionStatus: "idle" | "live";
  onStart: () => Promise<void>;
  onPause: () => Promise<void>;
  onResume: () => Promise<void>;
  onReset: () => Promise<void>;
  onSetSpeed: (speed: 1 | 2 | 5) => Promise<void>;
  onExport: () => Promise<void>;
  onModeChange: (mode: "demo" | "production") => void;
}

const speedMarks: Array<1 | 2 | 5> = [1, 2, 5];

export function Controls({
  mode,
  state,
  connectionStatus,
  onStart,
  onPause,
  onResume,
  onReset,
  onSetSpeed,
  onExport,
  onModeChange,
}: ControlsProps) {
  const status = state?.status;
  const currentSpeed = state?.speed || 1;

  return (
    <div className="glass-panel rounded-lg p-4 border border-white/10">
      <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
        <button
          onClick={onStart}
          className="px-4 py-2 border animate-pulse"
          style={{ borderColor: "var(--theme-danger)", background: "color-mix(in srgb, var(--theme-danger) 22%, transparent)", color: "var(--theme-text-primary)" }}
        >
          Start Battle
        </button>

        <button onClick={onPause} disabled={status !== "running"} className="px-3 py-2 border disabled:opacity-40" style={{ borderColor: "var(--theme-border)" }}>
          Pause
        </button>

        <button onClick={onResume} disabled={status !== "paused"} className="px-3 py-2 border disabled:opacity-40" style={{ borderColor: "var(--theme-border)" }}>
          Resume
        </button>

        <button onClick={onReset} disabled={!state} className="px-3 py-2 border disabled:opacity-40" style={{ borderColor: "var(--theme-border)" }}>
          Reset
        </button>

        <button onClick={onExport} disabled={!state} className="px-3 py-2 border disabled:opacity-40" style={{ borderColor: "var(--theme-border)" }}>
          Export Report
        </button>

        <select
          className="px-2 py-2"
          style={{ background: "var(--theme-surface)", border: "1px solid var(--theme-border)", color: "var(--theme-text-primary)" }}
          value={mode}
          onChange={(event) => onModeChange(event.target.value as "demo" | "production")}
        >
          <option value="demo">Demo Mode</option>
          <option value="production">Production Mode</option>
        </select>

        <div className="inline-flex items-center gap-2">
          <span>Speed</span>
          <input
            type="range"
            min={0}
            max={2}
            step={1}
            value={speedMarks.indexOf(currentSpeed)}
            onChange={(event) => onSetSpeed(speedMarks[Number(event.target.value)])}
            disabled={!state}
          />
          <span>{currentSpeed}x</span>
        </div>

        <div className="ml-auto text-muted-foreground">WS: {connectionStatus}</div>
      </div>
    </div>
  );
}
