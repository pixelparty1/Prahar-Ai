import { useEffect, useMemo, useRef, useState } from "react";
import type { BattleEvent } from "@shared/battle";

interface BattleFeedProps {
  events: BattleEvent[];
}

function getSeverityStyle(severity: BattleEvent["severity"]): { color: string } {
  if (severity === "critical") return { color: "var(--theme-danger)" };
  if (severity === "warning") return { color: "var(--theme-accent)" };
  return { color: "var(--theme-primary)" };
}

export function BattleFeed({ events }: BattleFeedProps) {
  const [autoScroll, setAutoScroll] = useState(true);
  const ref = useRef<HTMLDivElement | null>(null);

  const items = useMemo(() => events.slice(-150), [events]);

  useEffect(() => {
    if (!autoScroll || !ref.current) return;
    ref.current.scrollTop = ref.current.scrollHeight;
  }, [items, autoScroll]);

  return (
    <div className="glass-panel rounded-lg p-4 border border-white/10 h-full flex flex-col">
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-display text-lg">PRAHAAR BATTLE LOG</h3>
        <button
          onClick={() => setAutoScroll((v) => !v)}
          className="px-3 py-1 text-xs border border-white/20 font-mono hover:border-primary/60 transition"
        >
          {autoScroll ? "Pause" : "Resume"}
        </button>
      </div>

      <div ref={ref} className="flex-1 overflow-y-auto border rounded-md p-3 font-mono text-xs space-y-2" style={{ background: "color-mix(in srgb, var(--theme-background) 70%, black)", borderColor: "var(--theme-border)" }}>
        {items.length === 0 ? (
          <div className="text-muted-foreground">Awaiting Oracle commentary...</div>
        ) : (
          items.map((event) => (
            <div key={event.id} className="leading-relaxed" style={getSeverityStyle(event.severity)}>
              [{event.timestamp}] {event.message}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
