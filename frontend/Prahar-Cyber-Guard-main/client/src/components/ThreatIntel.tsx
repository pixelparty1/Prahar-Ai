import { useEffect, useState } from "react";
import { fetchThreatIntel, type ThreatIntelPayload } from "@/services/threatIntelService";

export function ThreatIntel() {
  const [intel, setIntel] = useState<ThreatIntelPayload | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let mounted = true;

    const load = async () => {
      setLoading(true);
      try {
        const payload = await fetchThreatIntel();
        if (mounted) setIntel(payload);
      } finally {
        if (mounted) setLoading(false);
      }
    };

    load();
    const timer = setInterval(load, 30000);

    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, []);

  return (
    <div className="glass-panel rounded-lg p-4 border border-white/10 h-full flex flex-col">
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-display text-lg">PRAHAAR THREAT INTEL</h3>
        <span
          className="text-xs font-mono px-2 py-1 rounded border"
          style={{
            borderColor: "var(--theme-danger)",
            color: "var(--theme-danger)",
            background: "color-mix(in srgb, var(--theme-danger) 18%, transparent)",
          }}
        >
          Active: {intel?.activeThreatCount ?? 0}
        </span>
      </div>

      <div className="text-xs font-mono text-muted-foreground mb-2">Today's Top 5 Threats</div>

      {loading && !intel ? (
        <div className="text-sm text-muted-foreground">Loading live threat feed...</div>
      ) : (
        <div className="space-y-2 overflow-y-auto pr-1">
          {(intel?.topThreats || []).slice(0, 5).map((threat) => (
            <div key={threat.id} className="border rounded-md p-2" style={{ borderColor: "var(--theme-border)", background: "color-mix(in srgb, var(--theme-background) 65%, black)" }}>
              <div className="flex items-center justify-between">
                <span className="font-mono text-[11px]" style={{ color: "var(--theme-primary)" }}>{threat.id}</span>
                <span className="font-mono text-[11px]" style={{ color: "var(--theme-accent)" }}>{threat.severity}</span>
              </div>
              <div className="text-[11px] text-muted-foreground mt-1 line-clamp-3">{threat.summary}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
