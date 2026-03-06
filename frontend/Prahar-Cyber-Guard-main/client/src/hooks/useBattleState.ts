import { useCallback, useMemo, useState } from "react";
import { jsPDF } from "jspdf";
import type { BattleEvent, BattleState } from "@shared/battle";
import {
  getBattleReport,
  pauseBattle,
  resetBattle,
  resumeBattle,
  setBattleSpeed,
  startBattle,
} from "@/services/battleService";
import { useBattleWebSocket } from "./useBattleWebSocket";

export function useBattleState() {
  const [battleId, setBattleId] = useState<string | null>(null);
  const [state, setState] = useState<BattleState | null>(null);
  const [latestEvent, setLatestEvent] = useState<BattleEvent | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<"idle" | "live">("idle");
  const [mode, setMode] = useState<"demo" | "production">("demo");

  const handleSocketMessage = useCallback((payload: any) => {
    if (payload.type === "system" && payload.message === "Battle stream connected") {
      setConnectionStatus("live");
    }

    if (payload.state) {
      setState(payload.state as BattleState);
    }

    if (payload.event) {
      setLatestEvent(payload.event as BattleEvent);
    }
  }, []);

  useBattleWebSocket(battleId, handleSocketMessage);

  const start = useCallback(async () => {
    const response = await startBattle(mode);
    setBattleId(response.battle_id);
    setState(response.state);
  }, [mode]);

  const pause = useCallback(async () => {
    if (!battleId) return;
    setState(await pauseBattle(battleId));
  }, [battleId]);

  const resume = useCallback(async () => {
    if (!battleId) return;
    setState(await resumeBattle(battleId));
  }, [battleId]);

  const reset = useCallback(async () => {
    if (!battleId) return;
    await resetBattle(battleId);
    setBattleId(null);
    setState(null);
    setLatestEvent(null);
    setConnectionStatus("idle");
  }, [battleId]);

  const setSpeed = useCallback(async (speed: 1 | 2 | 5) => {
    if (!battleId) return;
    setState(await setBattleSpeed(battleId, speed));
  }, [battleId]);

  const exportReport = useCallback(async () => {
    if (!battleId) return;

    const report = await getBattleReport(battleId);
    const pdf = new jsPDF();

    pdf.setFontSize(16);
    pdf.text("PRAHAAR - AUTONOMOUS CYBERWAR SYSTEM", 10, 15);
    pdf.setFontSize(11);
    pdf.text(`Battle ID: ${report.battleId}`, 10, 24);
    pdf.text(`Mode: ${report.mode}`, 10, 31);
    pdf.text(`Score: Red ${report.score.red} | Blue ${report.score.blue}`, 10, 38);
    pdf.text(`Winner: ${report.winner}`, 10, 45);

    let y = 55;
    pdf.text("Battle Log:", 10, y);
    y += 6;

    for (const event of (report.events || []).slice(-20)) {
      const line = `[${event.timestamp}] ${event.message}`;
      const wrapped = pdf.splitTextToSize(line, 185);
      pdf.text(wrapped, 10, y);
      y += wrapped.length * 5;

      if (y > 275) {
        pdf.addPage();
        y = 20;
      }
    }

    pdf.save(`prahaar-battle-report-${battleId}.pdf`);
  }, [battleId]);

  const controls = useMemo(
    () => ({
      start,
      pause,
      resume,
      reset,
      setSpeed,
      exportReport,
      setMode,
    }),
    [start, pause, resume, reset, setSpeed, exportReport],
  );

  return {
    battleId,
    mode,
    state,
    latestEvent,
    connectionStatus,
    controls,
  };
}
