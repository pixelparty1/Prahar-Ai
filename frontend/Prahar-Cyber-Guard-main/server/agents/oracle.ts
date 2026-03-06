import type { BattlePhase } from "@shared/battle";

const PHASE_LINES: Record<BattlePhase, string> = {
  Reconnaissance: "⚖️ Oracle: Recon phase active. Attack surface mapping in progress.",
  Attack: "⚖️ Oracle: Attack phase engaged. Hostile activity increasing.",
  Defense: "⚖️ Oracle: Defense phase active. Countermeasures deployed.",
  Recovery: "⚖️ Oracle: Recovery operations underway. Systems stabilizing.",
  Completed: "⚖️ Oracle: Engagement complete. Final score locked.",
};

export function getOraclePhaseLine(phase: BattlePhase): string {
  return PHASE_LINES[phase];
}

export function formatOracleScoreLine(redDelta = 0, blueDelta = 0): string {
  if (redDelta > 0 && blueDelta > 0) {
    return `⚖️ Oracle: Both teams score this cycle. Red +${redDelta}, Blue +${blueDelta}`;
  }

  if (redDelta > 0) {
    return `⚖️ Oracle: Red Team scores +${redDelta} points for offensive momentum.`;
  }

  if (blueDelta > 0) {
    return `⚖️ Oracle: Blue Team scores +${blueDelta} points for rapid response.`;
  }

  return "⚖️ Oracle: Tactical stalemate.";
}
