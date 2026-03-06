import type { BattleState } from "@shared/battle";

interface StartBattleResponse {
  battle_id: string;
  state: BattleState;
}

async function parseResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export async function startBattle(mode: "demo" | "production"): Promise<StartBattleResponse> {
  const response = await fetch("/api/battle/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode }),
  });

  return parseResponse<StartBattleResponse>(response);
}

export async function getBattleStatus(battleId: string): Promise<BattleState> {
  const response = await fetch(`/api/battle/status/${battleId}`);
  return parseResponse<BattleState>(response);
}

export async function pauseBattle(battleId: string): Promise<BattleState> {
  const response = await fetch(`/api/battle/${battleId}/pause`, { method: "POST" });
  return parseResponse<BattleState>(response);
}

export async function resumeBattle(battleId: string): Promise<BattleState> {
  const response = await fetch(`/api/battle/${battleId}/resume`, { method: "POST" });
  return parseResponse<BattleState>(response);
}

export async function resetBattle(battleId: string): Promise<void> {
  const response = await fetch(`/api/battle/${battleId}/reset`, { method: "POST" });
  await parseResponse<{ message: string }>(response);
}

export async function setBattleSpeed(battleId: string, speed: 1 | 2 | 5): Promise<BattleState> {
  const response = await fetch(`/api/battle/${battleId}/speed`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ speed }),
  });

  return parseResponse<BattleState>(response);
}

export async function getBattleReport(battleId: string): Promise<any> {
  const response = await fetch(`/api/battle/report/${battleId}`);
  return parseResponse<any>(response);
}

export async function analyzeMalware(file: File): Promise<{
  classification: string;
  confidence: number;
  threatLevel: string;
  suspiciousLines: Array<{ line: number; content: string; reason: string }>;
  explanation: string;
}> {
  const form = new FormData();
  form.append("file", file);

  const response = await fetch("/api/malware/analyze", {
    method: "POST",
    body: form,
  });

  return parseResponse(response);
}
