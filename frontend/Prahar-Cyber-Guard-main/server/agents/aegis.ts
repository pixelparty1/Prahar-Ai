const DEFENSE_RESPONSES = [
  "Anomaly detected - Blocking suspicious IP",
  "Patching SQL injection vulnerability",
  "Locking compromised account",
  "Firewall rule updated",
  "Threat contained - System restored",
  "Compromised segment isolated",
];

const ORACLE_DEFENSE_LINES = [
  "Oracle: Aegis neutralized the threat with rapid containment.",
  "Oracle: Blue Team response was disciplined and effective.",
  "Oracle: Defensive posture remains resilient under pressure.",
];

export interface AegisDefense {
  message: string;
  points: number;
  speedBonus: number;
  oracleLine: string;
}

export function runAegisDefense(responseMs: number, scriptedIndex?: number): AegisDefense {
  const message =
    scriptedIndex !== undefined
      ? DEFENSE_RESPONSES[scriptedIndex % DEFENSE_RESPONSES.length]
      : DEFENSE_RESPONSES[Math.floor(Math.random() * DEFENSE_RESPONSES.length)];

  const points = 10 + Math.floor(Math.random() * 21);
  const speedBonus = responseMs <= 1300 ? 10 : responseMs <= 2200 ? 5 : 0;
  const oracleLine = ORACLE_DEFENSE_LINES[Math.floor(Math.random() * ORACLE_DEFENSE_LINES.length)];

  return {
    message,
    points,
    speedBonus,
    oracleLine,
  };
}
