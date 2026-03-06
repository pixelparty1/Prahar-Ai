const ATTACK_PATTERNS = [
  "Port scan on target network",
  "SQL injection attempt on web server",
  "Brute force SSH credentials",
  "Privilege escalation attempt",
  "Data exfiltration simulation",
  "Lateral movement through internal host",
];

const ORACLE_ATTACK_LINES = [
  "Oracle: Ghost exploited a weak path to gain foothold. Critical move!",
  "Oracle: Red Team adapts strategy and pivots laterally.",
  "Oracle: Ghost is escalating pressure across multiple vectors.",
];

export interface GhostAttack {
  message: string;
  points: number;
  oracleLine: string;
}

export function runGhostAttack(scriptedIndex?: number): GhostAttack {
  const message =
    scriptedIndex !== undefined
      ? ATTACK_PATTERNS[scriptedIndex % ATTACK_PATTERNS.length]
      : ATTACK_PATTERNS[Math.floor(Math.random() * ATTACK_PATTERNS.length)];

  const points = 10 + Math.floor(Math.random() * 41);
  const oracleLine = ORACLE_ATTACK_LINES[Math.floor(Math.random() * ORACLE_ATTACK_LINES.length)];

  return {
    message,
    points,
    oracleLine,
  };
}
