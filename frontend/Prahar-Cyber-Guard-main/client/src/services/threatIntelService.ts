export interface ThreatItem {
  id: string;
  published: string;
  severity: string;
  score: number;
  summary: string;
}

export interface ThreatIntelPayload {
  source: string;
  timestamp: string;
  activeThreatCount: number;
  topThreats: ThreatItem[];
  activeThreats: Array<{ title: string; severity: string; source: string }>;
}

export async function fetchThreatIntel(): Promise<ThreatIntelPayload> {
  const response = await fetch("/api/threats/live");
  if (!response.ok) {
    throw new Error(`Threat fetch failed: ${response.status}`);
  }

  return response.json() as Promise<ThreatIntelPayload>;
}
