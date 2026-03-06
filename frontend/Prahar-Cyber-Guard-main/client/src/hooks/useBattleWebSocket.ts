import { useEffect } from "react";

export function useBattleWebSocket(
  battleId: string | null,
  onMessage: (payload: any) => void,
): void {
  useEffect(() => {
    if (!battleId) {
      return;
    }

    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${protocol}://${window.location.host}/ws/battle/${battleId}`);

    ws.onmessage = (event) => {
      try {
        onMessage(JSON.parse(event.data));
      } catch {
        onMessage({ type: "system", message: String(event.data) });
      }
    };

    return () => {
      ws.close();
    };
  }, [battleId, onMessage]);
}
