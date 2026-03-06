import { parse } from "url";
import type { Server } from "http";
import { WebSocketServer, type WebSocket } from "ws";

const battleClients = new Map<string, Set<WebSocket>>();
let initialized = false;

export function initBattleWebSocket(httpServer: Server): void {
  if (initialized) {
    return;
  }

  const wss = new WebSocketServer({ noServer: true });

  httpServer.on("upgrade", (request, socket, head) => {
    const { pathname } = parse(request.url || "", true);
    const match = pathname?.match(/^\/ws\/battle\/([a-zA-Z0-9-]+)$/);

    if (!match) {
      socket.destroy();
      return;
    }

    const battleId = match[1];

    wss.handleUpgrade(request, socket, head, (ws) => {
      let clients = battleClients.get(battleId);
      if (!clients) {
        clients = new Set<WebSocket>();
        battleClients.set(battleId, clients);
      }

      clients.add(ws);

      ws.on("close", () => {
        const set = battleClients.get(battleId);
        if (!set) {
          return;
        }

        set.delete(ws);
        if (set.size === 0) {
          battleClients.delete(battleId);
        }
      });

      ws.send(
        JSON.stringify({
          type: "system",
          message: "Battle stream connected",
          battleId,
        }),
      );
    });
  });

  initialized = true;
}

export function broadcastBattleUpdate(battleId: string, payload: unknown): void {
  const clients = battleClients.get(battleId);
  if (!clients) {
    return;
  }

  const serialized = JSON.stringify(payload);
  clients.forEach((client) => {
    if (client.readyState === client.OPEN) {
      client.send(serialized);
    }
  });
}
