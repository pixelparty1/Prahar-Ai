import type { Express, Request, Response } from "express";
import type { Server } from "http";
import { registerApiRoutes } from "./routes/index";
import { initBattleWebSocket } from "./websocket/battleStream";

const DEFAULT_PYTHON_BACKEND_URL = "http://localhost:8000";

type ProxyMethod = "GET" | "POST";

function getPythonBackendBaseUrl(): string {
  return (process.env.PYTHON_BACKEND_URL || DEFAULT_PYTHON_BACKEND_URL).replace(/\/$/, "");
}

function buildBackendUrl(path: string, req: Request): string {
  const base = getPythonBackendBaseUrl();
  const query = req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
  return `${base}${path}${query}`;
}

async function proxyJsonRequest(
  req: Request,
  res: Response,
  method: ProxyMethod,
  backendPath: string,
): Promise<void> {
  try {
    const response = await fetch(buildBackendUrl(backendPath, req), {
      method,
      headers: {
        "Content-Type": "application/json",
      },
      body: method === "POST" ? JSON.stringify(req.body ?? {}) : undefined,
    });

    const contentType = response.headers.get("content-type") || "";
    const raw = await response.text();
    const data = contentType.includes("application/json")
      ? JSON.parse(raw || "{}")
      : { raw };

    res.status(response.status).json(data);
  } catch {
    res.status(502).json({ error: "AI backend unavailable" });
  }
}

async function proxySseRequest(req: Request, res: Response, backendPath: string): Promise<void> {
  try {
    const backendResponse = await fetch(buildBackendUrl(backendPath, req), {
      method: "GET",
      headers: {
        Accept: "text/event-stream",
      },
    });

    if (!backendResponse.ok || !backendResponse.body) {
      res.status(backendResponse.status || 502).json({ error: "AI backend unavailable" });
      return;
    }

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    const reader = backendResponse.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        res.write(Buffer.from(value));
      }
    }

    res.end();
  } catch {
    if (!res.headersSent) {
      res.status(502).json({ error: "AI backend unavailable" });
      return;
    }
    res.write("event: error\ndata: AI backend unavailable\n\n");
    res.end();
  }
}

function registerCommandProxyRoutes(app: Express): void {
  // Core Command Center endpoint mappings.
  app.post("/api/command/run", async (req: Request, res: Response) => {
    await proxyJsonRequest(req, res, "POST", "/run");
  });

  app.post("/api/command/stop", async (req: Request, res: Response) => {
    await proxyJsonRequest(req, res, "POST", "/stop");
  });

  app.get("/api/command/status", async (req: Request, res: Response) => {
    await proxyJsonRequest(req, res, "GET", "/status");
  });

  app.get("/api/command/health", async (req: Request, res: Response) => {
    await proxyJsonRequest(req, res, "GET", "/health");
  });

  app.get("/api/command/reports", async (req: Request, res: Response) => {
    await proxyJsonRequest(req, res, "GET", "/reports");
  });

  // Optional streaming endpoint passthrough if Python backend emits SSE tokens/events.
  app.get("/api/command/stream", async (req: Request, res: Response) => {
    await proxySseRequest(req, res, "/stream");
  });

  // Generic passthrough for additional Python endpoints under /api/command/*.
  app.get("/api/command/:path", async (req: Request, res: Response) => {
    await proxyJsonRequest(req, res, "GET", `/${req.params.path}`);
  });

  app.post("/api/command/:path", async (req: Request, res: Response) => {
    await proxyJsonRequest(req, res, "POST", `/${req.params.path}`);
  });
}

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  registerApiRoutes(app);
  registerCommandProxyRoutes(app);
  initBattleWebSocket(httpServer);

  return httpServer;
}
