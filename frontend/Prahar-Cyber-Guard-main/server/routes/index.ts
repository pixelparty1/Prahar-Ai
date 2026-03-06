import type { Express, Request, Response } from "express";
import battleRouter from "./battle";
import malwareRouter from "./malware";
import threatsRouter from "./threats";
import authRouter from "./auth";
import scanRouter from "./scan";

function isPrivateOrLocalHost(hostname: string): boolean {
  const host = hostname.toLowerCase();

  if (host === "localhost" || host === "127.0.0.1" || host === "::1") {
    return true;
  }

  if (/^10\./.test(host)) return true;
  if (/^192\.168\./.test(host)) return true;
  if (/^127\./.test(host)) return true;

  const match172 = host.match(/^172\.(\d+)\./);
  if (match172) {
    const secondOctet = Number(match172[1]);
    if (secondOctet >= 16 && secondOctet <= 31) {
      return true;
    }
  }

  return false;
}

export function registerApiRoutes(app: Express): void {
  app.use("/api/auth", authRouter);
  app.use("/api/battle", battleRouter);
  app.use("/api/malware", malwareRouter);
  app.use("/api/threats", threatsRouter);
  app.use("/api/scan", scanRouter);

  app.post("/api/simulation/start", (req: Request, res: Response) => {
    const { targetUrl, selectedBotId } = req.body as {
      targetUrl?: string;
      selectedBotId?: string;
    };

    const timestamp = new Date().toISOString();
    console.log(`[simulation][${timestamp}] start attempt target=${targetUrl ?? ""} bot=${selectedBotId ?? ""}`);

    if (!targetUrl || typeof targetUrl !== "string") {
      return res.status(400).json({ message: "targetUrl is required" });
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(targetUrl);
    } catch {
      return res.status(400).json({ message: "URL must be valid and use http/https" });
    }

    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
      return res.status(400).json({ message: "URL must be valid and use http/https" });
    }

    if (isPrivateOrLocalHost(parsedUrl.hostname)) {
      return res.status(400).json({ message: "Localhost and internal targets are not allowed" });
    }

    const simulationId = `sim_${Date.now()}`;

    return res.json({
      success: true,
      simulationId,
      message: `Simulation started on ${targetUrl}`,
    });
  });

  app.post("/api/simulation/stop", (req: Request, res: Response) => {
    const { simulationId } = req.body as { simulationId?: string };
    const timestamp = new Date().toISOString();
    console.log(`[simulation][${timestamp}] stop attempt simulationId=${simulationId ?? ""}`);

    return res.json({
      success: true,
      message: "Simulation stopped",
    });
  });
}
