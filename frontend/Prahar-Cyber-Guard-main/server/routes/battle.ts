import { Router } from "express";
import type { BattleMode } from "@shared/battle";
import { BattleEngine } from "../services/battleEngine";
import { broadcastBattleUpdate } from "../websocket/battleStream";

export const battleEngine = new BattleEngine((battleId, payload) => {
  broadcastBattleUpdate(battleId, payload);
});

const battleRouter = Router();

battleRouter.post("/start", (req, res) => {
  const mode = (req.body?.mode as BattleMode) || "demo";
  const state = battleEngine.start(mode === "production" ? "production" : "demo");

  return res.json({
    battle_id: state.battleId,
    state,
  });
});

battleRouter.get("/status/:battleId", (req, res) => {
  const state = battleEngine.getStatus(req.params.battleId);
  if (!state) {
    return res.status(404).json({ message: "Battle not found" });
  }

  return res.json(state);
});

battleRouter.post("/:battleId/pause", (req, res) => {
  const state = battleEngine.pause(req.params.battleId);
  if (!state) {
    return res.status(404).json({ message: "Battle not found" });
  }

  return res.json(state);
});

battleRouter.post("/:battleId/resume", (req, res) => {
  const state = battleEngine.resume(req.params.battleId);
  if (!state) {
    return res.status(404).json({ message: "Battle not found" });
  }

  return res.json(state);
});

battleRouter.post("/:battleId/speed", (req, res) => {
  const speed = Number(req.body?.speed);
  if (![1, 2, 5].includes(speed)) {
    return res.status(400).json({ message: "Speed must be one of 1, 2, 5" });
  }

  const state = battleEngine.setSpeed(req.params.battleId, speed as 1 | 2 | 5);
  if (!state) {
    return res.status(404).json({ message: "Battle not found" });
  }

  return res.json(state);
});

battleRouter.post("/:battleId/reset", (req, res) => {
  const state = battleEngine.getStatus(req.params.battleId);
  if (!state) {
    return res.status(404).json({ message: "Battle not found" });
  }

  battleEngine.reset(req.params.battleId);
  return res.json({ message: "Battle reset" });
});

battleRouter.get("/report/:battleId", (req, res) => {
  const state = battleEngine.getStatus(req.params.battleId);
  if (!state) {
    return res.status(404).json({ message: "Battle not found" });
  }

  return res.json({
    generatedAt: new Date().toISOString(),
    branding: "PRAHAAR - AUTONOMOUS CYBERWAR SYSTEM",
    battleId: state.battleId,
    mode: state.mode,
    score: state.score,
    winner: state.winner || "in-progress",
    durationMs: state.elapsedMs,
    events: state.events,
  });
});

export default battleRouter;
