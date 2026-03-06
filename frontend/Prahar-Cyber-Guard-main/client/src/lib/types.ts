export interface CommandRunPayload {
  targetUrl: string;
  selectedBotId?: string;
}

export interface CommandRunResponse {
  success?: boolean;
  simulationId?: string;
  message?: string;
  [key: string]: unknown;
}

export interface CommandStopPayload {
  simulationId?: string;
}

export interface CommandStopResponse {
  success?: boolean;
  message?: string;
  [key: string]: unknown;
}

export interface CommandStatusResponse {
  success?: boolean;
  simulationId?: string;
  active?: boolean;
  message?: string;
  [key: string]: unknown;
}

export interface CommandApiError {
  error?: string;
  message?: string;
}
