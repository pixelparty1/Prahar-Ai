import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type {
  CommandApiError,
  CommandRunPayload,
  CommandRunResponse,
  CommandStatusResponse,
  CommandStopPayload,
  CommandStopResponse,
} from "@/lib/types";

async function parseJsonOrThrow<T>(response: Response): Promise<T> {
  const payload = (await response.json().catch(() => ({}))) as T & CommandApiError;

  if (!response.ok) {
    throw new Error(payload.message || payload.error || "Request failed");
  }

  return payload;
}

export function useCommandCenter() {
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<unknown>(null);

  const statusQuery = useQuery({
    queryKey: ["command-center", "status"],
    queryFn: async () => {
      const response = await fetch("/api/command/status");
      return parseJsonOrThrow<CommandStatusResponse>(response);
    },
    refetchInterval: 3000,
  });

  const runMutation = useMutation({
    mutationFn: async (payload: CommandRunPayload) => {
      const response = await fetch("/api/command/run", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      return parseJsonOrThrow<CommandRunResponse>(response);
    },
    onSuccess: (data) => {
      setError(null);
      setResult(data);
      void queryClient.invalidateQueries({ queryKey: ["command-center", "status"] });
    },
    onError: (mutationError) => {
      setError(mutationError instanceof Error ? mutationError.message : "Run request failed");
    },
  });

  const stopMutation = useMutation({
    mutationFn: async (payload?: CommandStopPayload) => {
      const response = await fetch("/api/command/stop", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload ?? {}),
      });

      return parseJsonOrThrow<CommandStopResponse>(response);
    },
    onSuccess: (data) => {
      setError(null);
      setResult(data);
      void queryClient.invalidateQueries({ queryKey: ["command-center", "status"] });
    },
    onError: (mutationError) => {
      setError(mutationError instanceof Error ? mutationError.message : "Stop request failed");
    },
  });

  useEffect(() => {
    if (statusQuery.data) {
      setResult(statusQuery.data);
    }

    if (statusQuery.error) {
      setError(statusQuery.error instanceof Error ? statusQuery.error.message : "Status request failed");
    }
  }, [statusQuery.data, statusQuery.error]);

  const runSimulation = async (payload: CommandRunPayload) => {
    const data = await runMutation.mutateAsync(payload);
    return data;
  };

  const stopSimulation = async (payload?: CommandStopPayload) => {
    const data = await stopMutation.mutateAsync(payload);
    return data;
  };

  const getStatus = async () => {
    const response = await statusQuery.refetch();
    return response.data ?? null;
  };

  const getHealth = async () => {
    const response = await fetch("/api/command/health");
    const data = await parseJsonOrThrow<Record<string, unknown>>(response);
    setResult(data);
    return data;
  };

  const getReports = async () => {
    const response = await fetch("/api/command/reports");
    const data = await parseJsonOrThrow<Record<string, unknown>>(response);
    setResult(data);
    return data;
  };

  return {
    runSimulation,
    stopSimulation,
    getStatus,
    getHealth,
    getReports,
    isLoading: runMutation.isPending || stopMutation.isPending || statusQuery.isFetching,
    error,
    result,
    status: statusQuery.data ?? null,
  };
}
