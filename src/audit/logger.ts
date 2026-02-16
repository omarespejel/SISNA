import pino from "pino";

export type AuditLevel = "debug" | "info" | "warn" | "error";

export type AuditEvent = {
  level: AuditLevel;
  event: string;
  requestId?: string;
  details?: Record<string, unknown>;
};

export class AuditLogger {
  private readonly logger;

  constructor(minLevel: AuditLevel = "info") {
    this.logger = pino(
      {
        level: minLevel,
        base: undefined,
        timestamp: () => `,"ts":"${new Date().toISOString()}"`,
        formatters: {
          level: (label) => ({ level: label }),
        },
      },
      pino.destination({ sync: false }),
    );
  }

  log(payload: AuditEvent): void {
    this.logger[payload.level]({
      event: payload.event,
      request_id: payload.requestId,
      details: payload.details ?? {},
    });
  }
}
