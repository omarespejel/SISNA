export type AuditLevel = "debug" | "info" | "warn" | "error";

export type AuditEvent = {
  level: AuditLevel;
  event: string;
  requestId?: string;
  details?: Record<string, unknown>;
};

export class AuditLogger {
  constructor(private readonly minLevel: AuditLevel = "info") {}

  log(payload: AuditEvent): void {
    if (!shouldLog(this.minLevel, payload.level)) {
      return;
    }

    const line = {
      ts: new Date().toISOString(),
      level: payload.level,
      event: payload.event,
      request_id: payload.requestId,
      details: payload.details ?? {},
    };

    process.stdout.write(`${JSON.stringify(line)}\n`);
  }
}

function shouldLog(min: AuditLevel, target: AuditLevel): boolean {
  const rank: Record<AuditLevel, number> = {
    debug: 10,
    info: 20,
    warn: 30,
    error: 40,
  };

  return rank[target] >= rank[min];
}
