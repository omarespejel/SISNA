import type { Request } from "express";

export type AuthContext = {
  nonce: string;
  timestamp: number;
  clientId: string;
};

export type RequestWithContext = Request & {
  rawBody?: string;
  requestId?: string;
  authContext?: AuthContext;
};
