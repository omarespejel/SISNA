import type { Request } from "express";

export type AuthContext = {
  nonce: string;
  timestamp: number;
};

export type RequestWithContext = Request & {
  rawBody?: string;
  requestId?: string;
  authContext?: AuthContext;
};
