import { hash } from "starknet";
import type { SignSessionTransactionRequest } from "../types/api.js";

const DENIED_ENTRYPOINTS = [
  "upgrade",
  "add_or_update_session_key",
  "revoke_session_key",
  "__execute__",
  "set_public_key",
  "setPublicKey",
  "execute_from_outside_v2",
  "set_spending_policy",
  "remove_spending_policy",
  "set_agent_id",
  "register_interfaces",
  "compute_session_message_hash",
  "__validate__",
  "__validate_declare__",
  "__validate_deploy__",
] as const;

const DENIED_SELECTOR_SET = new Set(
  DENIED_ENTRYPOINTS.map((name) => hash.getSelectorFromName(name).toLowerCase()),
);

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

export type SigningPolicyConfig = {
  maxValidityWindowSec: number;
  allowedChainIds: Set<string>;
};

function normalizeFelt(value: string): string {
  return `0x${BigInt(value).toString(16)}`.toLowerCase();
}

export function assertSigningPolicy(
  req: SignSessionTransactionRequest,
  policy: SigningPolicyConfig,
): void {
  const nowSec = Math.floor(Date.now() / 1000);
  if (req.validUntil <= nowSec) {
    throw new PolicyError("validUntil is already expired");
  }
  if (req.validUntil > nowSec + policy.maxValidityWindowSec) {
    throw new PolicyError("validUntil exceeds maximum allowed future window");
  }

  if (policy.allowedChainIds.size > 0) {
    const chainId = normalizeFelt(req.chainId);
    if (!policy.allowedChainIds.has(chainId)) {
      throw new PolicyError(`chainId ${req.chainId} is not allowed`);
    }
  }

  for (const call of req.calls) {
    if (call.contractAddress.toLowerCase() === req.accountAddress.toLowerCase()) {
      throw new PolicyError("self-call is denied for session signing");
    }

    const selector = call.entrypoint.startsWith("0x")
      ? call.entrypoint.toLowerCase()
      : hash.getSelectorFromName(call.entrypoint).toLowerCase();

    if (DENIED_SELECTOR_SET.has(selector)) {
      throw new PolicyError(`denied selector: ${call.entrypoint}`);
    }
  }
}
