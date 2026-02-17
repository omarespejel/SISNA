import { ec, num } from "starknet";
import type { AppConfig, SigningKeyConfig } from "../config.js";
import type { SignSessionTransactionRequest } from "../types/api.js";
import type { AuditLogger } from "../audit/logger.js";
import {
  SessionTransactionSigner,
  type SignatureResult,
} from "./sessionSigner.js";
import type { SigningPolicyConfig } from "./policy.js";
import { PolicyError } from "./policy.js";

type SignerProviderName = "local" | "dfns";

export type SessionSigner = {
  readonly defaultKeyId: string;
  readonly provider: SignerProviderName;
  sign(req: SignSessionTransactionRequest, clientId: string): Promise<SignatureResult>;
};

type SignerFactoryArgs = {
  config: AppConfig;
  logger: AuditLogger;
  signingKeys: SigningKeyConfig[];
  defaultKeyId: string;
  allowedKeyIdsByClient: Map<string, Set<string> | undefined>;
  allowedAccountsByClient: Map<string, Set<string> | undefined>;
  signingPolicy: SigningPolicyConfig;
};

type DfnsSignerProviderConfig = {
  endpointUrl: string;
  timeoutMs: number;
  authToken: string;
  userActionSignature: string;
  defaultKeyId: string;
};

type DfnsSignResponse = {
  signatureMode: "v2_snip12";
  signatureKind: "Snip12";
  domainHash: string;
  messageHash: string;
  sessionPublicKey: string;
  signature: [string, string, string, string];
};

export class SignerUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignerUnavailableError";
  }
}

class LocalSessionSignerProvider implements SessionSigner {
  readonly provider = "local" as const;
  readonly defaultKeyId: string;

  constructor(private readonly inner: SessionTransactionSigner) {
    this.defaultKeyId = inner.defaultKeyId;
  }

  async sign(req: SignSessionTransactionRequest, clientId: string): Promise<SignatureResult> {
    return this.inner.sign(req, clientId);
  }
}

class DfnsSessionSignerProvider implements SessionSigner {
  readonly provider = "dfns" as const;
  readonly defaultKeyId: string;

  constructor(private readonly config: DfnsSignerProviderConfig) {
    this.defaultKeyId = config.defaultKeyId;
  }

  async sign(req: SignSessionTransactionRequest, clientId: string): Promise<SignatureResult> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      const response = await fetch(this.config.endpointUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.config.authToken}`,
          "x-dfns-useraction": this.config.userActionSignature,
        },
        body: JSON.stringify({
          clientId,
          request: req,
          kind: "Snip12",
          signatureMode: "v2_snip12",
        }),
        signal: controller.signal,
      });

      let payload: unknown = null;
      try {
        payload = await response.json();
      } catch {
        if (!response.ok) {
          throw new SignerUnavailableError(`DFNS signer returned HTTP ${response.status}`);
        }
        throw new SignerUnavailableError("DFNS signer returned non-JSON response");
      }

      if (!response.ok) {
        const message = typeof payload === "object" && payload && "error" in payload
          ? String((payload as { error: unknown }).error)
          : `DFNS signer returned HTTP ${response.status}`;
        if (response.status === 400 || response.status === 422) {
          throw new PolicyError(message);
        }
        throw new SignerUnavailableError(message);
      }

      return validateDfnsSignResponse(payload, req.validUntil);
    } catch (err) {
      if (err instanceof PolicyError || err instanceof SignerUnavailableError) {
        throw err;
      }
      if (err instanceof Error && err.name === "AbortError") {
        throw new SignerUnavailableError("DFNS signer request timed out");
      }
      throw new SignerUnavailableError(
        err instanceof Error ? err.message : "DFNS signer request failed",
      );
    } finally {
      clearTimeout(timeout);
    }
  }
}

class FallbackSessionSignerProvider implements SessionSigner {
  readonly defaultKeyId: string;
  private lastSignerProvider?: SignerProviderName;

  constructor(
    private readonly primary: SessionSigner,
    private readonly fallback: SessionSigner,
    private readonly logger: AuditLogger,
  ) {
    this.defaultKeyId = primary.defaultKeyId;
  }

  get provider(): SignerProviderName {
    return this.lastSignerProvider ?? this.primary.provider;
  }

  async sign(req: SignSessionTransactionRequest, clientId: string): Promise<SignatureResult> {
    try {
      const primaryResult = await this.primary.sign(req, clientId);
      this.lastSignerProvider = primaryResult.signerProvider;
      return primaryResult;
    } catch (err) {
      if (err instanceof PolicyError) {
        throw err;
      }
      this.logger.log({
        level: "warn",
        event: "signer.primary_unavailable_fallback",
        details: {
          primaryProvider: this.primary.provider,
          fallbackProvider: this.fallback.provider,
          error: err instanceof Error ? err.message : String(err),
        },
      });
      const fallbackResult = await this.fallback.sign(req, clientId);
      this.lastSignerProvider = fallbackResult.signerProvider;
      return fallbackResult;
    }
  }
}

function isHexFelt(value: unknown): value is string {
  return typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value);
}

function validateDfnsSignResponse(payload: unknown, validUntil: number): SignatureResult {
  if (!payload || typeof payload !== "object") {
    throw new SignerUnavailableError("DFNS signer response payload is invalid");
  }
  const parsed = payload as Partial<DfnsSignResponse>;
  if (parsed.signatureMode !== "v2_snip12" || parsed.signatureKind !== "Snip12") {
    throw new SignerUnavailableError("DFNS signer returned unsupported signature mode");
  }
  if (!isHexFelt(parsed.domainHash) || !isHexFelt(parsed.messageHash)) {
    throw new SignerUnavailableError("DFNS signer response hashes are invalid");
  }
  if (!isHexFelt(parsed.sessionPublicKey)) {
    throw new SignerUnavailableError("DFNS signer returned invalid sessionPublicKey");
  }
  if (!Array.isArray(parsed.signature) || parsed.signature.length !== 4 || !parsed.signature.every(isHexFelt)) {
    throw new SignerUnavailableError("DFNS signer returned invalid signature shape");
  }

  const normalizedSignature = parsed.signature.map((felt) => num.toHex(BigInt(felt))) as [
    string,
    string,
    string,
    string,
  ];
  const normalizedPubkey = num.toHex(BigInt(parsed.sessionPublicKey));
  const normalizedValidUntil = num.toHex(validUntil);
  if (normalizedSignature[0] !== normalizedPubkey) {
    throw new SignerUnavailableError("DFNS signer returned mismatched session pubkey");
  }
  if (normalizedSignature[3] !== normalizedValidUntil) {
    throw new SignerUnavailableError("DFNS signer returned mismatched valid_until");
  }

  const verified = ec.starkCurve.verify(
    new ec.starkCurve.Signature(BigInt(normalizedSignature[1]), BigInt(normalizedSignature[2])),
    parsed.messageHash,
    normalizedPubkey,
  );
  if (!verified) {
    throw new SignerUnavailableError("DFNS signer returned unverifiable signature");
  }

  return {
    signerProvider: "dfns",
    sessionPublicKey: normalizedPubkey,
    signatureMode: "v2_snip12",
    signatureKind: "Snip12",
    domainHash: num.toHex(BigInt(parsed.domainHash)),
    messageHash: num.toHex(BigInt(parsed.messageHash)),
    signature: normalizedSignature,
  };
}

export function createSessionSignerProvider(args: SignerFactoryArgs): SessionSigner {
  const buildLocalProvider = () => new LocalSessionSignerProvider(
    new SessionTransactionSigner(
      args.signingKeys,
      args.defaultKeyId,
      args.allowedKeyIdsByClient,
      args.allowedAccountsByClient,
      args.signingPolicy,
    ),
  );

  if (args.config.KEYRING_SIGNER_PROVIDER === "local") {
    return buildLocalProvider();
  }

  const dfnsProvider = new DfnsSessionSignerProvider({
    endpointUrl: args.config.KEYRING_DFNS_SIGNER_URL!,
    timeoutMs: args.config.KEYRING_DFNS_TIMEOUT_MS,
    authToken: args.config.KEYRING_DFNS_AUTH_TOKEN!,
    userActionSignature: args.config.KEYRING_DFNS_USER_ACTION_SIGNATURE!,
    defaultKeyId: args.defaultKeyId,
  });

  if (args.config.KEYRING_SIGNER_FALLBACK_PROVIDER === "local") {
    return new FallbackSessionSignerProvider(dfnsProvider, buildLocalProvider(), args.logger);
  }

  return dfnsProvider;
}
