import { z } from "zod";

const HexFelt = z.string().regex(/^0x[0-9a-fA-F]{1,64}$/, "Must be a 0x-prefixed hex string (max 32 bytes)");
const DecimalOrHexFelt = HexFelt.or(z.string().regex(/^\d{1,78}$/, "Must be a decimal string (max 78 digits)"));

export const CallSchema = z.object({
  contractAddress: HexFelt,
  entrypoint: z.string().min(1).max(256),
  calldata: z.array(DecimalOrHexFelt).max(256),
});

export const SignSessionTransactionRequestSchema = z.object({
  accountAddress: HexFelt,
  keyId: z.string().min(1).max(64).optional(),
  chainId: DecimalOrHexFelt,
  nonce: DecimalOrHexFelt,
  validUntil: z.number().int().positive(),
  calls: z.array(CallSchema).min(1).max(64),
  context: z
    .object({
      requester: z.string().optional(),
      tool: z.string().optional(),
      reason: z.string().optional(),
    })
    .optional(),
});

export type SignSessionTransactionRequest = z.infer<typeof SignSessionTransactionRequestSchema>;
