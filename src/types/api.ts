import { z } from "zod";

export const CallSchema = z.object({
  contractAddress: z.string().startsWith("0x"),
  entrypoint: z.string().min(1),
  calldata: z.array(z.string().startsWith("0x").or(z.string().regex(/^\d+$/))),
});

export const SignSessionTransactionRequestSchema = z.object({
  accountAddress: z.string().startsWith("0x"),
  keyId: z.string().min(1).optional(),
  chainId: z.string().startsWith("0x").or(z.string().regex(/^\d+$/)),
  nonce: z.string().startsWith("0x").or(z.string().regex(/^\d+$/)),
  validUntil: z.number().int().positive(),
  calls: z.array(CallSchema).min(1),
  context: z
    .object({
      requester: z.string().optional(),
      tool: z.string().optional(),
      reason: z.string().optional(),
    })
    .optional(),
});

export type SignSessionTransactionRequest = z.infer<typeof SignSessionTransactionRequestSchema>;
