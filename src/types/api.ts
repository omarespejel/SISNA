import { z } from "zod";

const HexFelt = z.string().regex(/^0x[0-9a-fA-F]{1,64}$/, "Must be a 0x-prefixed hex string (max 32 bytes)");
const DecimalOrHexFelt = HexFelt.or(z.string().regex(/^\d{1,78}$/, "Must be a decimal string (max 78 digits)"));
const MAX_TOTAL_CALLDATA_ELEMENTS = 2048;

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
  caller: DecimalOrHexFelt.optional(),
  executeAfter: DecimalOrHexFelt.optional(),
  validUntil: z.number().int().positive(),
  calls: z.array(CallSchema).min(1).max(64),
  context: z
    .object({
      requester: z.string().max(128).optional(),
      tool: z.string().max(64).optional(),
      reason: z.string().max(512).optional(),
    })
    .optional(),
}).superRefine((value, ctx) => {
  if (value.executeAfter !== undefined) {
    try {
      const executeAfter = BigInt(value.executeAfter);
      const validUntil = BigInt(value.validUntil);
      if (executeAfter > validUntil) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "executeAfter must be <= validUntil",
          path: ["executeAfter"],
        });
      }
    } catch {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Invalid executeAfter value",
        path: ["executeAfter"],
      });
    }
  }
  const totalCalldata = value.calls.reduce((sum, call) => sum + call.calldata.length, 0);
  if (totalCalldata > MAX_TOTAL_CALLDATA_ELEMENTS) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: `Total calldata elements exceed ${MAX_TOTAL_CALLDATA_ELEMENTS}`,
      path: ["calls"],
    });
  }
});

export type SignSessionTransactionRequest = z.infer<typeof SignSessionTransactionRequestSchema>;
