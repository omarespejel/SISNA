export function normalizeFelt(value: string): string {
  const candidate = value.trim();
  if (candidate.length === 0) {
    throw new Error(`invalid felt value: ${value}`);
  }

  let felt: bigint;
  try {
    felt = BigInt(candidate);
  } catch {
    throw new Error(`invalid felt value: ${value}`);
  }

  if (felt < 0n) {
    throw new Error(`invalid felt value: ${value}`);
  }

  return `0x${felt.toString(16)}`.toLowerCase();
}
