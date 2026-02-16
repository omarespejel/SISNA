const FELT_PRIME = (2n ** 251n) + (17n * (2n ** 192n)) + 1n;

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

  if (felt >= FELT_PRIME) {
    throw new Error(`invalid felt value: ${value}`);
  }

  return `0x${felt.toString(16)}`.toLowerCase();
}
