export function normalizeFelt(value: string): string {
  return `0x${BigInt(value).toString(16)}`.toLowerCase();
}
