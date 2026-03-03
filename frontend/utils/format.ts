/**
 * Formats a number as USD currency.
 * e.g. 1234.5 → "$1,234.50"
 */
export const formatCurrency = (amount: number): string =>
  new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
  }).format(amount);

/**
 * Formats a date string to a human-readable locale string.
 * e.g. "2024-01-15T10:30:00" → "Jan 15, 2024"
 */
export const formatDate = (dateStr: string): string =>
  new Date(dateStr).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
