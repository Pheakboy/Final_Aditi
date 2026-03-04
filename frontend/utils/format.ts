/**
 * Formats a number (or numeric string) as USD currency.
 * Safely handles undefined/null/NaN — returns "$0.00" in those cases.
 * e.g. 1234.5 → "$1,234.50"
 */
export const formatCurrency = (amount: number | string | undefined | null): string => {
  const num = typeof amount === "string" ? parseFloat(amount) : (amount ?? 0);
  if (isNaN(num)) return "$0.00";
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
  }).format(num);
};

/**
 * Formats a date string, ISO timestamp, or date array from Java to a human-readable string.
 * Safely handles undefined/null — returns empty string in that case.
 * e.g. "2024-01-15T10:30:00" → "Jan 15, 2024"
 * e.g. "2024-01-15" → "Jan 15, 2024"
 */
export const formatDate = (dateStr: string | undefined | null): string => {
  if (!dateStr) return "";
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return String(dateStr);
  return d.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
};
