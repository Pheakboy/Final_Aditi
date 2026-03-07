interface LoanFiltersProps {
  filter: "" | "PENDING" | "APPROVED" | "REJECTED";
  riskFilter: "" | "LOW" | "MEDIUM" | "HIGH";
  dateFrom: string;
  dateTo: string;
  onFilterChange: (value: "" | "PENDING" | "APPROVED" | "REJECTED") => void;
  onRiskFilterChange: (value: "" | "LOW" | "MEDIUM" | "HIGH") => void;
  onDateFromChange: (value: string) => void;
  onDateToChange: (value: string) => void;
  onClearFilters: () => void;
}

export default function LoanFilters({
  filter,
  riskFilter,
  dateFrom,
  dateTo,
  onFilterChange,
  onRiskFilterChange,
  onDateFromChange,
  onDateToChange,
  onClearFilters,
}: LoanFiltersProps) {
  const hasActiveFilters = !!(filter || riskFilter || dateFrom || dateTo);

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-4 mb-6 space-y-3">
      <div className="flex flex-wrap gap-4 items-center">
        <div className="flex gap-2 items-center">
          <span className="text-sm text-gray-500 font-medium">Status:</span>
          {(["", "PENDING", "APPROVED", "REJECTED"] as const).map((f) => (
            <button
              key={f || "ALL"}
              onClick={() => onFilterChange(f)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                filter === f
                  ? "bg-blue-600 text-white"
                  : "bg-gray-100 text-gray-600 hover:bg-gray-200"
              }`}
            >
              {f || "ALL"}
            </button>
          ))}
        </div>
        <div className="flex gap-2 items-center">
          <span className="text-sm text-gray-500 font-medium">Risk:</span>
          {(["", "LOW", "MEDIUM", "HIGH"] as const).map((r) => (
            <button
              key={r || "ALL"}
              onClick={() => onRiskFilterChange(r)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                riskFilter === r
                  ? "bg-blue-600 text-white"
                  : "bg-gray-100 text-gray-600 hover:bg-gray-200"
              }`}
            >
              {r || "ALL"}
            </button>
          ))}
        </div>
      </div>
      <div className="flex flex-wrap gap-4 items-center">
        <span className="text-sm text-gray-500 font-medium">Date Range:</span>
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-500">From:</label>
          <input
            type="date"
            value={dateFrom}
            onChange={(e) => onDateFromChange(e.target.value)}
            className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-500">To:</label>
          <input
            type="date"
            value={dateTo}
            onChange={(e) => onDateToChange(e.target.value)}
            className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        {hasActiveFilters && (
          <button
            onClick={onClearFilters}
            className="px-3 py-1.5 text-xs font-medium text-red-600 bg-red-50 border border-red-200 rounded-lg hover:bg-red-100 transition-colors"
          >
            Clear Filters
          </button>
        )}
      </div>
    </div>
  );
}
