interface TransactionFiltersProps {
  typeFilter: "ALL" | "INCOME" | "EXPENSE";
  dateFrom: string;
  dateTo: string;
  onTypeFilterChange: (value: "ALL" | "INCOME" | "EXPENSE") => void;
  onDateFromChange: (value: string) => void;
  onDateToChange: (value: string) => void;
}

export default function TransactionFilters({
  typeFilter,
  dateFrom,
  dateTo,
  onTypeFilterChange,
  onDateFromChange,
  onDateToChange,
}: TransactionFiltersProps) {
  return (
    <div className="bg-white rounded-2xl card-shadow p-4 mb-6">
      <div className="flex flex-wrap gap-4 items-center">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide">
            Type:
          </span>
          {(["ALL", "INCOME", "EXPENSE"] as const).map((f) => (
            <button
              key={f}
              onClick={() => onTypeFilterChange(f)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                typeFilter === f
                  ? "gradient-teal text-white"
                  : "bg-slate-100 text-slate-600 hover:bg-slate-200"
              }`}
            >
              {f}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide">
            Date:
          </span>
          <input
            type="date"
            value={dateFrom}
            onChange={(e) => onDateFromChange(e.target.value)}
            className="px-3 py-1.5 text-sm border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-500"
          />
          <span className="text-slate-400 text-sm">→</span>
          <input
            type="date"
            value={dateTo}
            onChange={(e) => onDateToChange(e.target.value)}
            className="px-3 py-1.5 text-sm border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-500"
          />
          {(dateFrom || dateTo) && (
            <button
              onClick={() => {
                onDateFromChange("");
                onDateToChange("");
              }}
              className="px-3 py-1.5 text-xs font-medium text-red-600 bg-red-50 border border-red-200 rounded-lg hover:bg-red-100 transition-colors"
            >
              Clear
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
