import { Transaction } from "../../types";
import { formatCurrency, formatDate } from "../../utils/format";

interface TransactionListProps {
  transactions: Transaction[];
  isLoading: boolean;
}

export default function TransactionList({
  transactions,
  isLoading,
}: TransactionListProps) {
  return (
    <div className="bg-white rounded-2xl card-shadow overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-900">
          Transaction History
        </h2>
        <span className="text-xs text-slate-400">
          {transactions.length} records
        </span>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-2 border-teal-500 border-t-transparent" />
        </div>
      ) : transactions.length === 0 ? (
        <div className="p-12 text-center">
          <div className="w-12 h-12 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-3">
            <svg
              className="w-6 h-6 text-slate-400"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
              />
            </svg>
          </div>
          <p className="text-slate-500 text-sm mb-1">No transactions found</p>
          <p className="text-slate-400 text-xs">
            Try adjusting your filters or add a new transaction
          </p>
        </div>
      ) : (
        <div className="divide-y divide-slate-50">
          {transactions.map((tx) => (
            <div
              key={tx.id}
              className="flex items-center gap-4 px-6 py-3 hover:bg-slate-50 transition-colors group"
            >
              <div
                className={`w-9 h-9 rounded-full flex items-center justify-center shrink-0 ${
                  tx.type === "INCOME" ? "bg-emerald-50" : "bg-red-50"
                }`}
              >
                <svg
                  className={`w-4 h-4 ${tx.type === "INCOME" ? "text-emerald-500" : "text-red-400"}`}
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  {tx.type === "INCOME" ? (
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M7 11l5-5m0 0l5 5m-5-5v12"
                    />
                  ) : (
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M17 13l-5 5m0 0l-5-5m5 5V6"
                    />
                  )}
                </svg>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-slate-800 truncate">
                  {tx.description ||
                    (tx.type === "INCOME" ? "Income" : "Expense")}
                </p>
                <p className="text-xs text-slate-400">
                  {formatDate(tx.transactionDate)}
                </p>
              </div>
              <div className="text-right shrink-0">
                <p
                  className={`text-sm font-semibold ${
                    tx.type === "INCOME" ? "text-emerald-600" : "text-red-500"
                  }`}
                >
                  {tx.type === "INCOME" ? "+" : "-"}
                  {formatCurrency(tx.amount)}
                </p>
                <span
                  className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                    tx.type === "INCOME"
                      ? "bg-emerald-50 text-emerald-700"
                      : "bg-red-50 text-red-600"
                  }`}
                >
                  {tx.type}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
