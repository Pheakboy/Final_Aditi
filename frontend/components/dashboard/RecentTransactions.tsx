import Link from "next/link";
import { Transaction } from "../../types";
import { formatCurrency, formatDate } from "../../utils/format";

interface RecentTransactionsProps {
  transactions: Transaction[];
  isLoading?: boolean;
}

export default function RecentTransactions({
  transactions,
  isLoading = false,
}: RecentTransactionsProps) {
  return (
    <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-6 transition-all hover:shadow-md">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-base font-semibold text-slate-900 tracking-tight">
          Recent Transactions
        </h2>
        <Link
          href="/transactions"
          className="text-sm font-bold text-teal-600 hover:text-teal-700 bg-teal-50 px-3 py-1.5 rounded-lg transition-colors"
        >
          View all →
        </Link>
      </div>

      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3 py-1 animate-pulse">
              <div className="w-8 h-8 bg-slate-200 rounded-full shrink-0"></div>
              <div className="flex-1 space-y-1.5">
                <div className="h-3 bg-slate-200 rounded w-40"></div>
                <div className="h-2.5 bg-slate-200 rounded w-24"></div>
              </div>
              <div className="h-3 bg-slate-200 rounded w-16 shrink-0"></div>
            </div>
          ))}
        </div>
      ) : transactions.length === 0 ? (
        <div className="text-center py-8">
          <div className="w-10 h-10 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-3">
            <svg
              className="w-5 h-5 text-slate-400"
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
          <p className="text-sm text-slate-400">No transactions yet</p>
        </div>
      ) : (
        <div className="space-y-1">
          {transactions.slice(0, 5).map((tx) => (
            <div key={tx.id} className="flex items-center gap-3 py-2">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${
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
                  {tx.description || tx.type}
                </p>
                <p className="text-xs text-slate-400">
                  {formatDate(tx.transactionDate)}
                </p>
              </div>
              <span
                className={`text-sm font-semibold shrink-0 ${
                  tx.type === "INCOME" ? "text-emerald-600" : "text-red-500"
                }`}
              >
                {tx.type === "INCOME" ? "+" : "-"}
                {formatCurrency(tx.amount)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
