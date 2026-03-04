"use client";

import { Loan } from "../types";
import RiskBadge from "./RiskBadge";
import { formatCurrency, formatDate } from "../utils/format";

interface LoanCardProps {
  loan: Loan;
  showApplicant?: boolean;
  onApprove?: (loanId: string) => void;
  onReject?: (loanId: string) => void;
  isProcessing?: boolean;
}

export default function LoanCard({
  loan,
  showApplicant = false,
  onApprove,
  onReject,
  isProcessing,
}: LoanCardProps) {
  const statusConfig = {
    PENDING: {
      border: "border-l-amber-400",
      badge: "bg-amber-50 text-amber-700 border-amber-200",
      label: "Pending",
    },
    APPROVED: {
      border: "border-l-emerald-400",
      badge: "bg-emerald-50 text-emerald-700 border-emerald-200",
      label: "Approved",
    },
    REJECTED: {
      border: "border-l-red-400",
      badge: "bg-red-50 text-red-700 border-red-200",
      label: "Rejected",
    },
  };

  const status = statusConfig[loan.status];

  return (
    <div
      className={`bg-white rounded-xl border border-l-4 border-slate-200 ${status.border} card-shadow hover:card-shadow-hover transition-shadow p-5`}
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-0.5">
            <span className="text-xl font-bold text-slate-900">
              {formatCurrency(loan.loanAmount)}
            </span>
            <span
              className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${status.badge}`}
            >
              {status.label}
            </span>
          </div>
          {loan.purpose && (
            <p className="text-sm text-slate-500 truncate">{loan.purpose}</p>
          )}
          {showApplicant && loan.applicantUsername && (
            <p className="text-sm font-medium text-indigo-600 mt-0.5 truncate">
              {loan.applicantUsername}
              <span className="text-slate-400 font-normal ml-1">
                ({loan.applicantEmail})
              </span>
            </p>
          )}
        </div>
        <div className="ml-3 shrink-0">
          <RiskBadge level={loan.riskLevel} score={loan.riskScore} />
        </div>
      </div>

      {/* Financial stats */}
      <div className="grid grid-cols-2 gap-2 mb-4">
        <div className="bg-slate-50 rounded-lg p-3">
          <p className="text-xs text-slate-400 mb-0.5">Monthly Income</p>
          <p className="text-sm font-semibold text-emerald-600">
            {formatCurrency(loan.monthlyIncome)}
          </p>
        </div>
        <div className="bg-slate-50 rounded-lg p-3">
          <p className="text-xs text-slate-400 mb-0.5">Monthly Expense</p>
          <p className="text-sm font-semibold text-red-500">
            {formatCurrency(loan.monthlyExpense)}
          </p>
        </div>
      </div>

      {/* Admin note */}
      {loan.adminNote && (
        <div className="bg-indigo-50 border border-indigo-100 rounded-lg px-3 py-2 mb-4">
          <p className="text-xs font-medium text-indigo-500 mb-0.5">
            Admin Note
          </p>
          <p className="text-sm text-indigo-800">{loan.adminNote}</p>
        </div>
      )}

      {/* Footer */}
      <div className="flex items-center justify-between text-xs text-slate-400 border-t border-slate-100 pt-3">
        <span>Applied {formatDate(loan.createdAt)}</span>
        {loan.updatedAt !== loan.createdAt && (
          <span>Updated {formatDate(loan.updatedAt)}</span>
        )}
      </div>

      {/* Action buttons */}
      {loan.status === "PENDING" && (onApprove || onReject) && (
        <div className="flex gap-2 mt-4">
          {onApprove && (
            <button
              onClick={() => onApprove(loan.id)}
              disabled={isProcessing}
              className="flex-1 py-2 px-3 bg-emerald-600 text-white text-sm font-semibold rounded-lg hover:bg-emerald-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {isProcessing ? "..." : "Approve"}
            </button>
          )}
          {onReject && (
            <button
              onClick={() => onReject(loan.id)}
              disabled={isProcessing}
              className="flex-1 py-2 px-3 bg-red-500 text-white text-sm font-semibold rounded-lg hover:bg-red-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {isProcessing ? "..." : "Reject"}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
