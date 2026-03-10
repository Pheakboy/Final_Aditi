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
      className={`bg-white border border-slate-200 rounded-xl shadow-sm hover:shadow-md transition-all duration-200 p-5 ${status.border}`}
      style={{ borderLeftWidth: "4px" }}
    >
      <div className="relative z-10">
        {/* Header */}
        <div className="flex items-start justify-between mb-5">
          <div className="flex-1 min-w-0 pr-4">
            <div className="flex items-center gap-3 flex-wrap mb-1">
              <span className="text-2xl font-extrabold text-slate-900 tracking-tight">
                {formatCurrency(loan.loanAmount)}
              </span>
              <span
                className={`px-3 py-1 rounded-lg text-xs font-bold border ${status.badge} shadow-sm`}
              >
                {status.label}
              </span>
            </div>
            {loan.purpose && (
              <p className="text-sm font-medium text-slate-500 truncate mb-1">{loan.purpose}</p>
            )}
            {showApplicant && (
              <div className="flex items-center gap-2 mt-2">
                <div className="w-5 h-5 rounded-md bg-slate-100 flex items-center justify-center shrink-0 border border-slate-200">
                  <span className="text-slate-600 text-xs font-bold">
                    {loan.applicantUsername ? loan.applicantUsername.charAt(0).toUpperCase() : "?"}
                  </span>
                </div>
                <p className="text-sm font-semibold text-slate-700 truncate">
                  {loan.applicantUsername || 'Unknown'}
                  {loan.applicantEmail && (
                    <span className="text-slate-400 font-medium ml-1.5 text-xs">
                      {loan.applicantEmail}
                    </span>
                  )}
                </p>
              </div>
            )}
          </div>
          <div className="shrink-0 mt-1">
            <RiskBadge level={loan.riskLevel} score={loan.riskScore} />
          </div>
        </div>

        {/* Financial stats */}
        <div className="grid grid-cols-2 gap-3 mb-5">
          <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
            <p className="text-[10px] font-bold text-slate-400 mb-1 uppercase tracking-widest">Income</p>
            <p className="text-sm font-bold text-emerald-600">
              {formatCurrency(loan.monthlyIncome)}
            </p>
          </div>
          <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
            <p className="text-[10px] font-bold text-slate-400 mb-1 uppercase tracking-widest">Expense</p>
            <p className="text-sm font-bold text-rose-500">
              {formatCurrency(loan.monthlyExpense)}
            </p>
          </div>
        </div>

        {/* Admin note */}
        {loan.adminNote && (
          <div className="bg-amber-50 border border-amber-200/60 rounded-lg p-3 mb-5">
            <div className="flex items-center gap-1.5 mb-1">
              <svg className="w-3.5 h-3.5 text-amber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <p className="text-[10px] font-bold text-amber-700 uppercase tracking-widest">
                Admin Note
              </p>
            </div>
            <p className="text-sm font-medium text-amber-900 leading-relaxed">{loan.adminNote}</p>
          </div>
        )}

        {/* Footer */}
        <div className="flex items-center justify-between text-[11px] font-medium text-slate-400 border-t border-slate-100 pt-3 mt-auto">
          <span className="flex items-center gap-1.5">
            <svg className="w-3.5 h-3.5 text-slate-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
            {formatDate(loan.createdAt)}
          </span>
          {loan.updatedAt !== loan.createdAt && (
            <span className="text-slate-400">Updated {formatDate(loan.updatedAt)}</span>
          )}
        </div>

        {/* Action buttons */}
        {loan.status === "PENDING" && (onApprove || onReject) && (
          <div className="flex gap-2 mt-4">
            {onApprove && (
              <button
                onClick={() => onApprove(loan.id)}
                disabled={isProcessing}
                className="flex-1 py-2 px-3 bg-white border border-emerald-200 text-emerald-600 text-sm font-bold rounded-lg hover:bg-emerald-50 hover:border-emerald-300 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {isProcessing ? "Processing..." : "Approve"}
              </button>
            )}
            {onReject && (
              <button
                onClick={() => onReject(loan.id)}
                disabled={isProcessing}
                className="flex-1 py-2 px-3 bg-white border border-rose-200 text-rose-600 text-sm font-bold rounded-lg hover:bg-rose-50 hover:border-rose-300 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {isProcessing ? "Processing..." : "Reject"}
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
