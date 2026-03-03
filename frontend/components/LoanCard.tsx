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
    PENDING: { bg: "bg-yellow-100", text: "text-yellow-800", label: "Pending" },
    APPROVED: { bg: "bg-green-100", text: "text-green-800", label: "Approved" },
    REJECTED: { bg: "bg-red-100", text: "text-red-800", label: "Rejected" },
  };

  const status = statusConfig[loan.status];


  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between mb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h3 className="text-lg font-semibold text-gray-900">
              {formatCurrency(loan.loanAmount)}
            </h3>
            <span
              className={`px-2 py-0.5 rounded-full text-xs font-medium ${status.bg} ${status.text}`}
            >
              {status.label}
            </span>
          </div>
          {loan.purpose && (
            <p className="text-sm text-gray-500">{loan.purpose}</p>
          )}
          {showApplicant && loan.applicantUsername && (
            <p className="text-sm text-blue-600 font-medium mt-1">
              Applicant: {loan.applicantUsername} ({loan.applicantEmail})
            </p>
          )}
        </div>
        <RiskBadge level={loan.riskLevel} score={loan.riskScore} />
      </div>

      <div className="grid grid-cols-2 gap-3 mb-4">
        <div className="bg-gray-50 rounded-lg p-3">
          <p className="text-xs text-gray-500 mb-1">Monthly Income</p>
          <p className="text-sm font-semibold text-gray-900">
            {formatCurrency(loan.monthlyIncome)}
          </p>
        </div>
        <div className="bg-gray-50 rounded-lg p-3">
          <p className="text-xs text-gray-500 mb-1">Monthly Expense</p>
          <p className="text-sm font-semibold text-gray-900">
            {formatCurrency(loan.monthlyExpense)}
          </p>
        </div>
      </div>

      {loan.adminNote && (
        <div className="bg-blue-50 border border-blue-100 rounded-lg p-3 mb-4">
          <p className="text-xs text-blue-600 font-medium mb-1">Admin Note</p>
          <p className="text-sm text-blue-800">{loan.adminNote}</p>
        </div>
      )}

      <div className="flex items-center justify-between text-xs text-gray-400">
        <span>Applied: {formatDate(loan.createdAt)}</span>
        {loan.updatedAt !== loan.createdAt && (
          <span>Updated: {formatDate(loan.updatedAt)}</span>
        )}
      </div>

      {loan.status === "PENDING" && (onApprove || onReject) && (
        <div className="flex gap-2 mt-4 pt-4 border-t border-gray-100">
          {onApprove && (
            <button
              onClick={() => onApprove(loan.id)}
              disabled={isProcessing}
              className="flex-1 py-2 px-4 bg-green-600 text-white text-sm font-medium rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {isProcessing ? "Processing..." : "Approve"}
            </button>
          )}
          {onReject && (
            <button
              onClick={() => onReject(loan.id)}
              disabled={isProcessing}
              className="flex-1 py-2 px-4 bg-red-600 text-white text-sm font-medium rounded-lg hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {isProcessing ? "Processing..." : "Reject"}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
