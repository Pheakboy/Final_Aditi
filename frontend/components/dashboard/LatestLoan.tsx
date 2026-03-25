import Link from "next/link";
import RiskBadge from "../RiskBadge";
import { Loan } from "../../types";
import { formatCurrency } from "../../utils/format";

interface LatestLoanProps {
  loan: Loan;
}

const STATUS_STYLES: Record<string, string> = {
  APPROVED: "bg-emerald-50 text-emerald-700",
  ACTIVE: "bg-teal-50 text-teal-700",
  COMPLETED: "bg-blue-50 text-blue-700",
  REJECTED: "bg-red-50 text-red-700",
  PENDING: "bg-amber-50 text-amber-700",
};

export default function LatestLoan({ loan }: LatestLoanProps) {
  return (
    <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-6 mb-8 transition-all hover:shadow-md">
      <div className="flex items-center justify-between mb-6 relative z-10">
        <h2 className="text-base font-semibold text-slate-900 tracking-tight">
          Latest Loan Application
        </h2>
        <Link
          href="/loan/status"
          className="text-sm font-bold text-teal-600 hover:text-teal-700 bg-teal-50 px-3 py-1.5 rounded-lg transition-colors"
        >
          View all →
        </Link>
      </div>
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-2xl font-bold text-slate-900">
            {formatCurrency(loan.loanAmount)}
          </p>
          {loan.purpose && (
            <p className="text-sm text-slate-400 mt-0.5">{loan.purpose}</p>
          )}
          <div className="flex items-center gap-2 mt-2">
            <span
              className={`text-xs font-semibold px-2 py-0.5 rounded-full ${STATUS_STYLES[loan.status] ?? "bg-slate-100 text-slate-700"}`}
            >
              {loan.status}
            </span>
          </div>
          {loan.adminNote && (
            <p className="text-sm text-slate-500 mt-2 italic">
              &ldquo;{loan.adminNote}&rdquo;
            </p>
          )}
        </div>
        <RiskBadge level={loan.riskLevel} score={loan.riskScore} />
      </div>
    </div>
  );
}
