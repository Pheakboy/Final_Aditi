import Link from "next/link";
import RiskBadge from "../RiskBadge";
import { Loan } from "../../types";
import { formatCurrency, formatDate } from "../../utils/format";

interface LoanTableProps {
  loans: Loan[];
  processingId: string | null;
  onApprove: (id: string) => void;
  onReject: (id: string) => void;
  onViewDetail?: (id: string) => void;
  onEditNote?: (id: string, currentNote: string) => void;
  onDelete?: (id: string) => void;
}

const STATUS_COLORS: Record<string, string> = {
  PENDING: "bg-yellow-100 text-yellow-700",
  APPROVED: "bg-green-100 text-green-700",
  REJECTED: "bg-red-100 text-red-700",
  ACTIVE: "bg-blue-100 text-blue-700",
  COMPLETED: "bg-slate-100 text-slate-600",
};

export default function LoanTable({
  loans,
  processingId,
  onApprove,
  onReject,
  onViewDetail,
  onEditNote,
  onDelete,
}: LoanTableProps) {
  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-gray-50 border-b border-gray-200">
          <tr>
            <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
              Applicant
            </th>
            <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
              Loan Amount
            </th>
            <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
              Risk
            </th>
            <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
              Status
            </th>
            <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
              Date
            </th>
            <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
              Actions
            </th>
            {onViewDetail && (
              <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                Detail
              </th>
            )}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {loans.map((loan) => (
            <tr key={loan.id} className="hover:bg-gray-50">
              <td className="px-4 py-3">
                <p className="font-medium text-gray-900">
                  {loan.applicantUsername}
                </p>
                <p className="text-xs text-gray-400">{loan.applicantEmail}</p>
              </td>
              <td className="px-4 py-3 font-medium text-gray-900">
                {formatCurrency(loan.loanAmount)}
              </td>
              <td className="px-4 py-3">
                <RiskBadge level={loan.riskLevel} score={loan.riskScore} />
              </td>
              <td className="px-4 py-3">
                <span
                  className={`px-2 py-1 rounded-full text-xs font-medium ${STATUS_COLORS[loan.status]}`}
                >
                  {loan.status}
                </span>
              </td>
              <td className="px-4 py-3 text-gray-500 text-xs">
                {formatDate(loan.createdAt)}
              </td>
              <td className="px-4 py-3">
                <div className="flex gap-2 flex-wrap">
                  {loan.status === "PENDING" && (
                    <>
                      <button
                        onClick={() => onApprove(loan.id)}
                        disabled={processingId === loan.id}
                        className="px-2 py-1 bg-green-600 text-white text-xs rounded hover:bg-green-700 disabled:opacity-50 transition-colors"
                      >
                        Approve
                      </button>
                      <button
                        onClick={() => onReject(loan.id)}
                        disabled={processingId === loan.id}
                        className="px-2 py-1 bg-red-600 text-white text-xs rounded hover:bg-red-700 disabled:opacity-50 transition-colors"
                      >
                        Reject
                      </button>
                    </>
                  )}
                </div>
              </td>
              {onViewDetail && (
                <td className="px-4 py-3">
                  <div className="flex gap-1 flex-wrap">
                    <Link
                      href={`/admin/loans/${loan.id}`}
                      className="text-xs text-blue-600 hover:text-blue-800 font-medium"
                    >
                      View →
                    </Link>
                    {onEditNote && (
                      <button
                        onClick={() =>
                          onEditNote(loan.id, loan.adminNote || "")
                        }
                        className="ml-2 text-xs text-indigo-600 hover:text-indigo-800 font-medium"
                      >
                        Edit Note
                      </button>
                    )}
                    {onDelete && (
                      <button
                        onClick={() => onDelete(loan.id)}
                        className="ml-2 text-xs text-red-500 hover:text-red-700 font-medium"
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
