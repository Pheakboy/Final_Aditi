"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../../context/AuthContext";
import Sidebar from "../../../components/Sidebar";
import LoanCard from "../../../components/LoanCard";
import RiskBadge from "../../../components/RiskBadge";
import { adminApi } from "../../../services/api";
import { Loan } from "../../../types";
import { formatCurrency } from "../../../utils/format";

export default function AdminApplicantsPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const [loans, setLoans] = useState<Loan[]>([]);
  const [dataLoading, setDataLoading] = useState(true);
  const [dataError, setDataError] = useState("");
  const [filter, setFilter] = useState<
    "ALL" | "PENDING" | "APPROVED" | "REJECTED"
  >("ALL");
  const [riskFilter, setRiskFilter] = useState<
    "ALL" | "LOW" | "MEDIUM" | "HIGH"
  >("ALL");
  const [processingId, setProcessingId] = useState<string | null>(null);
  const [noteModal, setNoteModal] = useState<{
    loanId: string;
    decision: "APPROVED" | "REJECTED";
  } | null>(null);
  const [note, setNote] = useState("");
  const [viewMode, setViewMode] = useState<"cards" | "table">("cards");

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
    if (!isLoading && user && !isAdmin) router.push("/dashboard");
  }, [user, isLoading, isAdmin, router]);

  const fetchLoans = async () => {
    try {
      const res = await adminApi.getAllLoans();
      setLoans(res.data.data || []);
    } catch (err) {
      console.error("Failed to fetch loans", err);
      setDataError("Failed to load applicants. Please refresh.");
    } finally {
      setDataLoading(false);
    }
  };

  useEffect(() => {
    if (user && isAdmin) fetchLoans();
  }, [user, isAdmin]);

  const handleDecide = async (
    loanId: string,
    decision: "APPROVED" | "REJECTED",
    noteText?: string,
  ) => {
    setProcessingId(loanId);
    try {
      await adminApi.decideLoan(loanId, { decision, note: noteText });
      await fetchLoans();
    } catch (err) {
      console.error("Failed to process decision", err);
    } finally {
      setProcessingId(null);
      setNoteModal(null);
      setNote("");
    }
  };

  const openNoteModal = (loanId: string, decision: "APPROVED" | "REJECTED") => {
    setNoteModal({ loanId, decision });
    setNote("");
  };

  const filteredLoans = loans.filter((loan) => {
    const statusMatch = filter === "ALL" || loan.status === filter;
    const riskMatch = riskFilter === "ALL" || loan.riskLevel === riskFilter;
    return statusMatch && riskMatch;
  });


  if (isLoading || dataLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-gray-50">
      <Sidebar />
      <main className="flex-1 p-8">
        {dataError && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm mb-6">
            {dataError}
          </div>
        )}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">All Applicants</h1>
            <p className="text-gray-500 mt-1">
              {filteredLoans.length} of {loans.length} applications
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setViewMode("cards")}
              className={`p-2 rounded-lg border transition-colors ${viewMode === "cards" ? "bg-blue-50 border-blue-200 text-blue-600" : "bg-white border-gray-200 text-gray-500 hover:bg-gray-50"}`}
            >
              <svg
                className="w-5 h-5"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"
                />
              </svg>
            </button>
            <button
              onClick={() => setViewMode("table")}
              className={`p-2 rounded-lg border transition-colors ${viewMode === "table" ? "bg-blue-50 border-blue-200 text-blue-600" : "bg-white border-gray-200 text-gray-500 hover:bg-gray-50"}`}
            >
              <svg
                className="w-5 h-5"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M4 6h16M4 10h16M4 14h16M4 18h16"
                />
              </svg>
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-4 mb-6">
          <div className="flex gap-2">
            <span className="text-sm text-gray-500 self-center">Status:</span>
            {(["ALL", "PENDING", "APPROVED", "REJECTED"] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                  filter === f
                    ? "bg-blue-600 text-white"
                    : "bg-white text-gray-600 border border-gray-200 hover:bg-gray-50"
                }`}
              >
                {f}
              </button>
            ))}
          </div>
          <div className="flex gap-2">
            <span className="text-sm text-gray-500 self-center">Risk:</span>
            {(["ALL", "LOW", "MEDIUM", "HIGH"] as const).map((r) => (
              <button
                key={r}
                onClick={() => setRiskFilter(r)}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                  riskFilter === r
                    ? "bg-blue-600 text-white"
                    : "bg-white text-gray-600 border border-gray-200 hover:bg-gray-50"
                }`}
              >
                {r}
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        {filteredLoans.length === 0 ? (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-12 text-center">
            <p className="text-gray-500">
              No loans match the selected filters.
            </p>
          </div>
        ) : viewMode === "cards" ? (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {filteredLoans.map((loan) => (
              <LoanCard
                key={loan.id}
                loan={loan}
                showApplicant={true}
                onApprove={
                  loan.status === "PENDING"
                    ? (id) => openNoteModal(id, "APPROVED")
                    : undefined
                }
                onReject={
                  loan.status === "PENDING"
                    ? (id) => openNoteModal(id, "REJECTED")
                    : undefined
                }
                isProcessing={processingId === loan.id}
              />
            ))}
          </div>
        ) : (
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
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {filteredLoans.map((loan) => {
                  const statusColors = {
                    PENDING: "bg-yellow-100 text-yellow-700",
                    APPROVED: "bg-green-100 text-green-700",
                    REJECTED: "bg-red-100 text-red-700",
                  };
                  return (
                    <tr key={loan.id} className="hover:bg-gray-50">
                      <td className="px-4 py-3">
                        <div>
                          <p className="font-medium text-gray-900">
                            {loan.applicantUsername}
                          </p>
                          <p className="text-xs text-gray-400">
                            {loan.applicantEmail}
                          </p>
                        </div>
                      </td>
                      <td className="px-4 py-3 font-medium text-gray-900">
                        {formatCurrency(loan.loanAmount)}
                      </td>
                      <td className="px-4 py-3">
                        <RiskBadge
                          level={loan.riskLevel}
                          score={loan.riskScore}
                        />
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`px-2 py-1 rounded-full text-xs font-medium ${statusColors[loan.status]}`}
                        >
                          {loan.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-500 text-xs">
                        {new Date(loan.createdAt).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-3">
                        {loan.status === "PENDING" && (
                          <div className="flex gap-2">
                            <button
                              onClick={() => openNoteModal(loan.id, "APPROVED")}
                              disabled={processingId === loan.id}
                              className="px-2 py-1 bg-green-600 text-white text-xs rounded hover:bg-green-700 disabled:opacity-50 transition-colors"
                            >
                              Approve
                            </button>
                            <button
                              onClick={() => openNoteModal(loan.id, "REJECTED")}
                              disabled={processingId === loan.id}
                              className="px-2 py-1 bg-red-600 text-white text-xs rounded hover:bg-red-700 disabled:opacity-50 transition-colors"
                            >
                              Reject
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Note Modal */}
        {noteModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-md mx-4">
              <h3 className="text-lg font-semibold text-gray-900 mb-2">
                {noteModal.decision === "APPROVED"
                  ? "✅ Approve Loan"
                  : "❌ Reject Loan"}
              </h3>
              <p className="text-sm text-gray-500 mb-4">
                Add an optional note for the applicant:
              </p>
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                rows={3}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm mb-4"
                placeholder={
                  noteModal.decision === "APPROVED"
                    ? "e.g. Congratulations! Loan approved."
                    : "e.g. Insufficient income."
                }
              />
              <div className="flex gap-3">
                <button
                  onClick={() =>
                    handleDecide(
                      noteModal.loanId,
                      noteModal.decision,
                      note || undefined,
                    )
                  }
                  disabled={processingId !== null}
                  className={`flex-1 py-2 px-4 text-white text-sm font-medium rounded-lg disabled:opacity-50 transition-colors ${
                    noteModal.decision === "APPROVED"
                      ? "bg-green-600 hover:bg-green-700"
                      : "bg-red-600 hover:bg-red-700"
                  }`}
                >
                  {processingId
                    ? "Processing..."
                    : `Confirm ${noteModal.decision}`}
                </button>
                <button
                  onClick={() => {
                    setNoteModal(null);
                    setNote("");
                  }}
                  className="flex-1 py-2 px-4 bg-gray-100 text-gray-700 text-sm font-medium rounded-lg hover:bg-gray-200 transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
