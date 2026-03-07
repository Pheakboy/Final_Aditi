"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "../../../context/AuthContext";
import Sidebar from "../../../components/Sidebar";
import LoanCard from "../../../components/LoanCard";
import RiskBadge from "../../../components/RiskBadge";
import { adminApi } from "../../../services/api";
import { Loan, PagedResponse } from "../../../types";
import { formatCurrency, formatDate } from "../../../utils/format";

export default function AdminLoansPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const [loans, setLoans] = useState<Loan[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [dataError, setDataError] = useState("");
  const [filter, setFilter] = useState<
    "" | "PENDING" | "APPROVED" | "REJECTED"
  >("");
  const [riskFilter, setRiskFilter] = useState<"" | "LOW" | "MEDIUM" | "HIGH">(
    "",
  );
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [currentPage, setCurrentPage] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [totalElements, setTotalElements] = useState(0);
  const PAGE_SIZE = 10;
  const [processingId, setProcessingId] = useState<string | null>(null);
  const [noteModal, setNoteModal] = useState<{
    loanId: string;
    decision: "APPROVED" | "REJECTED";
  } | null>(null);
  const [note, setNote] = useState("");
  const [viewMode, setViewMode] = useState<"cards" | "table">("cards");
  const [deleteModal, setDeleteModal] = useState<string | null>(null); // loanId to delete
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [editNoteModal, setEditNoteModal] = useState<{ loanId: string; currentNote: string } | null>(null);
  const [noteEditText, setNoteEditText] = useState("");
  const [noteEditLoading, setNoteEditLoading] = useState(false);

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
    if (!isLoading && user && !isAdmin) router.push("/dashboard");
  }, [user, isLoading, isAdmin, router]);

  const fetchLoans = useCallback(
    async (page = 0) => {
      setDataLoading(true);
      try {
        const res = await adminApi.getLoansFiltered({
          page,
          size: PAGE_SIZE,
          status: filter || undefined,
          riskLevel: riskFilter || undefined,
          from: dateFrom || undefined,
          to: dateTo || undefined,
        });
        const paged: PagedResponse<Loan> = res.data.data;
        setLoans(paged.content || []);
        setCurrentPage(paged.page);
        setTotalPages(paged.totalPages);
        setTotalElements(paged.totalElements);
      } catch (err) {
        console.error("Failed to fetch loans", err);
        setDataError("Failed to load loan applications. Please refresh.");
      } finally {
        setDataLoading(false);
      }
    },
    [filter, riskFilter, dateFrom, dateTo],
  );

  useEffect(() => {
    if (user && isAdmin) {
      setCurrentPage(0);
      fetchLoans(0);
    }
  }, [user, isAdmin, filter, riskFilter, dateFrom, dateTo]);

  const handleDecide = async (
    loanId: string,
    decision: "APPROVED" | "REJECTED",
    noteText?: string,
  ) => {
    setProcessingId(loanId);
    try {
      await adminApi.decideLoan(loanId, { decision, note: noteText });
      await fetchLoans(currentPage);
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

  const handlePageChange = (newPage: number) => {
    setCurrentPage(newPage);
    fetchLoans(newPage);
  };

  const clearFilters = () => {
    setFilter("");
    setRiskFilter("");
    setDateFrom("");
    setDateTo("");
  };

  const handleDelete = async (loanId: string) => {
    setDeleteLoading(true);
    try {
      await adminApi.deleteLoan(loanId);
      setDeleteModal(null);
      await fetchLoans(currentPage);
    } catch { /* ignore */ } finally { setDeleteLoading(false); }
  };

  const handleEditNote = async () => {
    if (!editNoteModal) return;
    setNoteEditLoading(true);
    try {
      await adminApi.updateLoanNote(editNoteModal.loanId, noteEditText);
      setEditNoteModal(null);
      await fetchLoans(currentPage);
    } catch { /* ignore */ } finally { setNoteEditLoading(false); }
  };

  if (isLoading) {
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
            <h1 className="text-2xl font-bold text-gray-900">
              Loan Applications
            </h1>
            <p className="text-gray-500 mt-1">
              {totalElements} application{totalElements !== 1 ? "s" : ""} found
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={async () => {
                try {
                  const res = await adminApi.exportLoans();
                  const url = window.URL.createObjectURL(new Blob([res.data]));
                  const a = document.createElement("a"); a.href = url; a.download = "loans.csv"; a.click();
                  window.URL.revokeObjectURL(url);
                } catch { /* ignore */ }
              }}
              className="flex items-center gap-2 px-3 py-2 bg-white border border-gray-200 text-gray-600 text-sm font-medium rounded-lg hover:bg-gray-50 transition-colors"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
              Export CSV
            </button>
            <button onClick={() => setViewMode("cards")}
              className={`p-2 rounded-lg border transition-colors ${viewMode === "cards" ? "bg-blue-50 border-blue-200 text-blue-600" : "bg-white border-gray-200 text-gray-500 hover:bg-gray-50"}`}>
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
              </svg>
            </button>
            <button onClick={() => setViewMode("table")}
              className={`p-2 rounded-lg border transition-colors ${viewMode === "table" ? "bg-blue-50 border-blue-200 text-blue-600" : "bg-white border-gray-200 text-gray-500 hover:bg-gray-50"}`}>
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
              </svg>
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="bg-white rounded-xl border border-gray-200 p-4 mb-6 space-y-3">
          <div className="flex flex-wrap gap-4 items-center">
            <div className="flex gap-2 items-center">
              <span className="text-sm text-gray-500 font-medium">Status:</span>
              {(["", "PENDING", "APPROVED", "REJECTED"] as const).map((f) => (
                <button
                  key={f || "ALL"}
                  onClick={() => setFilter(f)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${filter === f ? "bg-blue-600 text-white" : "bg-gray-100 text-gray-600 hover:bg-gray-200"}`}
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
                  onClick={() => setRiskFilter(r)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${riskFilter === r ? "bg-blue-600 text-white" : "bg-gray-100 text-gray-600 hover:bg-gray-200"}`}
                >
                  {r || "ALL"}
                </button>
              ))}
            </div>
          </div>
          <div className="flex flex-wrap gap-4 items-center">
            <span className="text-sm text-gray-500 font-medium">
              Date Range:
            </span>
            <div className="flex items-center gap-2">
              <label className="text-xs text-gray-500">From:</label>
              <input
                type="date"
                value={dateFrom}
                onChange={(e) => setDateFrom(e.target.value)}
                className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs text-gray-500">To:</label>
              <input
                type="date"
                value={dateTo}
                onChange={(e) => setDateTo(e.target.value)}
                className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            {(filter || riskFilter || dateFrom || dateTo) && (
              <button
                onClick={clearFilters}
                className="px-3 py-1.5 text-xs font-medium text-red-600 bg-red-50 border border-red-200 rounded-lg hover:bg-red-100 transition-colors"
              >
                Clear Filters
              </button>
            )}
          </div>
        </div>

        {/* Content */}
        {dataLoading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-600"></div>
          </div>
        ) : loans.length === 0 ? (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-12 text-center">
            <p className="text-gray-500">
              No loans match the selected filters.
            </p>
          </div>
        ) : viewMode === "cards" ? (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {loans.map((loan) => (
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
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">Actions</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">Detail</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {loans.map((loan) => {
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
                        {formatDate(loan.createdAt)}
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
                      <td className="px-4 py-3">
                        <div className="flex gap-1">
                          <Link href={`/admin/loans/${loan.id}`} className="text-xs text-blue-600 hover:text-blue-800 font-medium">View →</Link>
                          <button onClick={() => { setEditNoteModal({ loanId: loan.id, currentNote: loan.adminNote || "" }); setNoteEditText(loan.adminNote || ""); }}
                            className="ml-2 text-xs text-indigo-600 hover:text-indigo-800 font-medium">Edit Note</button>
                          <button onClick={() => setDeleteModal(loan.id)}
                            className="ml-2 text-xs text-red-500 hover:text-red-700 font-medium">Delete</button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-6">
            <p className="text-sm text-gray-500">
              Page {currentPage + 1} of {totalPages} &nbsp;·&nbsp;{" "}
              {totalElements} total
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handlePageChange(0)}
                disabled={currentPage === 0}
                className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg bg-white hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                «
              </button>
              <button
                onClick={() => handlePageChange(currentPage - 1)}
                disabled={currentPage === 0}
                className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg bg-white hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                ‹ Prev
              </button>
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                const start = Math.max(
                  0,
                  Math.min(currentPage - 2, totalPages - 5),
                );
                const p = start + i;
                return (
                  <button
                    key={p}
                    onClick={() => handlePageChange(p)}
                    className={`px-3 py-1.5 text-sm border rounded-lg transition-colors ${p === currentPage ? "bg-blue-600 text-white border-blue-600" : "border-gray-300 bg-white hover:bg-gray-50"}`}
                  >
                    {p + 1}
                  </button>
                );
              })}
              <button
                onClick={() => handlePageChange(currentPage + 1)}
                disabled={currentPage >= totalPages - 1}
                className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg bg-white hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Next ›
              </button>
              <button
                onClick={() => handlePageChange(totalPages - 1)}
                disabled={currentPage >= totalPages - 1}
                className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg bg-white hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                »
              </button>
            </div>
          </div>
        )}

        {/* Note Modal */}
        {noteModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-md mx-4">
              <h3 className="text-lg font-semibold text-gray-900 mb-2">
                {noteModal.decision === "APPROVED"
                  ? "Approve Loan"
                  : "Reject Loan"}
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
                  className={`flex-1 py-2 px-4 text-white text-sm font-medium rounded-lg disabled:opacity-50 transition-colors ${noteModal.decision === "APPROVED" ? "bg-green-600 hover:bg-green-700" : "bg-red-600 hover:bg-red-700"}`}
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

      {/* ── Delete Confirm Modal */}
      {deleteModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-2xl shadow-xl p-6 w-full max-w-sm mx-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-2">Delete Loan?</h3>
            <p className="text-sm text-gray-500 mb-5">This action is permanent and cannot be undone.</p>
            <div className="flex gap-3">
              <button onClick={() => handleDelete(deleteModal)} disabled={deleteLoading}
                className="flex-1 py-2 bg-red-600 text-white text-sm font-semibold rounded-lg hover:bg-red-700 disabled:opacity-50 transition-colors">
                {deleteLoading ? "Deleting..." : "Delete"}
              </button>
              <button onClick={() => setDeleteModal(null)}
                className="flex-1 py-2 bg-gray-100 text-gray-700 text-sm font-semibold rounded-lg hover:bg-gray-200 transition-colors">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Edit Note Modal */}
      {editNoteModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-2xl shadow-xl p-6 w-full max-w-md mx-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-2">Edit Admin Note</h3>
            <textarea value={noteEditText} onChange={e => setNoteEditText(e.target.value)} rows={4}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 mb-4 resize-none"
              placeholder="Add a note for this loan..." />
            <div className="flex gap-3">
              <button onClick={handleEditNote} disabled={noteEditLoading}
                className="flex-1 py-2 bg-indigo-600 text-white text-sm font-semibold rounded-lg hover:bg-indigo-700 disabled:opacity-50 transition-colors">
                {noteEditLoading ? "Saving..." : "Save Note"}
              </button>
              <button onClick={() => setEditNoteModal(null)}
                className="flex-1 py-2 bg-gray-100 text-gray-700 text-sm font-semibold rounded-lg hover:bg-gray-200 transition-colors">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
