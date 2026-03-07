"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "../../../context/AuthContext";
import Sidebar from "../../../components/Sidebar";
import LoanCard from "../../../components/LoanCard";
import { adminApi } from "../../../services/api";
import { Loan, PagedResponse } from "../../../types";
import LoadingScreen from "../../../components/ui/LoadingScreen";
import ErrorAlert from "../../../components/ui/ErrorAlert";
import Pagination from "../../../components/ui/Pagination";
import LoanFilters from "../../../components/admin/LoanFilters";
import LoanTable from "../../../components/admin/LoanTable";
import NoteModal from "../../../components/admin/NoteModal";
import DeleteModal from "../../../components/admin/DeleteModal";
import EditNoteModal from "../../../components/admin/EditNoteModal";

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
  const [editNoteModal, setEditNoteModal] = useState<{
    loanId: string;
    currentNote: string;
  } | null>(null);
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
    } catch {
      /* ignore */
    } finally {
      setDeleteLoading(false);
    }
  };

  const handleEditNote = async () => {
    if (!editNoteModal) return;
    setNoteEditLoading(true);
    try {
      await adminApi.updateLoanNote(editNoteModal.loanId, noteEditText);
      setEditNoteModal(null);
      await fetchLoans(currentPage);
    } catch {
      /* ignore */
    } finally {
      setNoteEditLoading(false);
    }
  };

  if (isLoading) {
    return <LoadingScreen color="border-blue-600" />;
  }

  return (
    <div className="flex min-h-screen bg-gray-50">
      <Sidebar />
      <main className="flex-1 p-8">
        {dataError && <ErrorAlert message={dataError} />}
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
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = "loans.csv";
                  a.click();
                  window.URL.revokeObjectURL(url);
                } catch {
                  /* ignore */
                }
              }}
              className="flex items-center gap-2 px-3 py-2 bg-white border border-gray-200 text-gray-600 text-sm font-medium rounded-lg hover:bg-gray-50 transition-colors"
            >
              <svg
                className="w-4 h-4"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
                />
              </svg>
              Export CSV
            </button>
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
            <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-600" />
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
          <LoanTable
            loans={loans}
            processingId={processingId}
            onApprove={(id) => openNoteModal(id, "APPROVED")}
            onReject={(id) => openNoteModal(id, "REJECTED")}
            onViewDetail={(id) => router.push(`/admin/loans/${id}`)}
            onEditNote={(id, current) => {
              setEditNoteModal({ loanId: id, currentNote: current });
              setNoteEditText(current);
            }}
            onDelete={(id) => setDeleteModal(id)}
          />
        )}

        <Pagination
          currentPage={currentPage}
          totalPages={totalPages}
          totalElements={totalElements}
          onPageChange={handlePageChange}
        />

        {/* Note Modal */}
        {noteModal && (
          <NoteModal
            decision={noteModal.decision}
            note={note}
            isProcessing={processingId !== null}
            onNoteChange={setNote}
            onConfirm={() =>
              handleDecide(
                noteModal.loanId,
                noteModal.decision,
                note || undefined,
              )
            }
            onCancel={() => {
              setNoteModal(null);
              setNote("");
            }}
          />
        )}
      </main>

      {/* Delete Modal */}
      {deleteModal && (
        <DeleteModal
          isLoading={deleteLoading}
          onConfirm={() => handleDelete(deleteModal)}
          onCancel={() => setDeleteModal(null)}
        />
      )}

      {/* Edit Note Modal */}
      {editNoteModal && (
        <EditNoteModal
          noteText={noteEditText}
          isLoading={noteEditLoading}
          onNoteChange={setNoteEditText}
          onSave={handleEditNote}
          onCancel={() => setEditNoteModal(null)}
        />
      )}
    </div>
  );
}
