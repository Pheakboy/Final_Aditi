"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../../context/AuthContext";
import AdminLayout from "../../../components/admin/AdminLayout";
import LoanCard from "../../../components/LoanCard";
import { adminApi } from "../../../services/api";
import { Loan, PagedResponse } from "../../../types";
import LoadingScreen from "../../../components/ui/LoadingScreen";
import ErrorAlert from "../../../components/ui/ErrorAlert";
import Pagination from "../../../components/ui/Pagination";
import LoanFilters from "../../../components/admin/LoanFilters";
import LoanTable from "../../../components/admin/LoanTable";
import NoteModal from "../../../components/admin/NoteModal";
import axios from "axios";
import { useToast } from "../../../components/ui/Toast";

export default function AdminApplicantsPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const { showToast } = useToast();
  const [loans, setLoans] = useState<Loan[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [dataError, setDataError] = useState("");
  const [filter, setFilter] = useState<
    "" | "PENDING" | "APPROVED" | "ACTIVE" | "REJECTED" | "COMPLETED"
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
  const [viewMode, setViewMode] = useState<"cards" | "table">("table");

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
      } catch {
        setDataError("Failed to load applicants. Please refresh.");
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
      showToast(
        decision === "APPROVED"
          ? "Loan approved successfully"
          : "Loan rejected",
        decision === "APPROVED" ? "success" : "info",
      );
      await fetchLoans(currentPage);
    } catch (err: unknown) {
      const msg = axios.isAxiosError(err)
        ? (err.response?.data?.message ??
          "Failed to process decision. Please try again.")
        : "Failed to process decision. Please try again.";
      setDataError(msg);
      await fetchLoans(currentPage);
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

  if (isLoading) {
    return <LoadingScreen color="border-blue-600" />;
  }

  return (
    <AdminLayout title="All Applicants" subtitle="Loan applications for review">
      <div className="p-8">
        {dataError && <ErrorAlert message={dataError} />}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">All Applicants</h1>
            <p className="text-gray-500 mt-1">
              {totalElements} application{totalElements !== 1 ? "s" : ""} found
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

        <LoanFilters
          filter={filter}
          riskFilter={riskFilter}
          dateFrom={dateFrom}
          dateTo={dateTo}
          onFilterChange={setFilter}
          onRiskFilterChange={setRiskFilter}
          onDateFromChange={setDateFrom}
          onDateToChange={setDateTo}
          onClearFilters={clearFilters}
        />

        {dataLoading ? (
          viewMode === "cards" ? (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {Array.from({ length: 6 }).map((_, i) => (
                <div
                  key={i}
                  className="bg-white rounded-xl border border-gray-200 p-6 animate-pulse"
                >
                  <div className="flex justify-between mb-4">
                    <div className="space-y-2">
                      <div className="h-4 bg-gray-200 rounded w-32"></div>
                      <div className="h-3 bg-gray-200 rounded w-24"></div>
                    </div>
                    <div className="h-6 bg-gray-200 rounded-full w-20"></div>
                  </div>
                  <div className="space-y-2">
                    <div className="h-3 bg-gray-200 rounded w-full"></div>
                    <div className="h-3 bg-gray-200 rounded w-4/5"></div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
              <div className="divide-y divide-gray-100">
                {Array.from({ length: 8 }).map((_, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-4 px-6 py-4 animate-pulse"
                  >
                    <div className="h-3 bg-gray-200 rounded w-32"></div>
                    <div className="h-3 bg-gray-200 rounded w-24 flex-1"></div>
                    <div className="h-3 bg-gray-200 rounded w-20"></div>
                    <div className="h-6 bg-gray-200 rounded-full w-16"></div>
                    <div className="h-6 bg-gray-200 rounded w-24"></div>
                  </div>
                ))}
              </div>
            </div>
          )
        ) : loans.length === 0 ? (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-12 text-center">
            <p className="text-gray-500">
              No applicants match the selected filters.
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
          />
        )}

        <Pagination
          currentPage={currentPage}
          totalPages={totalPages}
          totalElements={totalElements}
          onPageChange={handlePageChange}
        />

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
      </div>
    </AdminLayout>
  );
}
