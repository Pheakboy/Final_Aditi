"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "../../../context/AuthContext";
import Sidebar from "../../../components/Sidebar";
import LoanCard from "../../../components/LoanCard";
import { adminApi } from "../../../services/api";
import { Loan } from "../../../types";

export default function AdminDashboardPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const [pendingLoans, setPendingLoans] = useState<Loan[]>([]);
  const [allLoans, setAllLoans] = useState<Loan[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [dataError, setDataError] = useState("");
  const [processingId, setProcessingId] = useState<string | null>(null);
  const [noteModal, setNoteModal] = useState<{
    loanId: string;
    decision: "APPROVED" | "REJECTED";
  } | null>(null);
  const [note, setNote] = useState("");

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
    if (!isLoading && user && !isAdmin) router.push("/dashboard");
  }, [user, isLoading, isAdmin, router]);

  const fetchData = async () => {
    setDataLoading(true);
    try {
      const [pendingRes, allRes] = await Promise.all([
        adminApi.getPendingLoans(),
        adminApi.getAllLoans(),
      ]);
      setPendingLoans(pendingRes.data.data || []);
      setAllLoans(allRes.data.data || []);
    } catch (err) {
      console.error("Failed to fetch admin data", err);
      setDataError("Failed to load dashboard data. Please refresh.");
    } finally {
      setDataLoading(false);
    }
  };

  useEffect(() => {
    if (user && isAdmin) fetchData();
  }, [user, isAdmin]);

  const handleDecide = async (
    loanId: string,
    decision: "APPROVED" | "REJECTED",
    noteText?: string,
  ) => {
    setProcessingId(loanId);
    try {
      await adminApi.decideLoan(loanId, { decision, note: noteText });
      await fetchData();
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

  if (isLoading || dataLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  const approvedCount = allLoans.filter((l) => l.status === "APPROVED").length;
  const rejectedCount = allLoans.filter((l) => l.status === "REJECTED").length;

  return (
    <div className="flex min-h-screen bg-gray-50">
      <Sidebar />
      <main className="flex-1 p-8">
        {dataError && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm mb-6">
            {dataError}
          </div>
        )}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-gray-900">Admin Dashboard</h1>
          <p className="text-gray-500 mt-1">
            Review and manage loan applications
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <p className="text-sm text-gray-500 mb-1">Total Applications</p>
            <p className="text-3xl font-bold text-gray-900">
              {allLoans.length}
            </p>
          </div>
          <div className="bg-yellow-50 rounded-xl border border-yellow-200 p-6">
            <p className="text-sm text-yellow-700 mb-1">Pending Review</p>
            <p className="text-3xl font-bold text-yellow-700">
              {pendingLoans.length}
            </p>
          </div>
          <div className="bg-green-50 rounded-xl border border-green-200 p-6">
            <p className="text-sm text-green-700 mb-1">Approved</p>
            <p className="text-3xl font-bold text-green-700">{approvedCount}</p>
          </div>
          <div className="bg-red-50 rounded-xl border border-red-200 p-6">
            <p className="text-sm text-red-700 mb-1">Rejected</p>
            <p className="text-3xl font-bold text-red-700">{rejectedCount}</p>
          </div>
        </div>

        {/* Pending Loans */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">
              Pending Applications
              {pendingLoans.length > 0 && (
                <span className="ml-2 bg-yellow-100 text-yellow-700 text-sm px-2 py-0.5 rounded-full">
                  {pendingLoans.length}
                </span>
              )}
            </h2>
            <Link
              href="/admin/applicants"
              className="text-sm text-blue-600 hover:text-blue-700 font-medium"
            >
              View all loans →
            </Link>
          </div>

          {pendingLoans.length === 0 ? (
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-12 text-center">
              <svg
                className="w-12 h-12 text-gray-300 mx-auto mb-4"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1}
                  d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <p className="text-gray-500">
                No pending loan applications. All caught up!
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {pendingLoans.map((loan) => (
                <LoanCard
                  key={loan.id}
                  loan={loan}
                  showApplicant={true}
                  onApprove={(id) => openNoteModal(id, "APPROVED")}
                  onReject={(id) => openNoteModal(id, "REJECTED")}
                  isProcessing={processingId === loan.id}
                />
              ))}
            </div>
          )}
        </div>

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
                    ? "e.g. Congratulations! Your loan has been approved."
                    : "e.g. Insufficient income documentation."
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
