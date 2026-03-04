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

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <div className="animate-spin rounded-full h-10 w-10 border-2 border-indigo-500 border-t-transparent"></div>
      </div>
    );
  }

  const approvedCount = allLoans.filter((l) => l.status === "APPROVED").length;
  const rejectedCount = allLoans.filter((l) => l.status === "REJECTED").length;

  const statCards = [
    {
      label: "Total Applications",
      value: allLoans.length,
      icon: (
        <svg
          className="w-5 h-5 text-white"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
          />
        </svg>
      ),
      bg: "gradient-indigo",
      valueColor: "text-slate-900",
    },
    {
      label: "Pending Review",
      value: pendingLoans.length,
      icon: (
        <svg
          className="w-5 h-5 text-white"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
      ),
      bg: "gradient-amber",
      valueColor: "text-amber-600",
    },
    {
      label: "Approved",
      value: approvedCount,
      icon: (
        <svg
          className="w-5 h-5 text-white"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
      ),
      bg: "gradient-emerald",
      valueColor: "text-emerald-600",
    },
    {
      label: "Rejected",
      value: rejectedCount,
      icon: (
        <svg
          className="w-5 h-5 text-white"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
      ),
      bg: "gradient-rose",
      valueColor: "text-red-500",
    },
  ];

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-6 lg:p-8 overflow-auto">
        {/* Header */}
        <div className="mb-8 animate-fade-in">
          <h1 className="text-2xl font-bold text-slate-900">Admin Dashboard</h1>
          <p className="text-slate-500 mt-1 text-sm">
            Review and manage loan applications
          </p>
        </div>

        {dataError && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl text-sm mb-6 flex items-center gap-2">
            <svg
              className="w-4 h-4 shrink-0"
              fill="currentColor"
              viewBox="0 0 20 20"
            >
              <path
                fillRule="evenodd"
                d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                clipRule="evenodd"
              />
            </svg>
            {dataError}
          </div>
        )}

        {/* Stat Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
          {statCards.map((card) => (
            <div
              key={card.label}
              className="bg-white rounded-2xl card-shadow p-5 flex items-start gap-3"
            >
              <div
                className={`${card.bg} w-10 h-10 rounded-xl flex items-center justify-center shrink-0`}
              >
                {card.icon}
              </div>
              <div>
                <p className="text-xs text-slate-500">{card.label}</p>
                <p className={`text-2xl font-bold mt-0.5 ${card.valueColor}`}>
                  {card.value}
                </p>
              </div>
            </div>
          ))}
        </div>

        {/* Pending Applications */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <h2 className="text-base font-semibold text-slate-900">
                Pending Applications
              </h2>
              {pendingLoans.length > 0 && (
                <span className="bg-amber-100 text-amber-700 text-xs font-semibold px-2 py-0.5 rounded-full">
                  {pendingLoans.length}
                </span>
              )}
            </div>
            <Link
              href="/admin/applicants"
              className="text-xs font-medium text-indigo-600 hover:text-indigo-700"
            >
              View all loans →
            </Link>
          </div>

          {pendingLoans.length === 0 ? (
            <div className="bg-white rounded-2xl card-shadow p-12 text-center">
              <div className="w-12 h-12 bg-emerald-50 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg
                  className="w-6 h-6 text-emerald-500"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={1.5}
                    d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                  />
                </svg>
              </div>
              <p className="text-slate-500 text-sm font-medium">
                All caught up!
              </p>
              <p className="text-slate-400 text-xs mt-1">
                No pending loan applications.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
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
          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-2xl shadow-2xl p-6 w-full max-w-md animate-fade-in">
              <div
                className={`w-10 h-10 rounded-xl flex items-center justify-center mb-4 ${noteModal.decision === "APPROVED" ? "bg-emerald-50" : "bg-red-50"}`}
              >
                {noteModal.decision === "APPROVED" ? (
                  <svg
                    className="w-5 h-5 text-emerald-600"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                    />
                  </svg>
                ) : (
                  <svg
                    className="w-5 h-5 text-red-500"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"
                    />
                  </svg>
                )}
              </div>
              <h3 className="text-base font-semibold text-slate-900 mb-1">
                {noteModal.decision === "APPROVED"
                  ? "Approve Loan"
                  : "Reject Loan"}
              </h3>
              <p className="text-sm text-slate-500 mb-4">
                Add an optional note for the applicant:
              </p>
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                rows={3}
                className="w-full px-4 py-3 border border-slate-200 rounded-xl text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors mb-4 resize-none"
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
                  className={`flex-1 py-2.5 px-4 text-white text-sm font-semibold rounded-xl disabled:opacity-50 transition-colors ${noteModal.decision === "APPROVED" ? "bg-emerald-600 hover:bg-emerald-700" : "bg-red-500 hover:bg-red-600"}`}
                >
                  {processingId
                    ? "Processing..."
                    : `Confirm ${noteModal.decision === "APPROVED" ? "Approval" : "Rejection"}`}
                </button>
                <button
                  onClick={() => {
                    setNoteModal(null);
                    setNote("");
                  }}
                  className="flex-1 py-2.5 px-4 bg-slate-100 text-slate-700 text-sm font-semibold rounded-xl hover:bg-slate-200 transition-colors"
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
