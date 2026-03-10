"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "../../../context/AuthContext";
import Sidebar from "../../../components/Sidebar";
import LoanCard from "../../../components/LoanCard";
import { adminApi } from "../../../services/api";
import { Loan } from "../../../types";
import LoadingScreen from "../../../components/ui/LoadingScreen";
import ErrorAlert from "../../../components/ui/ErrorAlert";
import StatCard from "../../../components/ui/StatCard";
import NoteModal from "../../../components/admin/NoteModal";

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
    return <LoadingScreen color="border-indigo-500" />;
  }

  const approvedCount = allLoans.filter((l) => l.status === "APPROVED").length;
  const rejectedCount = allLoans.filter((l) => l.status === "REJECTED").length;

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-6 lg:p-10 overflow-auto bg-slate-50">
        {/* Header */}
        <div className="mb-8 animate-slide-up flex flex-col sm:flex-row sm:items-end justify-between gap-4">
          <div>
            <h1 className="text-3xl font-extrabold text-slate-900 tracking-tight">Admin Dashboard</h1>
            <p className="text-slate-500 mt-1 text-sm font-medium">
              Review and manage loan applications across the platform
            </p>
          </div>
          <div className="text-sm font-semibold text-slate-500 bg-white px-3 py-1.5 rounded-lg border border-slate-200 shadow-sm inline-block">
            {new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'short', day: 'numeric' })}
          </div>
        </div>

        {dataError && <ErrorAlert message={dataError} />}

        {/* Stat Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
          <StatCard
            label="Total Applications"
            value={allLoans.length}
            iconBg="gradient-indigo"
            icon={
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
            }
          />
          <StatCard
            label="Pending Review"
            value={pendingLoans.length}
            valueColor="text-amber-600"
            iconBg="gradient-amber"
            icon={
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
            }
          />
          <StatCard
            label="Approved"
            value={approvedCount}
            valueColor="text-emerald-600"
            iconBg="gradient-emerald"
            icon={
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
            }
          />
          <StatCard
            label="Rejected"
            value={rejectedCount}
            valueColor="text-red-500"
            iconBg="gradient-rose"
            icon={
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
            }
          />
        </div>

        {/* Pending Applications Section */}
        <div className="mb-4 mt-8 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h2 className="text-xl font-bold text-slate-800 tracking-tight">Pending Applications</h2>
            {pendingLoans.length > 0 && (
              <span className="bg-amber-500/10 border border-amber-500/20 text-amber-700 text-xs font-bold px-2.5 py-1 rounded-full shadow-sm shadow-amber-500/10">
                {pendingLoans.length}
              </span>
            )}
          </div>
          <div className="h-px bg-slate-200/60 flex-1 ml-6 mr-6 hidden sm:block"></div>
          <Link
            href="/admin/applicants"
            className="text-sm font-bold text-indigo-600 hover:text-indigo-700 bg-indigo-50 px-4 py-2 rounded-xl transition-all hover:bg-indigo-100"
          >
            Review all →
          </Link>
        </div>

        <div className="animate-slide-up" style={{ animationDelay: "150ms" }}>
          {pendingLoans.length === 0 ? (
            <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-16 text-center">
              <div className="w-16 h-16 bg-emerald-50 rounded-2xl flex items-center justify-center mx-auto mb-6 border border-emerald-100">
                <svg
                  className="w-8 h-8 text-emerald-500"
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
              </div>
              <p className="text-slate-800 text-lg font-bold tracking-tight mb-1">
                All caught up!
              </p>
              <p className="text-slate-500 text-sm font-medium">
                There are no pending loan applications at this time.
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
    </div>
  );
}
