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
      <main className="flex-1 p-6 lg:p-8 overflow-auto">
        {/* Header */}
        <div className="mb-8 animate-fade-in">
          <h1 className="text-2xl font-bold text-slate-900">Admin Dashboard</h1>
          <p className="text-slate-500 mt-1 text-sm">
            Review and manage loan applications
          </p>
        </div>

        {dataError && <ErrorAlert message={dataError} />}

        {/* Stat Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
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
