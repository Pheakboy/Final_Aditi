"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "../../../context/AuthContext";
import UserLayout from "../../../components/UserLayout";
import { loanApi } from "../../../services/api";
import { Loan, LoanInstallment } from "../../../types";
import { formatCurrency, formatDate } from "../../../utils/format";

interface PendingInstallment extends LoanInstallment {
  loanId: string;
  loanAmount: number;
  loanPurpose?: string;
}

export default function LoanPaymentPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();

  const [pendingInstallments, setPendingInstallments] = useState<
    PendingInstallment[]
  >([]);
  const [loading, setLoading] = useState(false);
  const [payingId, setPayingId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [paidIds, setPaidIds] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
  }, [user, isLoading, router]);

  const loadPendingInstallments = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const loansRes = await loanApi.getMyLoans();
      const activeLoans: Loan[] = (loansRes.data.data || []).filter(
        (l: Loan) => l.status === "ACTIVE",
      );

      const allPending: PendingInstallment[] = [];
      await Promise.all(
        activeLoans.map(async (loan) => {
          try {
            const instRes = await loanApi.getInstallments(loan.id);
            const installments: LoanInstallment[] = instRes.data.data || [];
            installments
              .filter((i) => i.status === "PENDING" || i.status === "OVERDUE")
              .forEach((i) =>
                allPending.push({
                  ...i,
                  loanId: loan.id,
                  loanAmount: loan.loanAmount,
                  loanPurpose: loan.purpose,
                }),
              );
          } catch {
            // skip if a single loan fails
          }
        }),
      );

      // Sort: overdue first, then by due date asc
      allPending.sort((a, b) => {
        if (a.status === "OVERDUE" && b.status !== "OVERDUE") return -1;
        if (a.status !== "OVERDUE" && b.status === "OVERDUE") return 1;
        return new Date(a.dueDate).getTime() - new Date(b.dueDate).getTime();
      });

      setPendingInstallments(allPending);
    } catch {
      setError("Failed to load pending payments. Please refresh.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (user) loadPendingInstallments();
  }, [user, loadPendingInstallments]);

  const handlePay = async (installment: PendingInstallment) => {
    setPayingId(installment.id);
    setError("");
    try {
      await loanApi.payInstallment(installment.id);
      setPaidIds((prev) => new Set([...prev, installment.id]));
      // Re-fetch to reflect updated state
      loadPendingInstallments();
    } catch (err: unknown) {
      const axiosErr = err as {
        response?: { data?: { message?: string } };
      };
      setError(
        axiosErr?.response?.data?.message ||
          "Payment failed. Please check your balance and try again.",
      );
    } finally {
      setPayingId(null);
    }
  };

  const totalDue = pendingInstallments.reduce(
    (sum, i) => sum + Number(i.totalAmount),
    0,
  );
  const overdueCount = pendingInstallments.filter(
    (i) => i.status === "OVERDUE",
  ).length;

  if (isLoading)
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <div className="animate-spin rounded-full h-10 w-10 border-2 border-teal-500 border-t-transparent" />
      </div>
    );

  return (
    <UserLayout
      title="Make a Payment"
      subtitle="Pay your pending loan installments"
    >
      <div className="p-6 lg:p-8">
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl text-sm mb-5">
            {error}
          </div>
        )}

        {!loading && pendingInstallments.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
            <div className="bg-white rounded-2xl card-shadow p-5">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1">
                Pending Payments
              </p>
              <p className="text-3xl font-bold text-slate-900">
                {pendingInstallments.length}
              </p>
              <p className="text-xs text-slate-400 mt-0.5">installments due</p>
            </div>
            <div
              className={`rounded-2xl p-5 ${overdueCount > 0 ? "bg-red-50 border border-red-200" : "bg-white card-shadow"}`}
            >
              <p
                className={`text-xs font-semibold uppercase tracking-wide mb-1 ${overdueCount > 0 ? "text-red-500" : "text-slate-400"}`}
              >
                Overdue
              </p>
              <p
                className={`text-3xl font-bold ${overdueCount > 0 ? "text-red-600" : "text-slate-400"}`}
              >
                {overdueCount}
              </p>
              <p
                className={`text-xs mt-0.5 ${overdueCount > 0 ? "text-red-400" : "text-slate-400"}`}
              >
                installments overdue
              </p>
            </div>
            <div className="bg-white rounded-2xl card-shadow p-5">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1">
                Total Due
              </p>
              <p className="text-3xl font-bold text-slate-900">
                {formatCurrency(totalDue)}
              </p>
              <p className="text-xs text-slate-400 mt-0.5">across all loans</p>
            </div>
          </div>
        )}

        {loading ? (
          <div className="flex justify-center py-16">
            <div className="animate-spin rounded-full h-8 w-8 border-2 border-teal-500 border-t-transparent" />
          </div>
        ) : pendingInstallments.length === 0 ? (
          <div className="bg-white rounded-2xl card-shadow p-12 text-center">
            <div className="w-14 h-14 bg-emerald-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg
                className="w-7 h-7 text-emerald-500"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M5 13l4 4L19 7"
                />
              </svg>
            </div>
            <p className="text-slate-700 font-semibold mb-1">
              No pending payments
            </p>
            <p className="text-slate-400 text-sm mb-5">
              You have no outstanding installments at this time.
            </p>
            <Link
              href="/loan/installments"
              className="text-teal-600 hover:text-teal-700 text-sm font-medium"
            >
              View full installment schedule →
            </Link>
          </div>
        ) : (
          <div className="space-y-3">
            {pendingInstallments.map((inst) => {
              const isPaying = payingId === inst.id;
              const isOverdue =
                inst.status === "OVERDUE" ||
                (inst.status === "PENDING" &&
                  new Date(inst.dueDate) < new Date());
              const justPaid = paidIds.has(inst.id);

              return (
                <div
                  key={inst.id}
                  className={`bg-white rounded-2xl card-shadow p-5 border transition-all ${
                    justPaid
                      ? "border-emerald-200 opacity-60"
                      : isOverdue
                        ? "border-red-200"
                        : "border-transparent"
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                        <p className="font-semibold text-slate-900 text-sm">
                          Installment #{inst.installmentNumber}
                        </p>
                        <span
                          className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
                            isOverdue
                              ? "bg-red-100 text-red-700"
                              : "bg-amber-100 text-amber-700"
                          }`}
                        >
                          {isOverdue ? "OVERDUE" : "DUE"}
                        </span>
                        {inst.loanPurpose && (
                          <span className="text-xs text-slate-400 truncate max-w-40">
                            {inst.loanPurpose}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-500">
                        Loan: {formatCurrency(inst.loanAmount)} · Due:{" "}
                        <span
                          className={
                            isOverdue ? "text-red-600 font-medium" : ""
                          }
                        >
                          {formatDate(inst.dueDate)}
                        </span>
                      </p>
                      <div className="flex items-center gap-4 text-xs text-slate-400 mt-2">
                        <span>
                          Principal: {formatCurrency(inst.principalAmount)}
                        </span>
                        <span>
                          Interest: {formatCurrency(inst.interestAmount)}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <p className="text-lg font-bold text-slate-900">
                          {formatCurrency(inst.totalAmount)}
                        </p>
                        <p className="text-xs text-slate-400">total due</p>
                      </div>
                      <button
                        onClick={() => handlePay(inst)}
                        disabled={isPaying || payingId !== null || justPaid}
                        className="px-5 py-2.5 gradient-teal text-white text-sm font-semibold rounded-xl shadow-sm hover:opacity-90 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                      >
                        {isPaying ? (
                          <>
                            <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                            Paying…
                          </>
                        ) : justPaid ? (
                          "Paid ✓"
                        ) : (
                          "Pay Now"
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        <div className="mt-6 flex items-center gap-4">
          <Link
            href="/loan/installments"
            className="text-sm text-slate-500 hover:text-teal-600 transition-colors"
          >
            ← View full installment schedule
          </Link>
        </div>
      </div>
    </UserLayout>
  );
}
