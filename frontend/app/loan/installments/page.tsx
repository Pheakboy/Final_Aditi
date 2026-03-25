"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "../../../context/AuthContext";
import UserLayout from "../../../components/UserLayout";
import { loanApi } from "../../../services/api";
import { Loan, LoanInstallment } from "../../../types";
import { formatCurrency, formatDate } from "../../../utils/format";

const statusConfig = {
  PENDING: {
    badge: "bg-amber-100 text-amber-700 border border-amber-200",
    dot: "bg-amber-400",
  },
  PAID: {
    badge: "bg-emerald-100 text-emerald-700 border border-emerald-200",
    dot: "bg-emerald-400",
  },
  OVERDUE: {
    badge: "bg-red-100 text-red-700 border border-red-200",
    dot: "bg-red-400",
  },
};

const loanStatusConfig: Record<string, { badge: string }> = {
  PENDING: { badge: "bg-amber-100 text-amber-700" },
  APPROVED: { badge: "bg-emerald-100 text-emerald-700" },
  REJECTED: { badge: "bg-red-100 text-red-700" },
  ACTIVE: { badge: "bg-blue-100 text-blue-700" },
  COMPLETED: { badge: "bg-slate-100 text-slate-600" },
};

export default function InstallmentsPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();

  const [loans, setLoans] = useState<Loan[]>([]);
  const [selectedLoan, setSelectedLoan] = useState<Loan | null>(null);
  const [installments, setInstallments] = useState<LoanInstallment[]>([]);
  const [loansLoading, setLoansLoading] = useState(false);
  const [installmentsLoading, setInstallmentsLoading] = useState(false);
  const [payingId, setPayingId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
  }, [user, isLoading, router]);

  useEffect(() => {
    if (user) {
      setLoansLoading(true);
      loanApi
        .getMyLoans()
        .then((res) => {
          const all: Loan[] = res.data.data || [];
          // Show only loans that have installments (ACTIVE or COMPLETED)
          const relevant = all.filter(
            (l) => l.status === "ACTIVE" || l.status === "COMPLETED",
          );
          setLoans(relevant);
          if (relevant.length > 0) setSelectedLoan(relevant[0]);
        })
        .catch(() => setError("Failed to load loans. Please refresh."))
        .finally(() => setLoansLoading(false));
    }
  }, [user]);

  const fetchInstallments = useCallback(async (loanId: string) => {
    setInstallmentsLoading(true);
    setInstallments([]);
    setError("");
    try {
      const res = await loanApi.getInstallments(loanId);
      setInstallments(res.data.data || []);
    } catch {
      setError("Failed to load installments. Please try again.");
    } finally {
      setInstallmentsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (selectedLoan) fetchInstallments(selectedLoan.id);
  }, [selectedLoan, fetchInstallments]);

  const handlePayInstallment = async (installment: LoanInstallment) => {
    setPayingId(installment.id);
    setError("");
    setSuccessMsg("");
    try {
      await loanApi.payInstallment(installment.id);
      setSuccessMsg(
        `Installment #${installment.installmentNumber} paid successfully!`,
      );
      // Refresh installments list
      if (selectedLoan) fetchInstallments(selectedLoan.id);
    } catch (err: unknown) {
      const axiosErr = err as {
        response?: { data?: { message?: string } };
      };
      setError(
        axiosErr?.response?.data?.message ||
          "Payment failed. Check your balance and try again.",
      );
    } finally {
      setPayingId(null);
    }
  };

  const paidCount = installments.filter((i) => i.status === "PAID").length;
  const pendingCount = installments.filter(
    (i) => i.status === "PENDING",
  ).length;
  const overdueCount = installments.filter(
    (i) => i.status === "OVERDUE",
  ).length;
  const totalPaid = installments
    .filter((i) => i.status === "PAID")
    .reduce((sum, i) => sum + Number(i.totalAmount), 0);
  const totalRemaining = installments
    .filter((i) => i.status !== "PAID")
    .reduce((sum, i) => sum + Number(i.totalAmount), 0);

  if (isLoading)
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <div className="animate-spin rounded-full h-10 w-10 border-2 border-teal-500 border-t-transparent" />
      </div>
    );

  return (
    <UserLayout
      title="Loan Installments"
      subtitle="View and pay your monthly installment schedule"
    >
      <div className="p-6 lg:p-8">
        {/* Messages */}
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl text-sm mb-5">
            {error}
          </div>
        )}
        {successMsg && (
          <div className="bg-emerald-50 border border-emerald-200 text-emerald-700 px-4 py-3 rounded-xl text-sm mb-5 flex items-center gap-2">
            <svg
              className="w-4 h-4 shrink-0"
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
            {successMsg}
          </div>
        )}

        {loansLoading ? (
          <div className="flex justify-center py-16">
            <div className="animate-spin rounded-full h-8 w-8 border-2 border-teal-500 border-t-transparent" />
          </div>
        ) : loans.length === 0 ? (
          <div className="bg-white rounded-2xl card-shadow p-12 text-center">
            <div className="w-14 h-14 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg
                className="w-7 h-7 text-slate-400"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1.5}
                  d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
                />
              </svg>
            </div>
            <p className="text-slate-600 font-medium mb-1">
              No active loan installments
            </p>
            <p className="text-slate-400 text-sm mb-5">
              Installments appear once your loan is approved and activated.
            </p>
            <Link
              href="/loan/status"
              className="text-teal-600 hover:text-teal-700 text-sm font-medium"
            >
              View my loan applications →
            </Link>
          </div>
        ) : (
          <div className="flex flex-col lg:flex-row gap-6">
            {/* Loan selector */}
            <div className="lg:w-72 shrink-0">
              <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
                Select Loan
              </h3>
              <div className="space-y-2">
                {loans.map((loan) => {
                  const cfg = loanStatusConfig[loan.status] ?? {
                    badge: "bg-slate-100 text-slate-600",
                  };
                  return (
                    <button
                      key={loan.id}
                      onClick={() => {
                        setSelectedLoan(loan);
                        setSuccessMsg("");
                        setError("");
                      }}
                      className={`w-full text-left p-4 rounded-2xl border transition-all ${
                        selectedLoan?.id === loan.id
                          ? "border-teal-400 bg-teal-50 ring-1 ring-teal-300"
                          : "border-slate-200 bg-white hover:border-teal-200 hover:bg-teal-50/30"
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <p className="font-bold text-slate-900 text-sm">
                          {formatCurrency(loan.loanAmount)}
                        </p>
                        <span
                          className={`text-xs font-semibold px-2 py-0.5 rounded-full ${cfg.badge}`}
                        >
                          {loan.status}
                        </span>
                      </div>
                      {loan.purpose && (
                        <p className="text-xs text-slate-500 truncate">
                          {loan.purpose}
                        </p>
                      )}
                      <div className="flex items-center gap-2 text-xs text-slate-400 mt-1">
                        {loan.termMonths && (
                          <span>{loan.termMonths} months</span>
                        )}
                        {loan.interestRate && (
                          <span>
                            · {(Number(loan.interestRate) * 100).toFixed(0)}%
                            p.a.
                          </span>
                        )}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Installment schedule */}
            <div className="flex-1 min-w-0">
              {selectedLoan && (
                <>
                  {/* Summary cards */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
                    <div className="bg-white rounded-2xl card-shadow p-4">
                      <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1">
                        Paid
                      </p>
                      <p className="text-2xl font-bold text-emerald-600">
                        {paidCount}
                      </p>
                      <p className="text-xs text-slate-400 mt-0.5">
                        installments
                      </p>
                    </div>
                    <div className="bg-white rounded-2xl card-shadow p-4">
                      <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1">
                        Remaining
                      </p>
                      <p className="text-2xl font-bold text-amber-600">
                        {pendingCount}
                      </p>
                      <p className="text-xs text-slate-400 mt-0.5">
                        installments
                      </p>
                    </div>
                    {overdueCount > 0 && (
                      <div className="bg-red-50 rounded-2xl border border-red-200 p-4">
                        <p className="text-xs font-semibold text-red-500 uppercase tracking-wide mb-1">
                          Overdue
                        </p>
                        <p className="text-2xl font-bold text-red-600">
                          {overdueCount}
                        </p>
                        <p className="text-xs text-red-400 mt-0.5">
                          installments
                        </p>
                      </div>
                    )}
                    <div className="bg-white rounded-2xl card-shadow p-4">
                      <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1">
                        Balance Due
                      </p>
                      <p className="text-xl font-bold text-slate-900">
                        {formatCurrency(totalRemaining)}
                      </p>
                      <p className="text-xs text-slate-400 mt-0.5">
                        {formatCurrency(totalPaid)} paid
                      </p>
                    </div>
                  </div>

                  {/* Installment table */}
                  {installmentsLoading ? (
                    <div className="flex justify-center py-12">
                      <div className="animate-spin rounded-full h-8 w-8 border-2 border-teal-500 border-t-transparent" />
                    </div>
                  ) : installments.length === 0 ? (
                    <div className="bg-white rounded-2xl card-shadow p-8 text-center text-slate-400 text-sm">
                      No installment schedule found for this loan.
                    </div>
                  ) : (
                    <div className="bg-white rounded-2xl card-shadow overflow-hidden">
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="border-b border-slate-100 bg-slate-50">
                              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">
                                #
                              </th>
                              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">
                                Due Date
                              </th>
                              <th className="px-5 py-3 text-right text-xs font-semibold text-slate-500 uppercase tracking-wide">
                                Principal
                              </th>
                              <th className="px-5 py-3 text-right text-xs font-semibold text-slate-500 uppercase tracking-wide">
                                Interest
                              </th>
                              <th className="px-5 py-3 text-right text-xs font-semibold text-slate-500 uppercase tracking-wide">
                                Total
                              </th>
                              <th className="px-5 py-3 text-center text-xs font-semibold text-slate-500 uppercase tracking-wide">
                                Status
                              </th>
                              <th className="px-5 py-3 text-center text-xs font-semibold text-slate-500 uppercase tracking-wide">
                                Action
                              </th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100">
                            {installments.map((inst) => {
                              const cfg =
                                statusConfig[inst.status] ??
                                statusConfig.PENDING;
                              const isPaying = payingId === inst.id;
                              const isOverdue =
                                inst.status === "OVERDUE" ||
                                (inst.status === "PENDING" &&
                                  new Date(inst.dueDate) < new Date());
                              return (
                                <tr
                                  key={inst.id}
                                  className={`transition-colors ${
                                    inst.status === "PAID"
                                      ? "bg-emerald-50/30"
                                      : isOverdue
                                        ? "bg-red-50/30"
                                        : "hover:bg-slate-50"
                                  }`}
                                >
                                  <td className="px-5 py-4 text-slate-500 font-medium">
                                    {inst.installmentNumber}
                                  </td>
                                  <td className="px-5 py-4 text-slate-700">
                                    {formatDate(inst.dueDate)}
                                    {inst.paidAt && (
                                      <p className="text-xs text-slate-400 mt-0.5">
                                        Paid {formatDate(inst.paidAt)}
                                      </p>
                                    )}
                                  </td>
                                  <td className="px-5 py-4 text-right text-slate-700 tabular-nums">
                                    {formatCurrency(inst.principalAmount)}
                                  </td>
                                  <td className="px-5 py-4 text-right text-slate-500 tabular-nums">
                                    {formatCurrency(inst.interestAmount)}
                                  </td>
                                  <td className="px-5 py-4 text-right font-semibold text-slate-900 tabular-nums">
                                    {formatCurrency(inst.totalAmount)}
                                  </td>
                                  <td className="px-5 py-4 text-center">
                                    <span
                                      className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full ${cfg.badge}`}
                                    >
                                      <span
                                        className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`}
                                      />
                                      {inst.status}
                                    </span>
                                  </td>
                                  <td className="px-5 py-4 text-center">
                                    {inst.status !== "PAID" ? (
                                      <button
                                        onClick={() =>
                                          handlePayInstallment(inst)
                                        }
                                        disabled={isPaying || payingId !== null}
                                        className="inline-flex items-center gap-1.5 px-3.5 py-1.5 gradient-teal text-white text-xs font-semibold rounded-lg shadow-sm hover:opacity-90 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                                      >
                                        {isPaying ? (
                                          <>
                                            <span className="w-3 h-3 border border-white border-t-transparent rounded-full animate-spin" />
                                            Paying…
                                          </>
                                        ) : (
                                          "Pay Now"
                                        )}
                                      </button>
                                    ) : (
                                      <span className="text-xs text-slate-400">
                                        —
                                      </span>
                                    )}
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </UserLayout>
  );
}
