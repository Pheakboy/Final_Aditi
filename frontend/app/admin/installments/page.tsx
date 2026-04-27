"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../../context/AuthContext";
import AdminLayout from "../../../components/admin/AdminLayout";
import { adminApi } from "../../../services/api";
import { PagedResponse } from "../../../types";
import LoadingScreen from "../../../components/ui/LoadingScreen";
import ErrorAlert from "../../../components/ui/ErrorAlert";
import Pagination from "../../../components/ui/Pagination";
import { formatCurrency, formatDate } from "../../../utils/format";
import { useToast } from "../../../components/ui/Toast";

type StatusFilter = "" | "PENDING" | "PAID" | "OVERDUE";

interface AdminInstallment {
  id: string;
  loanId: string;
  applicantUsername: string;
  applicantEmail: string;
  installmentNumber: number;
  dueDate: string;
  principalAmount: number;
  interestAmount: number;
  totalAmount: number;
  status: "PENDING" | "PAID" | "OVERDUE";
  paidAt?: string;
}

interface ConfirmAction {
  id: string;
  action: "PAID" | "OVERDUE" | "PENDING";
  installment: AdminInstallment;
}

interface SystemStats {
  total: number;
  pending: number;
  overdue: number;
  paid: number;
}

function getDaysDiff(dueDateStr: string): number {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const due = new Date(
    dueDateStr.includes("T") ? dueDateStr : dueDateStr + "T00:00:00Z",
  );
  return Math.round((due.getTime() - today.getTime()) / (1000 * 60 * 60 * 24));
}

function DueBadge({ dueDate, status }: { dueDate: string; status: string }) {
  if (status === "PAID") return null;
  const days = getDaysDiff(dueDate);
  if (days < 0)
    return (
      <span className="mt-1 inline-flex px-1.5 py-0.5 rounded text-xs font-semibold bg-red-100 text-red-700">
        {Math.abs(days)}d overdue
      </span>
    );
  if (days === 0)
    return (
      <span className="mt-1 inline-flex px-1.5 py-0.5 rounded text-xs font-semibold bg-orange-100 text-orange-700">
        Due today
      </span>
    );
  if (days <= 3)
    return (
      <span className="mt-1 inline-flex px-1.5 py-0.5 rounded text-xs font-semibold bg-amber-100 text-amber-700">
        {days}d left
      </span>
    );
  if (days <= 7)
    return (
      <span className="mt-1 inline-flex px-1.5 py-0.5 rounded text-xs font-medium bg-yellow-50 text-yellow-600 border border-yellow-100">
        {days}d left
      </span>
    );
  return null;
}

const STATUS_CONFIG: Record<string, { label: string; cls: string }> = {
  PENDING: {
    label: "Pending",
    cls: "bg-amber-100 text-amber-800 border border-amber-200",
  },
  PAID: {
    label: "Paid",
    cls: "bg-emerald-100 text-emerald-800 border border-emerald-200",
  },
  OVERDUE: {
    label: "Overdue",
    cls: "bg-red-100 text-red-700 border border-red-200",
  },
};

const FILTER_TABS: {
  value: StatusFilter;
  label: string;
  inactiveClass: string;
  activeClass: string;
}[] = [
  {
    value: "",
    label: "All",
    inactiveClass: "bg-white border-gray-200 text-gray-600 hover:bg-gray-50",
    activeClass: "bg-slate-900 text-white border-transparent",
  },
  {
    value: "PENDING",
    label: "Pending",
    inactiveClass: "bg-white border-amber-200 text-amber-700 hover:bg-amber-50",
    activeClass: "bg-amber-500 text-white border-transparent",
  },
  {
    value: "OVERDUE",
    label: "Overdue",
    inactiveClass: "bg-white border-red-200 text-red-600 hover:bg-red-50",
    activeClass: "bg-red-600 text-white border-transparent",
  },
  {
    value: "PAID",
    label: "Paid",
    inactiveClass:
      "bg-white border-emerald-200 text-emerald-700 hover:bg-emerald-50",
    activeClass: "bg-emerald-600 text-white border-transparent",
  },
];

export default function AdminInstallmentsPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const { showToast } = useToast();

  const [installments, setInstallments] = useState<AdminInstallment[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [dataError, setDataError] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("");
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [currentPage, setCurrentPage] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [totalElements, setTotalElements] = useState(0);
  const PAGE_SIZE = 20;

  const [stats, setStats] = useState<SystemStats>({
    total: 0,
    pending: 0,
    overdue: 0,
    paid: 0,
  });
  const [statsLoading, setStatsLoading] = useState(true);

  const [processingId, setProcessingId] = useState<string | null>(null);
  const [confirmAction, setConfirmAction] = useState<ConfirmAction | null>(
    null,
  );
  const [reminderLoading, setReminderLoading] = useState(false);
  const [daysAhead, setDaysAhead] = useState(3);

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
    if (!isLoading && user && !isAdmin) router.push("/dashboard");
  }, [user, isLoading, isAdmin, router]);

  const fetchStats = useCallback(async () => {
    setStatsLoading(true);
    try {
      const [allRes, pendingRes, overdueRes, paidRes] = await Promise.all([
        adminApi.getAllInstallments({ page: 0, size: 1 }),
        adminApi.getAllInstallments({ page: 0, size: 1, status: "PENDING" }),
        adminApi.getAllInstallments({ page: 0, size: 1, status: "OVERDUE" }),
        adminApi.getAllInstallments({ page: 0, size: 1, status: "PAID" }),
      ]);
      setStats({
        total: (allRes.data.data as PagedResponse<AdminInstallment>)
          .totalElements,
        pending: (pendingRes.data.data as PagedResponse<AdminInstallment>)
          .totalElements,
        overdue: (overdueRes.data.data as PagedResponse<AdminInstallment>)
          .totalElements,
        paid: (paidRes.data.data as PagedResponse<AdminInstallment>)
          .totalElements,
      });
    } catch {
      // stats are non-critical
    } finally {
      setStatsLoading(false);
    }
  }, []);

  const fetchInstallments = useCallback(
    async (page = 0) => {
      setDataLoading(true);
      setDataError("");
      try {
        const res = await adminApi.getAllInstallments({
          page,
          size: PAGE_SIZE,
          status: statusFilter || undefined,
          search: search || undefined,
        });
        const paged: PagedResponse<AdminInstallment> = res.data.data;
        setInstallments(paged.content || []);
        setCurrentPage(paged.page);
        setTotalPages(paged.totalPages);
        setTotalElements(paged.totalElements);
      } catch {
        setDataError("Failed to load installments. Please refresh.");
      } finally {
        setDataLoading(false);
      }
    },
    [statusFilter, search],
  );

  useEffect(() => {
    if (user && isAdmin) fetchStats();
  }, [user, isAdmin, fetchStats]);

  useEffect(() => {
    if (user && isAdmin) {
      setCurrentPage(0);
      fetchInstallments(0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user, isAdmin, statusFilter, search]);

  const handleAction = async () => {
    if (!confirmAction) return;
    const { id, action } = confirmAction;
    setProcessingId(id);
    setConfirmAction(null);
    try {
      if (action === "PAID") await adminApi.markInstallmentPaid(id);
      else if (action === "OVERDUE") await adminApi.markInstallmentOverdue(id);
      else await adminApi.markInstallmentPending(id);
      const label =
        action === "PAID"
          ? "Marked as paid"
          : action === "OVERDUE"
            ? "Marked as overdue"
            : "Reset to pending";
      showToast(label, action === "PAID" ? "success" : "info");
      await Promise.all([fetchInstallments(currentPage), fetchStats()]);
    } catch {
      showToast("Action failed. Please try again.", "error");
    } finally {
      setProcessingId(null);
    }
  };

  const handleTriggerReminders = async () => {
    setReminderLoading(true);
    try {
      const res = await adminApi.triggerPaymentReminders(daysAhead);
      const data = res.data.data as {
        reminders_sent: number;
        marked_overdue: number;
      };
      showToast(
        `Sent ${data.reminders_sent} reminder(s), marked ${data.marked_overdue} overdue`,
        "success",
      );
      await Promise.all([fetchInstallments(currentPage), fetchStats()]);
    } catch {
      showToast("Failed to trigger reminders", "error");
    } finally {
      setReminderLoading(false);
    }
  };

  const displayed = installments;

  if (isLoading) return <LoadingScreen color="border-indigo-500" />;

  return (
    <AdminLayout
      title="Installment Management"
      subtitle="Monitor and manage all loan installments across the platform"
      onRefresh={() => {
        fetchInstallments(currentPage);
        fetchStats();
      }}
    >
      <div className="p-6 lg:p-8 space-y-6">
        {dataError && <ErrorAlert message={dataError} />}

        {/* -- System-wide Stats ------------------------------------------- */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {(
            [
              {
                label: "Total Installments",
                value: stats.total,
                valueColor: "text-slate-900",
                borderColor: "border-slate-200",
                iconBg: "bg-slate-100",
                iconColor: "text-slate-600",
                icon: (
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
                      d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
                    />
                  </svg>
                ),
              },
              {
                label: "Pending Payment",
                value: stats.pending,
                valueColor: "text-amber-700",
                borderColor: "border-amber-200",
                iconBg: "bg-amber-50",
                iconColor: "text-amber-600",
                icon: (
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
                      d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
                    />
                  </svg>
                ),
              },
              {
                label: "Overdue",
                value: stats.overdue,
                valueColor: "text-red-700",
                borderColor: "border-red-200",
                iconBg: "bg-red-50",
                iconColor: "text-red-600",
                icon: (
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
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                    />
                  </svg>
                ),
              },
              {
                label: "Paid",
                value: stats.paid,
                valueColor: "text-emerald-700",
                borderColor: "border-emerald-200",
                iconBg: "bg-emerald-50",
                iconColor: "text-emerald-600",
                icon: (
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
                      d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                    />
                  </svg>
                ),
              },
            ] as const
          ).map(
            ({
              label,
              value,
              valueColor,
              borderColor,
              iconBg,
              iconColor,
              icon,
            }) => (
              <div
                key={label}
                className={`bg-white rounded-xl border ${borderColor} p-5 shadow-sm`}
              >
                <div className="flex items-center justify-between mb-3">
                  <p className="text-xs font-semibold uppercase tracking-wider text-gray-500 leading-tight">
                    {label}
                  </p>
                  <div
                    className={`w-8 h-8 rounded-lg ${iconBg} ${iconColor} flex items-center justify-center`}
                  >
                    {icon}
                  </div>
                </div>
                {statsLoading ? (
                  <div className="h-8 bg-gray-100 rounded animate-pulse w-16" />
                ) : (
                  <p className={`text-3xl font-bold ${valueColor}`}>
                    {value.toLocaleString()}
                  </p>
                )}
              </div>
            ),
          )}
        </div>

        {/* -- Payment Reminder Engine ------------------------------------- */}
        <div className="bg-slate-900 rounded-xl p-5 text-white shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="w-9 h-9 rounded-lg bg-indigo-600 flex items-center justify-center shrink-0 mt-0.5">
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
                    d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
                  />
                </svg>
              </div>
              <div>
                <h3 className="font-semibold text-white">
                  Payment Reminder Engine
                </h3>
                <p className="text-slate-400 text-sm mt-0.5">
                  Send email reminders to users with upcoming installments and
                  automatically flag overdue ones.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <div className="flex items-center gap-2">
                <span className="text-sm text-slate-400 whitespace-nowrap">
                  Notify within
                </span>
                <input
                  type="number"
                  min={1}
                  max={30}
                  value={daysAhead}
                  onChange={(e) =>
                    setDaysAhead(
                      Math.min(30, Math.max(1, Number(e.target.value))),
                    )
                  }
                  className="w-14 px-2 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm text-center focus:outline-none focus:ring-1 focus:ring-indigo-500"
                />
                <span className="text-sm text-slate-400">days</span>
              </div>
              <button
                onClick={handleTriggerReminders}
                disabled={reminderLoading}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-semibold transition-colors disabled:opacity-50 whitespace-nowrap flex items-center gap-2"
              >
                {reminderLoading ? (
                  <>
                    <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Sending�
                  </>
                ) : (
                  <>
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
                        d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
                      />
                    </svg>
                    Send Reminders
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* -- Filters + Search ------------------------------------------- */}
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-4">
          <div className="flex flex-col sm:flex-row sm:items-center gap-3">
            <div className="flex gap-2 flex-wrap">
              {FILTER_TABS.map(
                ({ value, label, inactiveClass, activeClass }) => (
                  <button
                    key={value}
                    onClick={() => {
                      setStatusFilter(value);
                      setCurrentPage(0);
                    }}
                    className={`px-3.5 py-1.5 rounded-lg text-sm font-medium transition-all border relative ${
                      statusFilter === value ? activeClass : inactiveClass
                    }`}
                  >
                    {label}
                    {value === "OVERDUE" && stats.overdue > 0 && (
                      <span
                        className={`ml-1.5 px-1.5 py-0 rounded-full text-xs font-bold ${
                          statusFilter === value
                            ? "bg-white/20 text-white"
                            : "bg-red-100 text-red-700"
                        }`}
                      >
                        {stats.overdue}
                      </span>
                    )}
                    {value === "PENDING" && stats.pending > 0 && (
                      <span
                        className={`ml-1.5 px-1.5 py-0 rounded-full text-xs font-bold ${
                          statusFilter === value
                            ? "bg-white/20 text-white"
                            : "bg-amber-100 text-amber-700"
                        }`}
                      >
                        {stats.pending}
                      </span>
                    )}
                  </button>
                ),
              )}
            </div>
            <div className="sm:ml-auto flex gap-2">
              <div className="relative">
                <svg
                  className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
                  />
                </svg>
                <input
                  type="text"
                  placeholder="Search by user or loan ID�"
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") setSearch(searchInput);
                  }}
                  className="pl-9 pr-3 py-1.5 border border-gray-200 rounded-lg text-sm text-gray-700 w-56 focus:outline-none focus:ring-2 focus:ring-indigo-300"
                />
              </div>
              <button
                onClick={() => setSearch(searchInput)}
                className="px-3 py-1.5 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 transition-colors"
              >
                Search
              </button>
              {(searchInput || search) && (
                <button
                  onClick={() => {
                    setSearchInput("");
                    setSearch("");
                  }}
                  className="px-2.5 py-1.5 border border-gray-200 rounded-lg text-sm text-gray-500 hover:text-gray-700 hover:bg-gray-50 transition-colors"
                >
                  Clear
                </button>
              )}
            </div>
          </div>
        </div>

        {/* -- Table ------------------------------------------------------ */}
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
          <div className="px-5 py-3.5 border-b border-gray-100 flex items-center justify-between">
            <span className="text-sm font-medium text-gray-700">
              {dataLoading
                ? "Loading�"
                : `${totalElements.toLocaleString()} installment${totalElements !== 1 ? "s" : ""}${statusFilter ? ` � ${statusFilter.toLowerCase()}` : ""}${search ? ` � matching "${search}"` : ""}`}
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50/80 border-b border-gray-100">
                <tr>
                  <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Applicant
                  </th>
                  <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    #
                  </th>
                  <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Due Date
                  </th>
                  <th className="text-right px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Amount
                  </th>
                  <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Paid On
                  </th>
                  <th className="px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider text-right">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {dataLoading ? (
                  Array.from({ length: 8 }).map((_, i) => (
                    <tr key={i} className="animate-pulse">
                      {Array.from({ length: 7 }).map((__, j) => (
                        <td key={j} className="px-5 py-4">
                          <div
                            className="h-3.5 bg-gray-100 rounded"
                            style={{ width: `${60 + ((j * 17) % 40)}%` }}
                          />
                        </td>
                      ))}
                    </tr>
                  ))
                ) : displayed.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-5 py-16 text-center">
                      <div className="flex flex-col items-center gap-3">
                        <svg
                          className="w-12 h-12 text-gray-200"
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
                        <p className="text-sm font-medium text-gray-500">
                          No installments found
                        </p>
                        <p className="text-xs text-gray-400">
                          {search
                            ? `No results for "${search}" � try a different search term`
                            : statusFilter
                              ? `No ${statusFilter.toLowerCase()} installments at the moment`
                              : "No installment records exist yet"}
                        </p>
                      </div>
                    </td>
                  </tr>
                ) : (
                  displayed.map((inst) => {
                    const isOverdue = inst.status === "OVERDUE";
                    const isPaid = inst.status === "PAID";
                    const isProcessing = processingId === inst.id;
                    return (
                      <tr
                        key={inst.id}
                        className={`transition-colors hover:bg-gray-50/60 ${
                          isOverdue ? "bg-red-50/40" : ""
                        }`}
                      >
                        {/* Applicant */}
                        <td className="px-5 py-3.5">
                          <p className="font-medium text-gray-900">
                            {inst.applicantUsername}
                          </p>
                          <p className="text-xs text-gray-400 mt-0.5">
                            {inst.applicantEmail}
                          </p>
                          <p className="text-xs text-indigo-400 font-mono mt-0.5">
                            Loan #{inst.loanId.slice(0, 8)}�
                          </p>
                        </td>
                        {/* Installment number */}
                        <td className="px-5 py-3.5">
                          <span className="inline-flex items-center justify-center w-7 h-7 rounded-full bg-slate-100 text-slate-700 text-xs font-bold">
                            {inst.installmentNumber}
                          </span>
                        </td>
                        {/* Due date */}
                        <td className="px-5 py-3.5">
                          <p className="text-gray-700 text-sm">
                            {formatDate(inst.dueDate)}
                          </p>
                          <DueBadge
                            dueDate={inst.dueDate}
                            status={inst.status}
                          />
                        </td>
                        {/* Amount */}
                        <td className="px-5 py-3.5 text-right">
                          <p className="font-semibold text-gray-900">
                            {formatCurrency(inst.totalAmount)}
                          </p>
                          <p className="text-xs text-gray-400 mt-0.5">
                            {formatCurrency(inst.principalAmount)} +{" "}
                            {formatCurrency(inst.interestAmount)}
                          </p>
                        </td>
                        {/* Status */}
                        <td className="px-5 py-3.5">
                          <span
                            className={`inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-semibold ${
                              STATUS_CONFIG[inst.status]?.cls ??
                              "bg-gray-100 text-gray-600"
                            }`}
                          >
                            {STATUS_CONFIG[inst.status]?.label ?? inst.status}
                          </span>
                        </td>
                        {/* Paid on */}
                        <td className="px-5 py-3.5">
                          {inst.paidAt ? (
                            <p className="text-sm text-emerald-700 font-medium">
                              {formatDate(inst.paidAt)}
                            </p>
                          ) : (
                            <span className="text-gray-300 text-sm">�</span>
                          )}
                        </td>
                        {/* Actions */}
                        <td className="px-5 py-3.5">
                          <div className="flex items-center justify-end gap-2">
                            {isProcessing ? (
                              <span className="w-5 h-5 border-2 border-indigo-300 border-t-indigo-600 rounded-full animate-spin" />
                            ) : (
                              <>
                                {!isPaid && (
                                  <button
                                    onClick={() =>
                                      setConfirmAction({
                                        id: inst.id,
                                        action: "PAID",
                                        installment: inst,
                                      })
                                    }
                                    className="px-2.5 py-1.5 text-xs font-medium rounded-lg bg-emerald-50 text-emerald-700 border border-emerald-200 hover:bg-emerald-100 transition-colors"
                                  >
                                    Mark Paid
                                  </button>
                                )}
                                {inst.status === "PENDING" && (
                                  <button
                                    onClick={() =>
                                      setConfirmAction({
                                        id: inst.id,
                                        action: "OVERDUE",
                                        installment: inst,
                                      })
                                    }
                                    className="px-2.5 py-1.5 text-xs font-medium rounded-lg bg-red-50 text-red-600 border border-red-100 hover:bg-red-100 transition-colors"
                                  >
                                    Mark Overdue
                                  </button>
                                )}
                                {!isPaid && inst.status !== "PENDING" && (
                                  <button
                                    onClick={() =>
                                      setConfirmAction({
                                        id: inst.id,
                                        action: "PENDING",
                                        installment: inst,
                                      })
                                    }
                                    className="px-2.5 py-1.5 text-xs font-medium rounded-lg bg-gray-50 text-gray-600 border border-gray-200 hover:bg-gray-100 transition-colors"
                                  >
                                    Reset
                                  </button>
                                )}
                                {isPaid && (
                                  <button
                                    onClick={() =>
                                      setConfirmAction({
                                        id: inst.id,
                                        action: "PENDING",
                                        installment: inst,
                                      })
                                    }
                                    className="px-2.5 py-1.5 text-xs font-medium rounded-lg bg-gray-50 text-gray-500 border border-gray-200 hover:bg-gray-100 transition-colors"
                                  >
                                    Revert
                                  </button>
                                )}
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {totalPages > 1 && (
          <Pagination
            currentPage={currentPage}
            totalPages={totalPages}
            totalElements={totalElements}
            onPageChange={(p) => {
              setCurrentPage(p);
              fetchInstallments(p);
            }}
          />
        )}
      </div>

      {/* -- Confirm Action Modal ---------------------------------------- */}
      {confirmAction && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-2xl max-w-md w-full p-6">
            <div
              className={`w-10 h-10 rounded-full flex items-center justify-center mb-4 ${
                confirmAction.action === "PAID"
                  ? "bg-emerald-100"
                  : confirmAction.action === "OVERDUE"
                    ? "bg-red-100"
                    : "bg-gray-100"
              }`}
            >
              {confirmAction.action === "PAID" ? (
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
              ) : confirmAction.action === "OVERDUE" ? (
                <svg
                  className="w-5 h-5 text-red-600"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                  />
                </svg>
              ) : (
                <svg
                  className="w-5 h-5 text-gray-600"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                  />
                </svg>
              )}
            </div>
            <h2 className="text-base font-bold text-gray-900 mb-1">
              {confirmAction.action === "PAID"
                ? "Mark Installment as Paid"
                : confirmAction.action === "OVERDUE"
                  ? "Mark Installment as Overdue"
                  : "Reset Installment to Pending"}
            </h2>
            <div className="bg-gray-50 rounded-xl px-4 py-3 my-3 space-y-1.5 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-500">User</span>
                <span className="font-medium text-gray-900">
                  {confirmAction.installment.applicantUsername}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Installment</span>
                <span className="font-medium text-gray-900">
                  #{confirmAction.installment.installmentNumber}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Due Date</span>
                <span className="text-gray-900">
                  {formatDate(confirmAction.installment.dueDate)}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Amount</span>
                <span className="font-semibold text-gray-900">
                  {formatCurrency(confirmAction.installment.totalAmount)}
                </span>
              </div>
            </div>
            <p className="text-xs text-gray-500 mb-4">
              {confirmAction.action === "PAID"
                ? "This will record the installment as paid and update the loan balance."
                : confirmAction.action === "OVERDUE"
                  ? "This will flag the installment as overdue. The user may receive a notification."
                  : "This will revert the installment status back to pending."}
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setConfirmAction(null)}
                className="flex-1 py-2.5 border border-gray-200 rounded-xl text-sm font-medium text-gray-600 hover:bg-gray-50 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleAction}
                className={`flex-1 py-2.5 rounded-xl text-sm font-semibold text-white transition-colors ${
                  confirmAction.action === "PAID"
                    ? "bg-emerald-600 hover:bg-emerald-700"
                    : confirmAction.action === "OVERDUE"
                      ? "bg-red-600 hover:bg-red-700"
                      : "bg-slate-700 hover:bg-slate-800"
                }`}
              >
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}
    </AdminLayout>
  );
}
