"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../../context/AuthContext";
import AdminLayout from "../../../components/admin/AdminLayout";
import { adminApi } from "../../../services/api";

interface AuditLog {
  id: number;
  action: string;
  performedBy: string;
  targetType?: string;
  details?: string;
  ipAddress?: string;
  timestamp: string;
}

const actionColor = (action: string) => {
  if (
    action.includes("APPROVED") ||
    action.includes("CREATED") ||
    action.includes("REACTIVATED")
  )
    return "bg-emerald-50 text-emerald-700";
  if (
    action.includes("REJECTED") ||
    action.includes("DEACTIVATED") ||
    action.includes("DELETED")
  )
    return "bg-red-50 text-red-700";
  if (
    action.includes("UPDATED") ||
    action.includes("SENT") ||
    action.includes("EXPORTED")
  )
    return "bg-sky-50 text-sky-700";
  return "bg-slate-100 text-slate-600";
};

export default function AuditLogsPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [actionFilter, setActionFilter] = useState("");

  const today = new Date();
  const oneMonthAgo = new Date(today);
  oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
  const toDateStr = today.toISOString().slice(0, 10);
  const fromDateStr = oneMonthAgo.toISOString().slice(0, 10);

  const [dateFrom, setDateFrom] = useState(fromDateStr);
  const [dateTo, setDateTo] = useState(toDateStr);
  const [page, setPage] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [totalElements, setTotalElements] = useState(0);
  const PAGE_SIZE = 15;

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
    if (!isLoading && user && !isAdmin) router.push("/dashboard");
  }, [user, isLoading, isAdmin, router]);

  const fetchLogs = useCallback(
    async (p = 0) => {
      setDataLoading(true);
      try {
        const res = await adminApi.getAuditLogs({
          page: p,
          size: PAGE_SIZE,
          action: actionFilter || undefined,
          from: dateFrom || undefined,
          to: dateTo || undefined,
        });
        const data = res.data.data;
        if (data?.content) {
          setLogs(data.content);
          setPage(data.page ?? p);
          setTotalPages(data.totalPages ?? 1);
          setTotalElements(data.totalElements ?? 0);
        } else {
          setLogs(Array.isArray(data) ? data : []);
          setTotalPages(1);
        }
      } catch {
        /* silently handle */
      } finally {
        setDataLoading(false);
      }
    },
    [actionFilter, dateFrom, dateTo],
  );

  useEffect(() => {
    if (user && isAdmin) {
      setPage(0);
      fetchLogs(0);
    }
  }, [user, isAdmin, fetchLogs]);

  const formatTs = (ts: string) => new Date(ts).toLocaleString();

  if (isLoading)
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <div className="animate-spin rounded-full h-10 w-10 border-2 border-indigo-500 border-t-transparent" />
      </div>
    );

  return (
    <AdminLayout
      title="Audit Logs"
      subtitle={
        dataLoading
          ? "Loading…"
          : `${totalElements} events recorded · Read-only`
      }
    >
      <div className="p-6 lg:p-8">
        {/* Filters */}
        <div className="bg-white rounded-2xl border border-slate-200 p-4 mb-6 shadow-sm">
          <div className="flex flex-wrap gap-4 items-center">
            <div className="flex items-center gap-2">
              <label className="text-xs text-slate-500 font-medium">
                Action contains:
              </label>
              <input
                type="text"
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
                className="px-3 py-1.5 text-sm bg-white border border-slate-200 rounded-lg text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                placeholder="e.g. LOAN, USER..."
              />
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs text-slate-500 font-medium">
                From:
              </label>
              <input
                type="date"
                value={dateFrom}
                onChange={(e) => setDateFrom(e.target.value)}
                className="px-3 py-1.5 text-sm bg-white border border-slate-200 rounded-lg text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs text-slate-500 font-medium">To:</label>
              <input
                type="date"
                value={dateTo}
                onChange={(e) => setDateTo(e.target.value)}
                className="px-3 py-1.5 text-sm bg-white border border-slate-200 rounded-lg text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>
            {(actionFilter || dateFrom || dateTo) && (
              <button
                onClick={() => {
                  setActionFilter("");
                  setDateFrom("");
                  setDateTo("");
                }}
                className="px-3 py-1.5 text-xs font-medium text-red-600 bg-red-50 border border-red-200 rounded-lg hover:bg-red-100 transition-colors"
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {/* Table */}
        <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 border-b border-slate-100">
              <tr>
                {[
                  "Action",
                  "Performed By",
                  "Target",
                  "IP Address",
                  "Timestamp",
                ].map((h) => (
                  <th
                    key={h}
                    className="text-left px-5 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wide"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50">
              {dataLoading ? (
                Array.from({ length: 10 }).map((_, i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="px-5 py-3">
                      <div className="h-5 bg-slate-200 rounded-full w-28"></div>
                    </td>
                    <td className="px-5 py-3">
                      <div className="h-4 bg-slate-200 rounded w-32"></div>
                    </td>
                    <td className="px-5 py-3">
                      <div className="h-3 bg-slate-200 rounded w-20"></div>
                    </td>
                    <td className="px-5 py-3">
                      <div className="h-3 bg-slate-200 rounded w-24 font-mono"></div>
                    </td>
                    <td className="px-5 py-3">
                      <div className="h-3 bg-slate-200 rounded w-36"></div>
                    </td>
                  </tr>
                ))
              ) : logs.length === 0 ? (
                <tr>
                  <td
                    colSpan={5}
                    className="text-center py-12 text-slate-400 text-sm"
                  >
                    No audit logs found
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr
                    key={log.id}
                    className="hover:bg-slate-50 transition-colors"
                  >
                    <td className="px-5 py-3">
                      <span
                        className={`text-xs font-semibold px-2.5 py-1 rounded-full ${actionColor(log.action)}`}
                      >
                        {log.action}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-slate-800 text-sm font-medium">
                      {log.performedBy}
                    </td>
                    <td className="px-5 py-3 text-slate-500 text-xs">
                      {log.targetType || "—"}
                    </td>
                    <td className="px-5 py-3 text-slate-500 text-xs font-mono">
                      {log.ipAddress || "—"}
                    </td>
                    <td className="px-5 py-3 text-slate-400 text-xs whitespace-nowrap">
                      {formatTs(log.timestamp)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-6">
            <p className="text-sm text-slate-500">
              Page {page + 1} of {totalPages} · {totalElements} total
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => fetchLogs(page - 1)}
                disabled={page === 0}
                className="px-3 py-1.5 text-sm border border-slate-200 rounded-lg bg-white text-slate-600 hover:text-slate-900 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                ‹ Prev
              </button>
              <button
                onClick={() => fetchLogs(page + 1)}
                disabled={page >= totalPages - 1}
                className="px-3 py-1.5 text-sm border border-slate-200 rounded-lg bg-white text-slate-600 hover:text-slate-900 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                Next ›
              </button>
            </div>
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
