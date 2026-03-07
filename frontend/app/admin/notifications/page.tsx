"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../../context/AuthContext";
import Sidebar from "../../../components/Sidebar";
import { adminApi } from "../../../services/api";
import axios from "axios";

interface AdminNotif {
  id: string;
  title: string;
  message: string;
  type: string;
  isRead: boolean;
  createdAt: string;
  recipientUsername: string;
  recipientEmail: string;
}

const typeColor: Record<string, string> = {
  LOAN_APPROVED: "bg-emerald-100 text-emerald-700",
  LOAN_REJECTED: "bg-red-100 text-red-700",
  BROADCAST:     "bg-sky-100 text-sky-700",
  GENERAL:       "bg-slate-100 text-slate-600",
};

function formatRelative(date: string) {
  const diff = Date.now() - new Date(date).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "Just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function AdminNotificationsPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();

  const [broadcastForm, setBroadcastForm] = useState({ title: "", message: "" });
  const [userForm, setUserForm] = useState({ userId: "", title: "", message: "" });
  const [broadcastLoading, setBroadcastLoading] = useState(false);
  const [userLoading, setUserLoading] = useState(false);
  const [broadcastSuccess, setBroadcastSuccess] = useState("");
  const [broadcastError, setBroadcastError] = useState("");
  const [userSuccess, setUserSuccess] = useState("");
  const [userError, setUserError] = useState("");

  const [notifs, setNotifs] = useState<AdminNotif[]>([]);
  const [listLoading, setListLoading] = useState(false);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [totalElements, setTotalElements] = useState(0);
  const [currentPage, setCurrentPage] = useState(0);
  const [totalPages, setTotalPages] = useState(0);

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
    if (!isLoading && user && !isAdmin) router.push("/dashboard");
  }, [user, isLoading, isAdmin, router]);

  const fetchNotifs = useCallback(async (page = 0) => {
    setListLoading(true);
    try {
      const res = await adminApi.getAdminNotifications({ page, size: 15 });
      const paged = res.data.data;
      setNotifs(paged.content || []);
      setTotalElements(paged.totalElements);
      setCurrentPage(paged.page);
      setTotalPages(paged.totalPages);
    } catch { /* ignore */ } finally { setListLoading(false); }
  }, []);

  useEffect(() => { if (user && isAdmin) fetchNotifs(0); }, [user, isAdmin, fetchNotifs]);

  const handleBroadcast = async (e: React.FormEvent) => {
    e.preventDefault();
    setBroadcastLoading(true); setBroadcastError(""); setBroadcastSuccess("");
    try {
      await adminApi.broadcastNotification({ title: broadcastForm.title, message: broadcastForm.message });
      setBroadcastSuccess("Broadcast sent to all active users successfully.");
      setBroadcastForm({ title: "", message: "" });
      await fetchNotifs(0);
    } catch (err: unknown) {
      setBroadcastError(axios.isAxiosError(err) ? (err.response?.data?.message ?? "Failed to send") : "Failed to send");
    } finally { setBroadcastLoading(false); }
  };

  const handleSendToUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!userForm.userId) { setUserError("Please enter a user ID"); return; }
    setUserLoading(true); setUserError(""); setUserSuccess("");
    try {
      await adminApi.sendNotificationToUser(userForm.userId, { title: userForm.title, message: userForm.message });
      setUserSuccess(`Notification sent to user #${userForm.userId} successfully.`);
      setUserForm({ userId: "", title: "", message: "" });
      await fetchNotifs(0);
    } catch (err: unknown) {
      setUserError(axios.isAxiosError(err) ? (err.response?.data?.message ?? "Failed to send") : "Failed to send");
    } finally { setUserLoading(false); }
  };

  const handleDelete = async (id: string) => {
    setDeleteLoading(true);
    try {
      await adminApi.deleteNotification(id);
      setDeleteId(null);
      await fetchNotifs(currentPage);
    } catch { /* ignore */ } finally { setDeleteLoading(false); }
  };

  if (isLoading) return (
    <div className="flex min-h-screen items-center justify-center bg-slate-900">
      <div className="animate-spin rounded-full h-10 w-10 border-2 border-indigo-500 border-t-transparent" />
    </div>
  );

  return (
    <div className="flex min-h-screen bg-slate-900">
      <Sidebar />
      <main className="flex-1 p-6 lg:p-8 overflow-auto admin-scroll">
        <div className="mb-8 animate-fade-in">
          <h1 className="text-2xl font-bold text-white">Notifications</h1>
          <p className="text-slate-400 mt-1 text-sm">Send messages to users and manage all notifications</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-10">
          {/* Broadcast */}
          <div className="bg-slate-800 rounded-2xl border border-slate-700 p-6">
            <div className="flex items-center gap-3 mb-5">
              <div className="w-9 h-9 rounded-xl gradient-indigo flex items-center justify-center">
                <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z" />
                </svg>
              </div>
              <div>
                <h2 className="text-sm font-semibold text-white">Broadcast to All Users</h2>
                <p className="text-xs text-slate-500">Sends to every active user</p>
              </div>
            </div>
            {broadcastSuccess && <div className="bg-emerald-900/30 border border-emerald-700/50 text-emerald-300 px-3 py-2 rounded-xl text-sm mb-4">{broadcastSuccess}</div>}
            {broadcastError  && <div className="bg-red-900/30 border border-red-700/50 text-red-300 px-3 py-2 rounded-xl text-sm mb-4">{broadcastError}</div>}
            <form onSubmit={handleBroadcast} className="space-y-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1.5">Title <span className="text-red-400">*</span></label>
                <input type="text" value={broadcastForm.title} onChange={e => setBroadcastForm({ ...broadcastForm, title: e.target.value })} required
                  className="w-full px-4 py-2.5 bg-slate-900/50 border border-slate-600 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="e.g. System Maintenance Notice" />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1.5">Message <span className="text-red-400">*</span></label>
                <textarea value={broadcastForm.message} onChange={e => setBroadcastForm({ ...broadcastForm, message: e.target.value })} rows={4} required
                  className="w-full px-4 py-2.5 bg-slate-900/50 border border-slate-600 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 resize-none"
                  placeholder="Enter your message..." />
              </div>
              <button type="submit" disabled={broadcastLoading}
                className="w-full py-2.5 gradient-indigo text-white text-sm font-semibold rounded-xl hover:opacity-90 disabled:opacity-50 transition-all">
                {broadcastLoading ? "Sending..." : "Send Broadcast"}
              </button>
            </form>
          </div>

          {/* Send to User */}
          <div className="bg-slate-800 rounded-2xl border border-slate-700 p-6">
            <div className="flex items-center gap-3 mb-5">
              <div className="w-9 h-9 rounded-xl bg-sky-600/30 border border-sky-700/50 flex items-center justify-center">
                <svg className="w-5 h-5 text-sky-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                </svg>
              </div>
              <div>
                <h2 className="text-sm font-semibold text-white">Send to Specific User</h2>
                <p className="text-xs text-slate-500">Targeted notification by User ID</p>
              </div>
            </div>
            {userSuccess && <div className="bg-emerald-900/30 border border-emerald-700/50 text-emerald-300 px-3 py-2 rounded-xl text-sm mb-4">{userSuccess}</div>}
            {userError   && <div className="bg-red-900/30 border border-red-700/50 text-red-300 px-3 py-2 rounded-xl text-sm mb-4">{userError}</div>}
            <form onSubmit={handleSendToUser} className="space-y-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1.5">User ID <span className="text-red-400">*</span></label>
                <input type="text" value={userForm.userId} onChange={e => setUserForm({ ...userForm, userId: e.target.value })} required
                  className="w-full px-4 py-2.5 bg-slate-900/50 border border-slate-600 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="Enter numeric user ID" />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1.5">Title <span className="text-red-400">*</span></label>
                <input type="text" value={userForm.title} onChange={e => setUserForm({ ...userForm, title: e.target.value })} required
                  className="w-full px-4 py-2.5 bg-slate-900/50 border border-slate-600 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="Notification title" />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1.5">Message <span className="text-red-400">*</span></label>
                <textarea value={userForm.message} onChange={e => setUserForm({ ...userForm, message: e.target.value })} rows={4} required
                  className="w-full px-4 py-2.5 bg-slate-900/50 border border-slate-600 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 resize-none"
                  placeholder="Enter your message..." />
              </div>
              <button type="submit" disabled={userLoading}
                className="w-full py-2.5 bg-sky-600 text-white text-sm font-semibold rounded-xl hover:bg-sky-700 disabled:opacity-50 transition-colors">
                {userLoading ? "Sending..." : "Send Notification"}
              </button>
            </form>
          </div>
        </div>

        {/* Notification List */}
        <div className="bg-slate-800 rounded-2xl border border-slate-700 overflow-hidden">
          <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700">
            <div>
              <h2 className="text-sm font-semibold text-white">All Notifications</h2>
              <p className="text-xs text-slate-500 mt-0.5">{totalElements} total notifications</p>
            </div>
            <button onClick={() => fetchNotifs(currentPage)} className="text-xs text-slate-400 hover:text-white transition-colors">
              Refresh
            </button>
          </div>

          {listLoading ? (
            <div className="flex justify-center py-10">
              <div className="animate-spin rounded-full h-8 w-8 border-2 border-indigo-500 border-t-transparent" />
            </div>
          ) : notifs.length === 0 ? (
            <div className="text-center py-10 text-slate-500 text-sm">No notifications sent yet.</div>
          ) : (
            <>
              <div className="divide-y divide-slate-700/50">
                {notifs.map(n => (
                  <div key={n.id} className="flex items-start gap-4 px-6 py-4 hover:bg-slate-700/30 transition-colors">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${typeColor[n.type] ?? typeColor.GENERAL}`}>{n.type}</span>
                        <span className={`text-xs px-1.5 py-0.5 rounded ${n.isRead ? "text-slate-500" : "text-amber-400 bg-amber-900/20"}`}>
                          {n.isRead ? "Read" : "Unread"}
                        </span>
                        <span className="text-xs text-slate-500">{formatRelative(n.createdAt)}</span>
                      </div>
                      <p className="text-sm font-semibold text-white truncate">{n.title}</p>
                      <p className="text-xs text-slate-400 mt-0.5 truncate">{n.message}</p>
                      <p className="text-xs text-slate-600 mt-1">To: {n.recipientUsername} ({n.recipientEmail})</p>
                    </div>
                    <button onClick={() => setDeleteId(n.id)}
                      className="shrink-0 text-xs text-red-400 hover:text-red-300 font-medium mt-1 transition-colors">
                      Delete
                    </button>
                  </div>
                ))}
              </div>
              {totalPages > 1 && (
                <div className="flex items-center justify-between px-6 py-4 border-t border-slate-700">
                  <p className="text-xs text-slate-500">Page {currentPage + 1} of {totalPages}</p>
                  <div className="flex gap-2">
                    <button onClick={() => fetchNotifs(currentPage - 1)} disabled={currentPage === 0}
                      className="px-3 py-1.5 text-xs border border-slate-600 rounded-lg bg-slate-700 text-slate-300 hover:bg-slate-600 disabled:opacity-40 transition-colors">
                      Prev
                    </button>
                    <button onClick={() => fetchNotifs(currentPage + 1)} disabled={currentPage >= totalPages - 1}
                      className="px-3 py-1.5 text-xs border border-slate-600 rounded-lg bg-slate-700 text-slate-300 hover:bg-slate-600 disabled:opacity-40 transition-colors">
                      Next
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </main>

      {deleteId && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-slate-800 border border-slate-700 rounded-2xl shadow-xl p-6 w-full max-w-sm mx-4">
            <h3 className="text-base font-semibold text-white mb-2">Delete Notification?</h3>
            <p className="text-sm text-slate-400 mb-5">This will permanently remove the notification from the recipient&apos;s inbox.</p>
            <div className="flex gap-3">
              <button onClick={() => handleDelete(deleteId)} disabled={deleteLoading}
                className="flex-1 py-2 bg-red-600 text-white text-sm font-semibold rounded-xl hover:bg-red-700 disabled:opacity-50 transition-colors">
                {deleteLoading ? "Deleting..." : "Delete"}
              </button>
              <button onClick={() => setDeleteId(null)}
                className="flex-1 py-2 bg-slate-700 text-slate-200 text-sm font-semibold rounded-xl hover:bg-slate-600 transition-colors">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
