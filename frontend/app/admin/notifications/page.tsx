"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../../context/AuthContext";
import Sidebar from "../../../components/Sidebar";
import { adminApi } from "../../../services/api";
import axios from "axios";

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

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
    if (!isLoading && user && !isAdmin) router.push("/dashboard");
  }, [user, isLoading, isAdmin, router]);

  const handleBroadcast = async (e: React.FormEvent) => {
    e.preventDefault();
    setBroadcastLoading(true); setBroadcastError(""); setBroadcastSuccess("");
    try {
      await adminApi.broadcastNotification({ title: broadcastForm.title, message: broadcastForm.message });
      setBroadcastSuccess("Broadcast sent to all active users successfully.");
      setBroadcastForm({ title: "", message: "" });
    } catch (err: unknown) {
      setBroadcastError(axios.isAxiosError(err) ? (err.response?.data?.message ?? "Failed to send broadcast") : "Failed to send broadcast");
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
    } catch (err: unknown) {
      setUserError(axios.isAxiosError(err) ? (err.response?.data?.message ?? "Failed to send notification") : "Failed to send notification");
    } finally { setUserLoading(false); }
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
          <p className="text-slate-400 mt-1 text-sm">Send messages to users or broadcast to everyone</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
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
            {broadcastError && <div className="bg-red-900/30 border border-red-700/50 text-red-300 px-3 py-2 rounded-xl text-sm mb-4">{broadcastError}</div>}

            <form onSubmit={handleBroadcast} className="space-y-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1.5">Title <span className="text-red-400">*</span></label>
                <input type="text" value={broadcastForm.title} onChange={(e) => setBroadcastForm({ ...broadcastForm, title: e.target.value })} required
                  className="w-full px-4 py-2.5 bg-slate-900/50 border border-slate-600 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="e.g. System Maintenance Notice" />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1.5">Message <span className="text-red-400">*</span></label>
                <textarea value={broadcastForm.message} onChange={(e) => setBroadcastForm({ ...broadcastForm, message: e.target.value })} rows={4} required
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
            {userError && <div className="bg-red-900/30 border border-red-700/50 text-red-300 px-3 py-2 rounded-xl text-sm mb-4">{userError}</div>}

            <form onSubmit={handleSendToUser} className="space-y-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1.5">User ID <span className="text-red-400">*</span></label>
                <input type="text" value={userForm.userId} onChange={(e) => setUserForm({ ...userForm, userId: e.target.value })} required
                  className="w-full px-4 py-2.5 bg-slate-900/50 border border-slate-600 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="Enter numeric user ID" />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1.5">Title <span className="text-red-400">*</span></label>
                <input type="text" value={userForm.title} onChange={(e) => setUserForm({ ...userForm, title: e.target.value })} required
                  className="w-full px-4 py-2.5 bg-slate-900/50 border border-slate-600 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="Notification title" />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1.5">Message <span className="text-red-400">*</span></label>
                <textarea value={userForm.message} onChange={(e) => setUserForm({ ...userForm, message: e.target.value })} rows={4} required
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
      </main>
    </div>
  );
}
