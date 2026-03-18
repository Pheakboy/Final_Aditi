"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../context/AuthContext";
import UserLayout from "../../components/UserLayout";
import { notificationApi } from "../../services/api";

interface Notification {
  id: string;
  title: string;
  message: string;
  type: "LOAN_APPROVED" | "LOAN_REJECTED" | "BROADCAST" | "GENERAL";
  isRead: boolean;
  createdAt: string;
}

const typeConfig = {
  LOAN_APPROVED: {
    label: "Loan Approved",
    color: "bg-emerald-100 text-emerald-700 border-emerald-200",
  },
  LOAN_REJECTED: {
    label: "Loan Rejected",
    color: "bg-red-100 text-red-700 border-red-200",
  },
  BROADCAST: {
    label: "Broadcast",
    color: "bg-sky-100 text-sky-700 border-sky-200",
  },
  GENERAL: {
    label: "General",
    color: "bg-slate-100 text-slate-600 border-slate-200",
  },
};

export default function NotificationsPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [markingAll, setMarkingAll] = useState(false);
  const [now, setNow] = useState(0);

  // Update "now" after mount and every minute so relative times stay current.
  // Keeping Date.now() inside useEffect avoids server/client render mismatches.
  useEffect(() => {
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
  }, [user, isLoading, router]);

  const fetchNotifications = useCallback(async () => {
    setDataLoading(true);
    try {
      const [notifRes, countRes] = await Promise.all([
        notificationApi.getAll(),
        notificationApi.getUnreadCount(),
      ]);
      setNotifications(notifRes.data.data?.content || []);
      setUnreadCount(countRes.data.data ?? 0);
    } catch {
      // silently fail — page still renders
    } finally {
      setDataLoading(false);
    }
  }, []);

  useEffect(() => {
    if (user) fetchNotifications();
  }, [user, fetchNotifications]);

  const handleMarkRead = async (id: string) => {
    try {
      await notificationApi.markRead(id);
      setNotifications((prev) =>
        prev.map((n) => (n.id === id ? { ...n, isRead: true } : n)),
      );
      setUnreadCount((c) => Math.max(0, c - 1));
    } catch {
      /* ignore */
    }
  };

  const handleMarkAllRead = async () => {
    setMarkingAll(true);
    try {
      await notificationApi.markAllRead();
      setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
      setUnreadCount(0);
    } catch {
      /* ignore */
    } finally {
      setMarkingAll(false);
    }
  };

  const formatRelative = (date: string) => {
    // "now" is 0 until the component mounts on the client — avoids SSR mismatch.
    if (!now) return "";
    const diff = now - new Date(date).getTime();
    const m = Math.floor(diff / 60000);
    if (m < 1) return "Just now";
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  };

  if (isLoading)
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <div className="animate-spin rounded-full h-10 w-10 border-2 border-teal-500 border-t-transparent" />
      </div>
    );

  const notifSubtitle =
    unreadCount > 0
      ? `${unreadCount} unread message${unreadCount > 1 ? "s" : ""}`
      : "All caught up!";

  return (
    <UserLayout title="Notifications" subtitle={notifSubtitle}>
      <div className="p-6 lg:p-8">
        {/* Action bar */}
        {unreadCount > 0 && (
          <div className="flex justify-end mb-6 animate-fade-in">
            <button
              onClick={handleMarkAllRead}
              disabled={markingAll}
              className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 text-slate-600 text-sm font-medium rounded-xl hover:bg-slate-50 transition-colors disabled:opacity-50 card-shadow"
            >
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
                  d="M5 13l4 4L19 7"
                />
              </svg>
              {markingAll ? "Marking..." : "Mark all as read"}
            </button>
          </div>
        )}

        {/* Notifications List */}
        <div className="bg-white rounded-2xl card-shadow overflow-hidden">
          {dataLoading ? (
            <div className="flex justify-center py-12">
              <div className="animate-spin rounded-full h-8 w-8 border-2 border-teal-500 border-t-transparent" />
            </div>
          ) : notifications.length === 0 ? (
            <div className="p-12 text-center">
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
                    d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
                  />
                </svg>
              </div>
              <p className="text-slate-500 text-sm font-medium">
                No notifications yet
              </p>
              <p className="text-slate-400 text-xs mt-1">
                You&apos;ll be notified when your loan status changes
              </p>
            </div>
          ) : (
            <div className="divide-y divide-slate-50">
              {notifications.map((notif) => {
                const cfg = typeConfig[notif.type] ?? typeConfig.GENERAL;
                return (
                  <div
                    key={notif.id}
                    className={`flex items-start gap-4 px-6 py-4 transition-colors ${!notif.isRead ? "bg-teal-50/40" : "hover:bg-slate-50"}`}
                  >
                    {/* Unread dot */}
                    <div className="mt-1.5 shrink-0">
                      {!notif.isRead ? (
                        <span className="block w-2 h-2 rounded-full bg-teal-500" />
                      ) : (
                        <span className="block w-2 h-2 rounded-full bg-transparent" />
                      )}
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span
                          className={`text-xs font-medium px-2 py-0.5 rounded-full border ${cfg.color}`}
                        >
                          {cfg.label}
                        </span>
                        <span className="text-xs text-slate-400">
                          {formatRelative(notif.createdAt)}
                        </span>
                      </div>
                      <p className="text-sm font-semibold text-slate-900">
                        {notif.title}
                      </p>
                      <p className="text-sm text-slate-500 mt-0.5">
                        {notif.message}
                      </p>
                    </div>

                    {/* Mark read button */}
                    {!notif.isRead && (
                      <button
                        onClick={() => handleMarkRead(notif.id)}
                        className="shrink-0 text-xs text-teal-600 hover:text-teal-700 font-medium mt-1 whitespace-nowrap"
                      >
                        Mark read
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </UserLayout>
  );
}
