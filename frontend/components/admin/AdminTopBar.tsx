"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "../../context/AuthContext";
import { notificationApi } from "../../services/api";
import { Notification } from "../../types";

interface AdminTopBarProps {
  title: string;
  subtitle?: string;
  onRefresh?: () => void;
}

function formatRelative(date: string) {
  const diff = Date.now() - new Date(date).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "Just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function NotifTypeIcon({ type }: { type: string }) {
  if (type === "LOAN_APPROVED")
    return (
      <svg
        className="w-3.5 h-3.5"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2.5}
          d="M5 13l4 4L19 7"
        />
      </svg>
    );
  if (type === "LOAN_REJECTED")
    return (
      <svg
        className="w-3.5 h-3.5"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2.5}
          d="M6 18L18 6M6 6l12 12"
        />
      </svg>
    );
  if (type === "BROADCAST")
    return (
      <svg
        className="w-3.5 h-3.5"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z"
        />
      </svg>
    );
  return (
    <svg
      className="w-3.5 h-3.5"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
      />
    </svg>
  );
}

function notifMeta(type: string): { bg: string; ring: string } {
  switch (type) {
    case "LOAN_APPROVED":
      return {
        bg: "bg-emerald-100 text-emerald-600",
        ring: "ring-emerald-200",
      };
    case "LOAN_REJECTED":
      return { bg: "bg-red-100 text-red-600", ring: "ring-red-200" };
    case "BROADCAST":
      return { bg: "bg-sky-100 text-sky-600", ring: "ring-sky-200" };
    default:
      return { bg: "bg-indigo-100 text-indigo-600", ring: "ring-indigo-200" };
  }
}

export default function AdminTopBar({
  title,
  subtitle,
  onRefresh,
}: AdminTopBarProps) {
  const { user, logout } = useAuth();
  const router = useRouter();

  const [unread, setUnread] = useState(0);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [notifLoading, setNotifLoading] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [markingRead, setMarkingRead] = useState(false);
  const [loggingOut, setLoggingOut] = useState(false);

  const notifRef = useRef<HTMLDivElement>(null);
  const profileRef = useRef<HTMLDivElement>(null);

  const fetchNotifications = useCallback(async () => {
    setNotifLoading(true);
    try {
      const [countRes, listRes] = await Promise.all([
        notificationApi.getUnreadCount(),
        notificationApi.getAll({ page: 0, size: 6 }),
      ]);
      setUnread(countRes.data.data ?? 0);
      const raw = listRes.data.data;
      // Handle both paged response and plain array
      setNotifications(Array.isArray(raw) ? raw : (raw?.content ?? []));
    } catch {
      // silently ignore
    } finally {
      setNotifLoading(false);
    }
  }, []);

  useEffect(() => {
    if (user) fetchNotifications();
  }, [user, fetchNotifications]);

  // Close dropdowns on outside click
  useEffect(() => {
    function handle(e: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(e.target as Node))
        setNotifOpen(false);
      if (profileRef.current && !profileRef.current.contains(e.target as Node))
        setProfileOpen(false);
    }
    document.addEventListener("mousedown", handle);
    return () => document.removeEventListener("mousedown", handle);
  }, []);

  // Close on ESC
  useEffect(() => {
    function handle(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setNotifOpen(false);
        setProfileOpen(false);
      }
    }
    document.addEventListener("keydown", handle);
    return () => document.removeEventListener("keydown", handle);
  }, []);

  const handleMarkAllRead = async () => {
    setMarkingRead(true);
    try {
      await notificationApi.markAllRead();
      setUnread(0);
      setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
    } catch {
      // ignore
    } finally {
      setMarkingRead(false);
    }
  };

  const handleNotifClick = async (notif: Notification) => {
    if (!notif.isRead) {
      try {
        await notificationApi.markRead(notif.id);
        setNotifications((prev) =>
          prev.map((n) => (n.id === notif.id ? { ...n, isRead: true } : n)),
        );
        setUnread((prev) => Math.max(0, prev - 1));
      } catch {
        // ignore
      }
    }
    setNotifOpen(false);
  };

  const handleLogout = async () => {
    setLoggingOut(true);
    try {
      await logout();
      router.push("/login");
    } catch {
      router.push("/login");
    }
  };

  const initials = user?.username
    ? user.username.slice(0, 2).toUpperCase()
    : "AD";

  return (
    <header className="h-16 shrink-0 bg-white border-b border-slate-200 px-5 flex items-center justify-between shadow-sm z-30 relative">
      {/* ── Left: Breadcrumb + Page Title ─────────────────────────── */}
      <div className="flex items-center gap-3 min-w-0">
        <div className="min-w-0">
          <h1 className="text-[15px] font-extrabold text-slate-900 tracking-tight leading-none truncate">
            {title}
          </h1>
          <p className="text-[11px] text-slate-400 font-medium mt-0.5 leading-none">
            {subtitle ??
              new Date().toLocaleDateString("en-US", {
                weekday: "long",
                year: "numeric",
                month: "short",
                day: "numeric",
              })}
          </p>
        </div>
      </div>

      {/* ── Right: Actions ────────────────────────────────────────── */}
      <div className="flex items-center gap-1.5 shrink-0">
        {/* Refresh button (only when provided) */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            className="w-8 h-8 rounded-lg border border-slate-200 bg-slate-50 flex items-center justify-center text-slate-400 hover:text-indigo-600 hover:border-indigo-200 hover:bg-indigo-50 transition-all"
            title="Refresh data"
          >
            <svg
              className="w-3.5 h-3.5"
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
          </button>
        )}

        {/* ── Notification Bell ──────────────────────────────────── */}
        <div ref={notifRef} className="relative">
          <button
            onClick={() => {
              setNotifOpen((o) => !o);
              setProfileOpen(false);
            }}
            className="relative w-8 h-8 rounded-lg border border-slate-200 bg-slate-50 flex items-center justify-center text-slate-400 hover:text-indigo-600 hover:border-indigo-200 hover:bg-indigo-50 transition-all"
            title="Notifications"
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
                d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
              />
            </svg>
            {unread > 0 && (
              <span className="absolute -top-1 -right-1 min-w-4 h-4 bg-rose-500 text-white text-[9px] font-black rounded-full flex items-center justify-center px-1 shadow-sm animate-pulse">
                {unread > 99 ? "99+" : unread}
              </span>
            )}
          </button>

          {/* Notification Dropdown */}
          {notifOpen && (
            <div className="absolute right-0 top-11 w-80 bg-white rounded-2xl shadow-2xl border border-slate-200 z-50 overflow-hidden animate-slide-up">
              {/* Header */}
              <div className="flex items-center justify-between px-4 py-3 border-b border-slate-100">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-bold text-slate-900">
                    Notifications
                  </span>
                  {unread > 0 && (
                    <span className="min-w-5 h-5 bg-rose-500 text-white text-[10px] font-black rounded-full flex items-center justify-center px-1.5">
                      {unread}
                    </span>
                  )}
                </div>
                {unread > 0 && (
                  <button
                    onClick={handleMarkAllRead}
                    disabled={markingRead}
                    className="text-[11px] font-semibold text-indigo-500 hover:text-indigo-700 disabled:opacity-50 transition-colors"
                  >
                    {markingRead ? "Clearing…" : "Mark all read"}
                  </button>
                )}
              </div>

              {/* List */}
              <div className="max-h-72 overflow-y-auto admin-scroll">
                {notifLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <div className="animate-spin rounded-full h-5 w-5 border-2 border-indigo-500 border-t-transparent" />
                  </div>
                ) : notifications.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-10 text-slate-400">
                    <svg
                      className="w-8 h-8 mb-2 opacity-40"
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
                    <p className="text-xs font-medium">All caught up!</p>
                  </div>
                ) : (
                  notifications.map((notif) => {
                    const meta = notifMeta(notif.type);
                    return (
                      <button
                        key={notif.id}
                        onClick={() => handleNotifClick(notif)}
                        className={`w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-slate-50 transition-colors border-b border-slate-50 last:border-0 ${!notif.isRead ? "bg-indigo-50/40" : ""}`}
                      >
                        <div
                          className={`w-8 h-8 rounded-full ${meta.bg} flex items-center justify-center shrink-0 mt-0.5`}
                        >
                          <NotifTypeIcon type={notif.type} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p
                            className={`text-[13px] leading-snug truncate ${notif.isRead ? "font-medium text-slate-600" : "font-bold text-slate-900"}`}
                          >
                            {notif.title}
                          </p>
                          <p className="text-[11px] text-slate-400 truncate mt-0.5">
                            {notif.message}
                          </p>
                          <p className="text-[10px] text-slate-300 mt-1">
                            {formatRelative(notif.createdAt)}
                          </p>
                        </div>
                        {!notif.isRead && (
                          <div className="w-2 h-2 bg-indigo-500 rounded-full shrink-0 mt-2" />
                        )}
                      </button>
                    );
                  })
                )}
              </div>

              {/* Footer */}
              <Link
                href="/notifications"
                onClick={() => setNotifOpen(false)}
                className="flex items-center justify-center gap-1 py-3 text-[12px] font-semibold text-indigo-600 hover:text-indigo-800 border-t border-slate-100 hover:bg-indigo-50/50 transition-colors"
              >
                View all notifications
                <svg
                  className="w-3 h-3"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2.5}
                    d="M9 5l7 7-7 7"
                  />
                </svg>
              </Link>
            </div>
          )}
        </div>

        {/* Divider */}
        <div className="w-px h-5 bg-slate-200 mx-1" />

        {/* ── Profile / User ─────────────────────────────────────── */}
        <div ref={profileRef} className="relative">
          <button
            onClick={() => {
              setProfileOpen((o) => !o);
              setNotifOpen(false);
            }}
            className="flex items-center gap-2 pl-1 pr-2 h-9 rounded-xl hover:bg-slate-100 transition-all group"
          >
            {/* Avatar */}
            <div className="relative w-8 h-8 rounded-full gradient-indigo flex items-center justify-center shadow-sm shrink-0 ring-2 ring-white">
              {user?.photo ? (
                <span className="w-full h-full rounded-full gradient-indigo block" />
              ) : (
                <span className="text-white text-xs font-bold">
                  {initials.charAt(0)}
                </span>
              )}
              {/* Online dot */}
              <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-emerald-400 rounded-full ring-2 ring-white" />
            </div>

            {/* Name + badge */}
            <div className="hidden sm:block text-left">
              <p className="text-[13px] font-bold text-slate-800 leading-none">
                {user?.username}
              </p>
              <span className="text-[9px] font-bold text-indigo-600 bg-indigo-50 px-1.5 py-0.5 rounded-md leading-none mt-0.5 inline-block">
                ADMIN
              </span>
            </div>

            {/* Chevron */}
            <svg
              className={`w-3.5 h-3.5 text-slate-400 hidden sm:block transition-transform duration-200 ${profileOpen ? "rotate-180" : ""}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M19 9l-7 7-7-7"
              />
            </svg>
          </button>

          {/* Profile Dropdown */}
          {profileOpen && (
            <div className="absolute right-0 top-12 w-60 bg-white rounded-2xl shadow-2xl border border-slate-200 z-50 overflow-hidden animate-slide-up">
              {/* User info */}
              <div className="p-4 bg-linear-to-br from-indigo-50 via-slate-50 to-white border-b border-slate-100">
                <div className="flex items-center gap-3">
                  <div className="relative w-11 h-11 rounded-full gradient-indigo flex items-center justify-center shadow-md shrink-0">
                    {user?.photo ? (
                      <span className="w-full h-full rounded-full gradient-indigo block" />
                    ) : (
                      <span className="text-white text-sm font-black">
                        {initials}
                      </span>
                    )}
                    <span className="absolute -bottom-0.5 -right-0.5 w-3 h-3 bg-emerald-400 rounded-full ring-2 ring-white" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-black text-slate-900 truncate leading-tight">
                      {user?.username}
                    </p>
                    <p className="text-[11px] text-slate-500 truncate leading-tight mt-0.5">
                      {user?.email}
                    </p>
                    <span className="inline-flex items-center gap-1 text-[9px] font-black text-indigo-600 bg-indigo-100 px-1.5 py-0.5 rounded-md mt-1">
                      <svg
                        className="w-2 h-2"
                        fill="currentColor"
                        viewBox="0 0 20 20"
                      >
                        <path
                          fillRule="evenodd"
                          d="M10 1a4.5 4.5 0 00-4.5 4.5V9H5a2 2 0 00-2 2v6a2 2 0 002 2h10a2 2 0 002-2v-6a2 2 0 00-2-2h-.5V5.5A4.5 4.5 0 0010 1zm3 8V5.5a3 3 0 10-6 0V9h6z"
                          clipRule="evenodd"
                        />
                      </svg>
                      ADMINISTRATOR
                    </span>
                  </div>
                </div>
              </div>

              {/* Menu */}
              <div className="p-1.5">
                <Link
                  href="/admin/dashboard"
                  onClick={() => setProfileOpen(false)}
                  className="flex items-center gap-2.5 w-full px-3 py-2 text-[13px] text-slate-600 hover:bg-slate-50 rounded-xl transition-colors font-medium"
                >
                  <svg
                    className="w-4 h-4 text-slate-400"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"
                    />
                  </svg>
                  Dashboard
                </Link>
                <Link
                  href="/notifications"
                  onClick={() => setProfileOpen(false)}
                  className="flex items-center gap-2.5 w-full px-3 py-2 text-[13px] text-slate-600 hover:bg-slate-50 rounded-xl transition-colors font-medium"
                >
                  <svg
                    className="w-4 h-4 text-slate-400"
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
                  My Notifications
                  {unread > 0 && (
                    <span className="ml-auto text-[10px] font-black text-rose-500 bg-rose-50 px-1.5 py-0.5 rounded-md">
                      {unread}
                    </span>
                  )}
                </Link>
              </div>

              <div className="p-1.5 border-t border-slate-100">
                <button
                  onClick={handleLogout}
                  disabled={loggingOut}
                  className="flex items-center gap-2.5 w-full px-3 py-2 text-[13px] text-rose-500 hover:bg-rose-50 rounded-xl transition-colors font-semibold disabled:opacity-60"
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
                      d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
                    />
                  </svg>
                  {loggingOut ? "Signing out…" : "Sign Out"}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
