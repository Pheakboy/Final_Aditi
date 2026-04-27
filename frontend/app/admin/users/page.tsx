"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../../context/AuthContext";
import AdminLayout from "../../../components/admin/AdminLayout";
import { adminApi } from "../../../services/api";
import { AdminUser } from "../../../types";
import LoadingScreen from "../../../components/ui/LoadingScreen";
import ErrorAlert from "../../../components/ui/ErrorAlert";
import UserTable from "../../../components/admin/users/UserTable";
import CreateUserModal from "../../../components/admin/users/CreateUserModal";
import EditUserModal from "../../../components/admin/users/EditUserModal";
import { useToast } from "../../../components/ui/Toast";

interface CreateForm {
  username: string;
  email: string;
  role: string;
}
interface EditForm {
  username: string;
  email: string;
}

export default function AdminUsersPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [dataLoading, setDataLoading] = useState(true);
  const [dataError, setDataError] = useState("");
  const [search, setSearch] = useState("");

  const [showCreate, setShowCreate] = useState(false);
  const [createForm, setCreateForm] = useState<CreateForm>({
    username: "",
    email: "",
    role: "USER",
  });
  const [createLoading, setCreateLoading] = useState(false);
  const [createError, setCreateError] = useState("");
  const [tempPassword, setTempPassword] = useState("");

  const [editTarget, setEditTarget] = useState<AdminUser | null>(null);
  const [editForm, setEditForm] = useState<EditForm>({
    username: "",
    email: "",
  });
  const [editLoading, setEditLoading] = useState(false);
  const [editError, setEditError] = useState("");

  const [resetTarget, setResetTarget] = useState<AdminUser | null>(null);
  const [resetResult, setResetResult] = useState("");
  const [resetLoading, setResetLoading] = useState(false);

  const [deleteTarget, setDeleteTarget] = useState<AdminUser | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  const { showToast } = useToast();

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
    if (!isLoading && user && !isAdmin) router.push("/dashboard");
  }, [user, isLoading, isAdmin, router]);

  const fetchUsers = useCallback(async () => {
    setDataLoading(true);
    try {
      const res = await adminApi.getUsers();
      setUsers(res.data.data || []);
    } catch {
      setDataError("Failed to load users. Please refresh.");
    } finally {
      setDataLoading(false);
    }
  }, []);

  useEffect(() => {
    if (user && isAdmin) fetchUsers();
  }, [user, isAdmin, fetchUsers]);

  const filteredUsers = users.filter(
    (u) =>
      u.username.toLowerCase().includes(search.toLowerCase()) ||
      u.email.toLowerCase().includes(search.toLowerCase()),
  );

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateLoading(true);
    setCreateError("");
    setTempPassword("");
    try {
      const res = await adminApi.createUser({
        username: createForm.username,
        email: createForm.email,
        role: createForm.role,
      });
      const created = res.data.data as { temporaryPassword?: string };
      setTempPassword(created.temporaryPassword || "");
      setCreateForm({ username: "", email: "", role: "USER" });
      await fetchUsers();
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })
        ?.response?.data?.message;
      setCreateError(msg || "Failed to create user.");
    } finally {
      setCreateLoading(false);
    }
  };

  const closeCreate = () => {
    setShowCreate(false);
    setCreateError("");
    setTempPassword("");
  };

  const openEdit = (u: AdminUser) => {
    setEditTarget(u);
    setEditForm({ username: u.username, email: u.email });
    setEditError("");
  };

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editTarget) return;
    setEditLoading(true);
    setEditError("");
    try {
      await adminApi.updateUser(editTarget.id, {
        username: editForm.username,
        email: editForm.email,
      });
      setEditTarget(null);
      await fetchUsers();
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })
        ?.response?.data?.message;
      setEditError(msg || "Failed to update user.");
    } finally {
      setEditLoading(false);
    }
  };

  const handleToggleStatus = async (u: AdminUser) => {
    try {
      if (u.enabled) await adminApi.deactivateUser(u.id);
      else await adminApi.reactivateUser(u.id);
      await fetchUsers();
    } catch {
      /* ignore */
    }
  };

  const handleResetPassword = async (u: AdminUser) => {
    setResetTarget(u);
    setResetResult("");
  };

  const confirmResetPassword = async () => {
    if (!resetTarget) return;
    setResetLoading(true);
    try {
      const res = await adminApi.resetUserPassword(resetTarget.id);
      const data = res.data.data as { temporaryPassword?: string };
      setResetResult(data.temporaryPassword || "Password reset successfully");
    } catch {
      showToast("Failed to reset password", "error");
      setResetTarget(null);
    } finally {
      setResetLoading(false);
    }
  };

  const handleDeleteUser = (u: AdminUser) => {
    setDeleteTarget(u);
  };

  const confirmDeleteUser = async () => {
    if (!deleteTarget) return;
    setDeleteLoading(true);
    try {
      await adminApi.deleteUser(deleteTarget.id);
      showToast(`User "${deleteTarget.username}" deleted`, "success");
      setDeleteTarget(null);
      await fetchUsers();
    } catch {
      showToast("Failed to delete user", "error");
      setDeleteTarget(null);
    } finally {
      setDeleteLoading(false);
    }
  };

  if (isLoading) return <LoadingScreen color="border-indigo-500" />;

  return (
    <AdminLayout title="Users" subtitle="Manage registered user accounts">
      <div className="p-8">
        {dataError && <ErrorAlert message={dataError} />}

        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Users</h1>
            <p className="text-gray-500 mt-1">
              {dataLoading
                ? "Loading users…"
                : `${filteredUsers.length} of ${users.length} registered users`}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                setShowCreate(true);
                setTempPassword("");
                setCreateError("");
              }}
              className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700 transition-colors"
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
                  d="M12 4v16m8-8H4"
                />
              </svg>
              Create User
            </button>
            <button
              onClick={async () => {
                try {
                  const res = await adminApi.exportUsers();
                  const url = window.URL.createObjectURL(new Blob([res.data]));
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = "users.csv";
                  a.click();
                  window.URL.revokeObjectURL(url);
                } catch {
                  /* ignore */
                }
              }}
              className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-200 text-gray-600 text-sm font-medium rounded-lg hover:bg-gray-50 transition-colors"
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
                  d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
                />
              </svg>
              Export CSV
            </button>
          </div>
        </div>

        <div className="mb-6">
          <div className="relative max-w-sm">
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
              placeholder="Search by name or email..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>

        <UserTable
          users={filteredUsers}
          isLoading={dataLoading}
          search={search}
          onEdit={openEdit}
          onToggleStatus={handleToggleStatus}
          onResetPassword={handleResetPassword}
          onDelete={handleDeleteUser}
        />
      </div>

      {showCreate && (
        <CreateUserModal
          form={createForm}
          isLoading={createLoading}
          error={createError}
          tempPassword={tempPassword}
          onFormChange={setCreateForm}
          onSubmit={handleCreate}
          onClose={closeCreate}
        />
      )}

      {editTarget && (
        <EditUserModal
          username={editTarget.username}
          form={editForm}
          isLoading={editLoading}
          error={editError}
          onFormChange={setEditForm}
          onSubmit={handleEdit}
          onClose={() => setEditTarget(null)}
        />
      )}

      {/* Reset Password Modal */}
      {resetTarget && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-2xl max-w-md w-full p-6">
            <h2 className="text-lg font-bold text-gray-900 mb-1">
              Reset Password
            </h2>
            {resetResult ? (
              <div className="space-y-4">
                <p className="text-sm text-gray-600">
                  Password reset for <strong>{resetTarget.username}</strong>.
                  Share this temporary password:
                </p>
                <div className="bg-amber-50 border border-amber-200 rounded-xl px-4 py-3 font-mono text-sm text-amber-800 break-all">
                  {resetResult}
                </div>
                <p className="text-xs text-gray-500">
                  The user should change this password after logging in.
                </p>
                <button
                  onClick={() => {
                    setResetTarget(null);
                    setResetResult("");
                  }}
                  className="w-full py-2.5 bg-indigo-600 text-white rounded-xl font-medium hover:bg-indigo-700 transition-colors"
                >
                  Done
                </button>
              </div>
            ) : (
              <div className="space-y-4">
                <p className="text-sm text-gray-600">
                  Reset password for <strong>{resetTarget.username}</strong> (
                  {resetTarget.email})? A new temporary password will be
                  generated.
                </p>
                <div className="flex gap-3">
                  <button
                    onClick={() => setResetTarget(null)}
                    className="flex-1 py-2.5 border border-gray-200 rounded-xl text-sm font-medium text-gray-600 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={confirmResetPassword}
                    disabled={resetLoading}
                    className="flex-1 py-2.5 bg-amber-500 text-white rounded-xl text-sm font-medium hover:bg-amber-600 disabled:opacity-50"
                  >
                    {resetLoading ? "Resetting…" : "Reset Password"}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Delete User Modal */}
      {deleteTarget && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-2xl max-w-md w-full p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-red-100 flex items-center justify-center">
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
              </div>
              <h2 className="text-lg font-bold text-gray-900">Delete User</h2>
            </div>
            <p className="text-sm text-gray-600 mb-1">
              Delete <strong>{deleteTarget.username}</strong> (
              {deleteTarget.email})?
            </p>
            <p className="text-xs text-red-600 mb-6">
              This will permanently delete the user and all their loans,
              transactions, and data. This cannot be undone.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setDeleteTarget(null)}
                className="flex-1 py-2.5 border border-gray-200 rounded-xl text-sm font-medium text-gray-600 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={confirmDeleteUser}
                disabled={deleteLoading}
                className="flex-1 py-2.5 bg-red-600 text-white rounded-xl text-sm font-medium hover:bg-red-700 disabled:opacity-50"
              >
                {deleteLoading ? "Deleting…" : "Delete User"}
              </button>
            </div>
          </div>
        </div>
      )}
    </AdminLayout>
  );
}
