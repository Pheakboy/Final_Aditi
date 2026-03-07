"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "../../../context/AuthContext";
import Sidebar from "../../../components/Sidebar";
import { adminApi } from "../../../services/api";
import { AdminUser } from "../../../types";

interface CreateForm { username: string; email: string; role: string; }
interface EditForm   { username: string; email: string; }

export default function AdminUsersPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [dataLoading, setDataLoading] = useState(true);
  const [dataError, setDataError] = useState("");
  const [search, setSearch] = useState("");

  const [showCreate, setShowCreate] = useState(false);
  const [createForm, setCreateForm] = useState<CreateForm>({ username: "", email: "", role: "USER" });
  const [createLoading, setCreateLoading] = useState(false);
  const [createError, setCreateError] = useState("");
  const [tempPassword, setTempPassword] = useState("");

  const [editTarget, setEditTarget] = useState<AdminUser | null>(null);
  const [editForm, setEditForm] = useState<EditForm>({ username: "", email: "" });
  const [editLoading, setEditLoading] = useState(false);
  const [editError, setEditError] = useState("");

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

  useEffect(() => { if (user && isAdmin) fetchUsers(); }, [user, isAdmin, fetchUsers]);

  const filteredUsers = users.filter(
    (u) =>
      u.username.toLowerCase().includes(search.toLowerCase()) ||
      u.email.toLowerCase().includes(search.toLowerCase()),
  );

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateLoading(true); setCreateError(""); setTempPassword("");
    try {
      const res = await adminApi.createUser({ username: createForm.username, email: createForm.email, role: createForm.role });
      const created = res.data.data as { temporaryPassword?: string };
      setTempPassword(created.temporaryPassword || "");
      setCreateForm({ username: "", email: "", role: "USER" });
      await fetchUsers();
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
      setCreateError(msg || "Failed to create user.");
    } finally { setCreateLoading(false); }
  };

  const closeCreate = () => { setShowCreate(false); setCreateError(""); setTempPassword(""); };

  const openEdit = (u: AdminUser) => {
    setEditTarget(u);
    setEditForm({ username: u.username, email: u.email });
    setEditError("");
  };

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editTarget) return;
    setEditLoading(true); setEditError("");
    try {
      await adminApi.updateUser(editTarget.id, { username: editForm.username, email: editForm.email });
      setEditTarget(null);
      await fetchUsers();
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
      setEditError(msg || "Failed to update user.");
    } finally { setEditLoading(false); }
  };

  const handleToggleStatus = async (u: AdminUser) => {
    try {
      if (u.enabled) await adminApi.deactivateUser(u.id);
      else await adminApi.reactivateUser(u.id);
      await fetchUsers();
    } catch { /* ignore */ }
  };

  if (isLoading) return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="animate-spin rounded-full h-10 w-10 border-2 border-indigo-500 border-t-transparent" />
    </div>
  );

  return (
    <div className="flex min-h-screen bg-gray-50">
      <Sidebar />
      <main className="flex-1 p-8">
        {dataError && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm mb-6">{dataError}</div>
        )}

        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Users</h1>
            <p className="text-gray-500 mt-1">{filteredUsers.length} of {users.length} registered users</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => { setShowCreate(true); setTempPassword(""); setCreateError(""); }}
              className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700 transition-colors"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Create User
            </button>
            <button
              onClick={async () => {
                try {
                  const res = await adminApi.exportUsers();
                  const url = window.URL.createObjectURL(new Blob([res.data]));
                  const a = document.createElement("a"); a.href = url; a.download = "users.csv"; a.click();
                  window.URL.revokeObjectURL(url);
                } catch { /* ignore */ }
              }}
              className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-200 text-gray-600 text-sm font-medium rounded-lg hover:bg-gray-50 transition-colors"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
              Export CSV
            </button>
          </div>
        </div>

        <div className="mb-6">
          <div className="relative max-w-sm">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text" placeholder="Search by name or email..." value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
          {dataLoading ? (
            <div className="flex justify-center py-12">
              <div className="animate-spin rounded-full h-8 w-8 border-2 border-indigo-500 border-t-transparent" />
            </div>
          ) : filteredUsers.length === 0 ? (
            <div className="p-12 text-center text-gray-500">
              {search ? "No users match your search." : "No users found."}
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  {["User", "Roles", "Phone", "Status", "Actions"].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {filteredUsers.map((u) => (
                  <tr key={u.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <p className="font-medium text-gray-900">{u.username}</p>
                      <p className="text-xs text-gray-400">{u.email}</p>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {u.roles.map((role) => (
                          <span key={role} className={`px-2 py-0.5 rounded-full text-xs font-medium ${role === "ROLE_ADMIN" ? "bg-purple-100 text-purple-700" : "bg-blue-100 text-blue-700"}`}>
                            {role.replace("ROLE_", "")}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-gray-600 text-xs">{u.phoneNumber || <span className="text-gray-300">—</span>}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${u.enabled ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"}`}>
                        {u.enabled ? "Active" : "Disabled"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => openEdit(u)}
                          className="px-2.5 py-1 text-xs font-medium text-indigo-600 bg-indigo-50 border border-indigo-200 rounded-lg hover:bg-indigo-100 transition-colors"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleToggleStatus(u)}
                          className={`px-2.5 py-1 text-xs font-medium rounded-lg border transition-colors ${u.enabled ? "text-red-600 bg-red-50 border-red-200 hover:bg-red-100" : "text-green-600 bg-green-50 border-green-200 hover:bg-green-100"}`}
                        >
                          {u.enabled ? "Deactivate" : "Activate"}
                        </button>
                        <Link
                          href={`/admin/users/${u.id}`}
                          className="px-2.5 py-1 text-xs font-medium text-blue-600 bg-blue-50 border border-blue-200 rounded-lg hover:bg-blue-100 transition-colors"
                        >
                          Profile
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </main>

      {showCreate && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-2xl shadow-2xl p-6 w-full max-w-md mx-4">
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-bold text-gray-900">Create User</h3>
              <button onClick={closeCreate} className="text-gray-400 hover:text-gray-600">
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            {createError && <div className="bg-red-50 border border-red-200 text-red-700 px-3 py-2 rounded-lg text-sm mb-4">{createError}</div>}
            {tempPassword && (
              <div className="bg-green-50 border border-green-200 text-green-800 px-3 py-2 rounded-lg text-sm mb-4">
                User created! Temporary password: <span className="font-mono font-bold">{tempPassword}</span>
              </div>
            )}
            {!tempPassword && (
              <form onSubmit={handleCreate} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-gray-700 mb-1">Username <span className="text-red-500">*</span></label>
                  <input type="text" required value={createForm.username}
                    onChange={e => setCreateForm({ ...createForm, username: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    placeholder="johndoe" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-700 mb-1">Email <span className="text-red-500">*</span></label>
                  <input type="email" required value={createForm.email}
                    onChange={e => setCreateForm({ ...createForm, email: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    placeholder="john@example.com" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-700 mb-1">Role</label>
                  <select value={createForm.role} onChange={e => setCreateForm({ ...createForm, role: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white">
                    <option value="USER">USER</option>
                    <option value="ADMIN">ADMIN</option>
                  </select>
                </div>
                <div className="flex gap-3 pt-2">
                  <button type="submit" disabled={createLoading}
                    className="flex-1 py-2 bg-indigo-600 text-white text-sm font-semibold rounded-lg hover:bg-indigo-700 disabled:opacity-50 transition-colors">
                    {createLoading ? "Creating..." : "Create User"}
                  </button>
                  <button type="button" onClick={closeCreate}
                    className="flex-1 py-2 bg-gray-100 text-gray-700 text-sm font-semibold rounded-lg hover:bg-gray-200 transition-colors">
                    Cancel
                  </button>
                </div>
              </form>
            )}
            {tempPassword && (
              <button onClick={closeCreate}
                className="w-full mt-2 py-2 bg-indigo-600 text-white text-sm font-semibold rounded-lg hover:bg-indigo-700 transition-colors">
                Close
              </button>
            )}
          </div>
        </div>
      )}

      {editTarget && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-2xl shadow-2xl p-6 w-full max-w-md mx-4">
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-bold text-gray-900">Edit User — {editTarget.username}</h3>
              <button onClick={() => setEditTarget(null)} className="text-gray-400 hover:text-gray-600">
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            {editError && <div className="bg-red-50 border border-red-200 text-red-700 px-3 py-2 rounded-lg text-sm mb-4">{editError}</div>}
            <form onSubmit={handleEdit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">Username</label>
                <input type="text" value={editForm.username}
                  onChange={e => setEditForm({ ...editForm, username: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500" />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">Email</label>
                <input type="email" value={editForm.email}
                  onChange={e => setEditForm({ ...editForm, email: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500" />
              </div>
              <div className="flex gap-3 pt-2">
                <button type="submit" disabled={editLoading}
                  className="flex-1 py-2 bg-indigo-600 text-white text-sm font-semibold rounded-lg hover:bg-indigo-700 disabled:opacity-50 transition-colors">
                  {editLoading ? "Saving..." : "Save Changes"}
                </button>
                <button type="button" onClick={() => setEditTarget(null)}
                  className="flex-1 py-2 bg-gray-100 text-gray-700 text-sm font-semibold rounded-lg hover:bg-gray-200 transition-colors">
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
