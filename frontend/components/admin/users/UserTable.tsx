import Link from "next/link";
import { AdminUser } from "../../../types";

interface UserTableProps {
  users: AdminUser[];
  isLoading: boolean;
  search: string;
  onEdit: (user: AdminUser) => void;
  onToggleStatus: (user: AdminUser) => void;
  onResetPassword?: (user: AdminUser) => void;
  onDelete?: (user: AdminUser) => void;
}

export default function UserTable({
  users,
  isLoading,
  search,
  onEdit,
  onToggleStatus,
  onResetPassword,
  onDelete,
}: UserTableProps) {
  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
      {isLoading ? (
        <table className="w-full text-sm">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              {["User", "Roles", "Phone", "Status", "Actions"].map((h) => (
                <th
                  key={h}
                  className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {Array.from({ length: 6 }).map((_, i) => (
              <tr key={i} className="animate-pulse">
                <td className="px-4 py-3">
                  <div className="h-4 bg-gray-200 rounded w-28 mb-1"></div>
                  <div className="h-3 bg-gray-200 rounded w-40"></div>
                </td>
                <td className="px-4 py-3">
                  <div className="h-5 bg-gray-200 rounded-full w-16"></div>
                </td>
                <td className="px-4 py-3">
                  <div className="h-3 bg-gray-200 rounded w-24"></div>
                </td>
                <td className="px-4 py-3">
                  <div className="h-5 bg-gray-200 rounded-full w-14"></div>
                </td>
                <td className="px-4 py-3">
                  <div className="h-6 bg-gray-200 rounded w-32"></div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : users.length === 0 ? (
        <div className="p-12 text-center text-gray-500">
          {search ? "No users match your search." : "No users found."}
        </div>
      ) : (
        <table className="w-full text-sm">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              {["User", "Roles", "Phone", "Status", "Actions"].map((h) => (
                <th
                  key={h}
                  className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {users.map((u) => (
              <tr key={u.id} className="hover:bg-gray-50">
                <td className="px-4 py-3">
                  <p className="font-medium text-gray-900">{u.username}</p>
                  <p className="text-xs text-gray-400">{u.email}</p>
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {u.roles.map((role) => (
                      <span
                        key={role}
                        className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                          role === "ROLE_ADMIN"
                            ? "bg-purple-100 text-purple-700"
                            : "bg-blue-100 text-blue-700"
                        }`}
                      >
                        {role.replace("ROLE_", "")}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-4 py-3 text-gray-600 text-xs">
                  {u.phoneNumber || <span className="text-gray-300">—</span>}
                </td>
                <td className="px-4 py-3">
                  <span
                    className={`px-2 py-1 rounded-full text-xs font-medium ${
                      u.enabled
                        ? "bg-green-100 text-green-700"
                        : "bg-red-100 text-red-700"
                    }`}
                  >
                    {u.enabled ? "Active" : "Disabled"}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => onEdit(u)}
                      className="px-2.5 py-1 text-xs font-medium text-indigo-600 bg-indigo-50 border border-indigo-200 rounded-lg hover:bg-indigo-100 transition-colors"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => onToggleStatus(u)}
                      className={`px-2.5 py-1 text-xs font-medium rounded-lg border transition-colors ${
                        u.enabled
                          ? "text-red-600 bg-red-50 border-red-200 hover:bg-red-100"
                          : "text-green-600 bg-green-50 border-green-200 hover:bg-green-100"
                      }`}
                    >
                      {u.enabled ? "Deactivate" : "Activate"}
                    </button>
                    <Link
                      href={`/admin/users/${u.id}`}
                      className="px-2.5 py-1 text-xs font-medium text-blue-600 bg-blue-50 border border-blue-200 rounded-lg hover:bg-blue-100 transition-colors"
                    >
                      Profile
                    </Link>
                    {onResetPassword && (
                      <button
                        onClick={() => onResetPassword(u)}
                        className="px-2.5 py-1 text-xs font-medium text-amber-600 bg-amber-50 border border-amber-200 rounded-lg hover:bg-amber-100 transition-colors"
                      >
                        Reset Pwd
                      </button>
                    )}
                    {onDelete && (
                      <button
                        onClick={() => onDelete(u)}
                        className="px-2.5 py-1 text-xs font-medium text-red-600 bg-red-50 border border-red-200 rounded-lg hover:bg-red-100 transition-colors"
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
