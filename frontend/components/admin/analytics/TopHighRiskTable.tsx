import { AnalyticsData } from "../../../types";

interface TopHighRiskTableProps {
  topHighRiskUsers: AnalyticsData["topHighRiskUsers"];
}

export default function TopHighRiskTable({
  topHighRiskUsers,
}: TopHighRiskTableProps) {
  return (
    <section>
      <h2 className="text-lg font-semibold text-gray-800 mb-4">
        Top High-Risk Users
      </h2>
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        {topHighRiskUsers.length === 0 ? (
          <p className="p-6 text-center text-gray-500 text-sm">
            No high-risk users found.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                  #
                </th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                  User
                </th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                  Max Risk Score
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {topHighRiskUsers.map((u, idx) => (
                <tr key={idx} className="hover:bg-gray-50">
                  <td className="px-4 py-3 text-gray-400 font-mono text-xs">
                    {idx + 1}
                  </td>
                  <td className="px-4 py-3">
                    <p className="font-medium text-gray-900">{u.username}</p>
                    <p className="text-xs text-gray-400">{u.email}</p>
                  </td>
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-red-100 text-red-700">
                      {u.riskScore.toFixed(1)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
