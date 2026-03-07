import { AnalyticsData } from "../../../types";

const MONTH_NAMES = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

interface MonthlyStatsTableProps {
  monthlyStats: AnalyticsData["monthlyStats"];
}

export default function MonthlyStatsTable({
  monthlyStats,
}: MonthlyStatsTableProps) {
  const maxCount =
    monthlyStats.length > 0 ? Math.max(...monthlyStats.map((s) => s.count)) : 1;

  return (
    <section>
      <h2 className="text-lg font-semibold text-gray-800 mb-4">
        Monthly Applications
      </h2>
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        {monthlyStats.length === 0 ? (
          <p className="p-6 text-center text-gray-500 text-sm">
            No monthly data available.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                  Year
                </th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                  Month
                </th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                  Applications
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {monthlyStats.map((stat, idx) => (
                <tr key={idx} className="hover:bg-gray-50">
                  <td className="px-4 py-3 text-gray-700">{stat.year}</td>
                  <td className="px-4 py-3 text-gray-700">
                    {MONTH_NAMES[stat.month - 1] ?? stat.month}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <span className="font-semibold text-gray-900">
                        {stat.count}
                      </span>
                      <div className="flex-1 bg-gray-100 rounded-full h-2 max-w-30">
                        <div
                          className="bg-blue-500 h-2 rounded-full"
                          style={{
                            width: `${Math.min(100, (stat.count / maxCount) * 100)}%`,
                          }}
                        />
                      </div>
                    </div>
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
