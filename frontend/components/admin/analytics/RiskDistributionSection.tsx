import { AnalyticsData } from "../../../types";

interface RiskDistributionSectionProps {
  riskDistribution: AnalyticsData["riskDistribution"];
}

export default function RiskDistributionSection({
  riskDistribution,
}: RiskDistributionSectionProps) {
  const { total, low, medium, high } = riskDistribution;

  return (
    <section>
      <h2 className="text-lg font-semibold text-gray-800 mb-4">
        Risk Distribution
      </h2>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl border border-gray-200 p-5">
          <p className="text-xs font-medium text-gray-500 uppercase mb-1">
            Total Loans
          </p>
          <p className="text-3xl font-bold text-gray-900">{total}</p>
        </div>
        <div className="bg-green-50 rounded-xl border border-green-200 p-5">
          <p className="text-xs font-medium text-green-600 uppercase mb-1">
            Low Risk
          </p>
          <p className="text-3xl font-bold text-green-700">{low}</p>
          {total > 0 && (
            <p className="text-xs text-green-500 mt-1">
              {Math.round((low / total) * 100)}%
            </p>
          )}
        </div>
        <div className="bg-yellow-50 rounded-xl border border-yellow-200 p-5">
          <p className="text-xs font-medium text-yellow-600 uppercase mb-1">
            Medium Risk
          </p>
          <p className="text-3xl font-bold text-yellow-700">{medium}</p>
          {total > 0 && (
            <p className="text-xs text-yellow-500 mt-1">
              {Math.round((medium / total) * 100)}%
            </p>
          )}
        </div>
        <div className="bg-red-50 rounded-xl border border-red-200 p-5">
          <p className="text-xs font-medium text-red-600 uppercase mb-1">
            High Risk
          </p>
          <p className="text-3xl font-bold text-red-700">{high}</p>
          {total > 0 && (
            <p className="text-xs text-red-500 mt-1">
              {Math.round((high / total) * 100)}%
            </p>
          )}
        </div>
      </div>
    </section>
  );
}
