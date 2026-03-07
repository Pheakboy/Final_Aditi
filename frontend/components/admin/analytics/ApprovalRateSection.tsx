import { AnalyticsData } from "../../../types";

interface ApprovalRateSectionProps {
  approvalRate: AnalyticsData["approvalRate"];
}

export default function ApprovalRateSection({
  approvalRate,
}: ApprovalRateSectionProps) {
  const {
    approved,
    rejected,
    pending,
    approvalPercentage,
    rejectionPercentage,
  } = approvalRate;

  return (
    <section>
      <h2 className="text-lg font-semibold text-gray-800 mb-4">
        Approval Rate
      </h2>
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
        <div className="bg-green-50 rounded-xl border border-green-200 p-5">
          <p className="text-xs font-medium text-green-600 uppercase mb-1">
            Approved
          </p>
          <p className="text-3xl font-bold text-green-700">{approved}</p>
          <p className="text-sm text-green-600 mt-1 font-medium">
            {approvalPercentage.toFixed(1)}%
          </p>
        </div>
        <div className="bg-red-50 rounded-xl border border-red-200 p-5">
          <p className="text-xs font-medium text-red-600 uppercase mb-1">
            Rejected
          </p>
          <p className="text-3xl font-bold text-red-700">{rejected}</p>
          <p className="text-sm text-red-600 mt-1 font-medium">
            {rejectionPercentage.toFixed(1)}%
          </p>
        </div>
        <div className="bg-yellow-50 rounded-xl border border-yellow-200 p-5">
          <p className="text-xs font-medium text-yellow-600 uppercase mb-1">
            Pending
          </p>
          <p className="text-3xl font-bold text-yellow-700">{pending}</p>
        </div>
      </div>
    </section>
  );
}
