"use client";

interface RiskBadgeProps {
  level: "LOW" | "MEDIUM" | "HIGH" | undefined | null;
  score?: number | null;
}

export default function RiskBadge({ level, score }: RiskBadgeProps) {
  if (!level) return null;

  const config = {
    LOW: {
      bg: "bg-green-100",
      text: "text-green-800",
      border: "border-green-200",
      dot: "bg-green-500",
      label: "Low Risk",
    },
    MEDIUM: {
      bg: "bg-yellow-100",
      text: "text-yellow-800",
      border: "border-yellow-200",
      dot: "bg-yellow-500",
      label: "Medium Risk",
    },
    HIGH: {
      bg: "bg-red-100",
      text: "text-red-800",
      border: "border-red-200",
      dot: "bg-red-500",
      label: "High Risk",
    },
  };

  const c = config[level];

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${c.bg} ${c.text} ${c.border}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`}></span>
      {c.label}
      {score !== undefined && score !== null && (
        <span className="ml-1 opacity-75">({score.toFixed(1)})</span>
      )}
    </span>
  );
}
