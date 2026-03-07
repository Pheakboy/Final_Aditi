interface Feature {
  text: string;
}

interface BrandPanelProps {
  heading: string;
  subheading: string;
  features: string[];
  side?: "left" | "right";
}

export default function BrandPanel({
  heading,
  subheading,
  features,
  side = "left",
}: BrandPanelProps) {
  const decorationClasses =
    side === "left"
      ? "top-0 right-0 w-96 h-96 -translate-y-1/2 translate-x-1/2 bottom-0 left-0 w-64 h-64 translate-y-1/2 -translate-x-1/2"
      : "";

  return (
    <div className="hidden lg:flex lg:w-1/2 gradient-teal flex-col justify-between p-12 relative overflow-hidden">
      {/* Background decoration */}
      <div className="absolute inset-0 opacity-10">
        {side === "left" ? (
          <>
            <div className="absolute top-0 right-0 w-96 h-96 bg-white rounded-full -translate-y-1/2 translate-x-1/2" />
            <div className="absolute bottom-0 left-0 w-64 h-64 bg-white rounded-full translate-y-1/2 -translate-x-1/2" />
          </>
        ) : (
          <>
            <div className="absolute top-0 left-0 w-96 h-96 bg-white rounded-full -translate-y-1/2 -translate-x-1/2" />
            <div className="absolute bottom-0 right-0 w-64 h-64 bg-white rounded-full translate-y-1/2 translate-x-1/2" />
          </>
        )}
      </div>

      <div className="relative z-10">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-white/20 rounded-xl flex items-center justify-center backdrop-blur-sm">
            <svg
              className="w-6 h-6 text-white"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
          </div>
          <span className="text-white font-bold text-xl">LoanRisk</span>
        </div>
      </div>

      <div className="relative z-10">
        <h1 className="text-4xl font-bold text-white leading-tight mb-4">
          {heading}
        </h1>
        <p className="text-teal-100 text-lg mb-8">{subheading}</p>
        <div className="space-y-3">
          {features.map((f) => (
            <div key={f} className="flex items-center gap-3">
              <div className="w-5 h-5 rounded-full bg-white/20 flex items-center justify-center">
                <svg
                  className="w-3 h-3 text-white"
                  fill="currentColor"
                  viewBox="0 0 20 20"
                >
                  <path
                    fillRule="evenodd"
                    d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                    clipRule="evenodd"
                  />
                </svg>
              </div>
              <span className="text-teal-100 text-sm">{f}</span>
            </div>
          ))}
        </div>
      </div>

      <p className="relative z-10 text-teal-200 text-xs">
        © 2026 LoanRisk. All rights reserved.
      </p>
    </div>
  );
}
