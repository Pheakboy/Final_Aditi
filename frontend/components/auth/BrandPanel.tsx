import Image from "next/image";


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
    <div className="hidden lg:flex lg:w-1/2 relative overflow-hidden flex-col justify-between p-12 bg-slate-900">
      {/* Background decoration - animated rich gradient */}
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,_var(--tw-gradient-stops))] from-indigo-900/80 via-slate-900 to-teal-900/80"></div>
        {side === "left" ? (
          <>
            <div className="absolute top-0 right-0 w-[40rem] h-[40rem] bg-teal-500/20 rounded-full blur-[120px] -translate-y-1/4 translate-x-1/3 mix-blend-screen" />
            <div className="absolute bottom-0 left-0 w-[30rem] h-[30rem] bg-indigo-500/20 rounded-full blur-[100px] translate-y-1/3 -translate-x-1/4 mix-blend-screen" />
          </>
        ) : (
          <>
            <div className="absolute top-0 left-0 w-[40rem] h-[40rem] bg-teal-500/20 rounded-full blur-[120px] -translate-y-1/4 -translate-x-1/3 mix-blend-screen" />
            <div className="absolute bottom-0 right-0 w-[30rem] h-[30rem] bg-indigo-500/20 rounded-full blur-[100px] translate-y-1/3 translate-x-1/4 mix-blend-screen" />
          </>
        )}
        {/* Subtle noise overlay could go here */}
        <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 mix-blend-overlay"></div>
      </div>

      <div className="relative z-10 animate-fade-in">
        <Image
          src="/logo_no_bg.png"
          alt="LoanRisk Logo"
          width={255}
          height={255}
        />
      </div>

      <div className="relative z-10">
        <h1 className="text-4xl font-bold text-white leading-tight mb-4">
          {heading}
        </h1>
        <p className="text-teal-100 text-lg mb-8">{subheading}</p>
        <div className="space-y-3">
          {features.map((f) => (
            <div key={f} className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-white/20 flex items-center justify-center">
                <svg
                  className="w-6 h-6 text-white"
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
