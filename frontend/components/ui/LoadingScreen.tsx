interface LoadingScreenProps {
  color?: string;
}

export default function LoadingScreen({
  color = "border-teal-500",
}: LoadingScreenProps) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50">
      <div
        className={`animate-spin rounded-full h-10 w-10 border-2 ${color} border-t-transparent`}
      />
    </div>
  );
}
