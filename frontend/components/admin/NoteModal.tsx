interface NoteModalProps {
  decision: "APPROVED" | "REJECTED";
  note: string;
  isProcessing: boolean;
  onNoteChange: (value: string) => void;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function NoteModal({
  decision,
  note,
  isProcessing,
  onNoteChange,
  onConfirm,
  onCancel,
}: NoteModalProps) {
  const isApprove = decision === "APPROVED";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm"
        onClick={onCancel}
      />

      {/* Panel */}
      <div className="relative w-full max-w-md bg-white rounded-2xl shadow-2xl overflow-hidden">
        {/* Coloured accent bar */}
        <div
          className={`h-1 w-full ${
            isApprove
              ? "bg-gradient-to-r from-emerald-400 to-teal-500"
              : "bg-gradient-to-r from-rose-400 to-red-500"
          }`}
        />

        <div className="p-6">
          {/* Icon + heading */}
          <div className="flex items-start gap-4 mb-5">
            <div
              className={`w-11 h-11 rounded-xl flex items-center justify-center shrink-0 ${
                isApprove ? "bg-emerald-50" : "bg-rose-50"
              }`}
            >
              {isApprove ? (
                <svg
                  className="w-5 h-5 text-emerald-600"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M5 13l4 4L19 7"
                  />
                </svg>
              ) : (
                <svg
                  className="w-5 h-5 text-rose-600"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              )}
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-800">
                {isApprove
                  ? "Approve Loan Application"
                  : "Reject Loan Application"}
              </h3>
              <p className="text-sm text-slate-500 mt-0.5">
                {isApprove
                  ? "The applicant will be notified of the approval."
                  : "The applicant will be notified of the rejection."}
              </p>
            </div>
          </div>

          {/* Textarea */}
          <div className="mb-5">
            <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1.5">
              Note for applicant{" "}
              <span className="font-normal normal-case text-slate-400">
                (optional)
              </span>
            </label>
            <textarea
              value={note}
              onChange={(e) => onNoteChange(e.target.value)}
              rows={3}
              className="w-full px-3 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-700 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-teal-400 focus:border-transparent resize-none"
              placeholder={
                isApprove
                  ? "e.g. Congratulations! Your loan has been approved."
                  : "e.g. Application declined due to insufficient income."
              }
            />
          </div>

          {/* Buttons */}
          <div className="flex gap-3">
            <button
              onClick={onConfirm}
              disabled={isProcessing}
              className={`flex-1 flex items-center justify-center gap-2 py-2.5 px-4 text-white text-sm font-semibold rounded-xl disabled:opacity-60 transition-all shadow-sm ${
                isApprove
                  ? "bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-600 hover:to-teal-700"
                  : "bg-gradient-to-r from-rose-500 to-red-600 hover:from-rose-600 hover:to-red-700"
              }`}
            >
              {isProcessing && (
                <svg
                  className="animate-spin h-4 w-4"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8v8H4z"
                  />
                </svg>
              )}
              {isProcessing ? "Processing…" : isApprove ? "Approve" : "Reject"}
            </button>
            <button
              onClick={onCancel}
              disabled={isProcessing}
              className="flex-1 py-2.5 px-4 bg-slate-100 text-slate-700 text-sm font-semibold rounded-xl hover:bg-slate-200 transition-colors disabled:opacity-50"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
