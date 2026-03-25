interface DeleteModalProps {
  isLoading: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function DeleteModal({
  isLoading,
  onConfirm,
  onCancel,
}: DeleteModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm"
        onClick={onCancel}
      />
      <div className="relative bg-white rounded-2xl shadow-2xl overflow-hidden w-full max-w-sm">
        <div className="h-1 w-full bg-gradient-to-r from-rose-400 to-red-500" />
        <div className="p-6">
          <div className="flex items-start gap-4 mb-5">
            <div className="w-11 h-11 rounded-xl bg-rose-50 flex items-center justify-center shrink-0">
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
                  d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                />
              </svg>
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-800">
                Delete Loan?
              </h3>
              <p className="text-sm text-slate-500 mt-0.5">
                This action is permanent and cannot be undone.
              </p>
            </div>
          </div>
          <div className="flex gap-3">
            <button
              onClick={onConfirm}
              disabled={isLoading}
              className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-gradient-to-r from-rose-500 to-red-600 hover:from-rose-600 hover:to-red-700 text-white text-sm font-semibold rounded-xl disabled:opacity-50 transition-all shadow-sm"
            >
              {isLoading && (
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
              {isLoading ? "Deleting…" : "Delete"}
            </button>
            <button
              onClick={onCancel}
              disabled={isLoading}
              className="flex-1 py-2.5 bg-slate-100 text-slate-700 text-sm font-semibold rounded-xl hover:bg-slate-200 transition-colors disabled:opacity-50"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
