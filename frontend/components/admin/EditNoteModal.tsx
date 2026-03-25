interface EditNoteModalProps {
  noteText: string;
  isLoading: boolean;
  onNoteChange: (value: string) => void;
  onSave: () => void;
  onCancel: () => void;
}

export default function EditNoteModal({
  noteText,
  isLoading,
  onNoteChange,
  onSave,
  onCancel,
}: EditNoteModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm"
        onClick={onCancel}
      />
      <div className="relative bg-white rounded-2xl shadow-2xl overflow-hidden w-full max-w-md">
        <div className="h-1 w-full bg-linear-to-r from-indigo-400 to-violet-500" />
        <div className="p-6">
          <div className="flex items-start gap-4 mb-5">
            <div className="w-11 h-11 rounded-xl bg-indigo-50 flex items-center justify-center shrink-0">
              <svg
                className="w-5 h-5 text-indigo-600"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"
                />
              </svg>
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-800">
                Edit Admin Note
              </h3>
              <p className="text-sm text-slate-500 mt-0.5">
                This note is visible to admins only.
              </p>
            </div>
          </div>
          <div className="mb-5">
            <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1.5">
              Note
            </label>
            <textarea
              value={noteText}
              onChange={(e) => onNoteChange(e.target.value)}
              rows={4}
              className="w-full px-3 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-700 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:border-transparent resize-none"
              placeholder="Add a note for this loan…"
            />
          </div>
          <div className="flex gap-3">
            <button
              onClick={onSave}
              disabled={isLoading}
              className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-linear-to-r from-indigo-500 to-violet-600 hover:from-indigo-600 hover:to-violet-700 text-white text-sm font-semibold rounded-xl disabled:opacity-50 transition-all shadow-sm"
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
              {isLoading ? "Saving…" : "Save Note"}
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
