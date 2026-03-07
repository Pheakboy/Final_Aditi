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
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-md mx-4">
        <h3 className="text-lg font-semibold text-gray-900 mb-2">
          {decision === "APPROVED" ? "Approve Loan" : "Reject Loan"}
        </h3>
        <p className="text-sm text-gray-500 mb-4">
          Add an optional note for the applicant:
        </p>
        <textarea
          value={note}
          onChange={(e) => onNoteChange(e.target.value)}
          rows={3}
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm mb-4"
          placeholder={
            decision === "APPROVED"
              ? "e.g. Congratulations! Loan approved."
              : "e.g. Insufficient income."
          }
        />
        <div className="flex gap-3">
          <button
            onClick={onConfirm}
            disabled={isProcessing}
            className={`flex-1 py-2 px-4 text-white text-sm font-medium rounded-lg disabled:opacity-50 transition-colors ${
              decision === "APPROVED"
                ? "bg-green-600 hover:bg-green-700"
                : "bg-red-600 hover:bg-red-700"
            }`}
          >
            {isProcessing ? "Processing..." : `Confirm ${decision}`}
          </button>
          <button
            onClick={onCancel}
            className="flex-1 py-2 px-4 bg-gray-100 text-gray-700 text-sm font-medium rounded-lg hover:bg-gray-200 transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
