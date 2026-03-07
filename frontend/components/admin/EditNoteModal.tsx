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
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-2xl shadow-xl p-6 w-full max-w-md mx-4">
        <h3 className="text-lg font-semibold text-gray-900 mb-2">
          Edit Admin Note
        </h3>
        <textarea
          value={noteText}
          onChange={(e) => onNoteChange(e.target.value)}
          rows={4}
          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 mb-4 resize-none"
          placeholder="Add a note for this loan..."
        />
        <div className="flex gap-3">
          <button
            onClick={onSave}
            disabled={isLoading}
            className="flex-1 py-2 bg-indigo-600 text-white text-sm font-semibold rounded-lg hover:bg-indigo-700 disabled:opacity-50 transition-colors"
          >
            {isLoading ? "Saving..." : "Save Note"}
          </button>
          <button
            onClick={onCancel}
            className="flex-1 py-2 bg-gray-100 text-gray-700 text-sm font-semibold rounded-lg hover:bg-gray-200 transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
