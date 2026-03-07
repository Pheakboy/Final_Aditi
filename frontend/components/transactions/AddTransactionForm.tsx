import axios from "axios";

interface FormData {
  type: "INCOME" | "EXPENSE";
  amount: string;
  description: string;
}

interface AddTransactionFormProps {
  formData: FormData;
  formError: string;
  isSubmitting: boolean;
  onFormChange: (data: FormData) => void;
  onSubmit: (e: React.FormEvent) => void;
  onCancel: () => void;
}

export default function AddTransactionForm({
  formData,
  formError,
  isSubmitting,
  onFormChange,
  onSubmit,
  onCancel,
}: AddTransactionFormProps) {
  return (
    <div className="bg-white rounded-2xl card-shadow p-6 mb-6 animate-fade-in">
      <h2 className="text-sm font-semibold text-slate-900 mb-4">
        Add New Transaction
      </h2>
      <form onSubmit={onSubmit} className="space-y-4">
        {formError && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-3 py-2 rounded-xl text-sm">
            {formError}
          </div>
        )}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">
              Type
            </label>
            <select
              value={formData.type}
              onChange={(e) =>
                onFormChange({
                  ...formData,
                  type: e.target.value as "INCOME" | "EXPENSE",
                })
              }
              className="w-full px-4 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-900 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors"
            >
              <option value="INCOME">Income</option>
              <option value="EXPENSE">Expense</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">
              Amount ($)
            </label>
            <input
              type="number"
              step="0.01"
              min="0.01"
              value={formData.amount}
              onChange={(e) =>
                onFormChange({ ...formData, amount: e.target.value })
              }
              className="w-full px-4 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors"
              placeholder="0.00"
              required
            />
          </div>
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-1.5">
            Description (optional)
          </label>
          <input
            type="text"
            value={formData.description}
            onChange={(e) =>
              onFormChange({ ...formData, description: e.target.value })
            }
            className="w-full px-4 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors"
            placeholder="e.g. Salary, Rent, Groceries..."
          />
        </div>
        <div className="flex gap-3">
          <button
            type="submit"
            disabled={isSubmitting}
            className="px-6 py-2.5 gradient-teal text-white text-sm font-semibold rounded-xl hover:opacity-90 disabled:opacity-50 transition-all"
          >
            {isSubmitting ? "Adding..." : "Add Transaction"}
          </button>
          <button
            type="button"
            onClick={onCancel}
            className="px-6 py-2.5 bg-slate-100 text-slate-700 text-sm font-medium rounded-xl hover:bg-slate-200 transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
