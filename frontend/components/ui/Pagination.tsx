interface PaginationProps {
  currentPage: number;
  totalPages: number;
  totalElements: number;
  onPageChange: (page: number) => void;
}

export default function Pagination({
  currentPage,
  totalPages,
  totalElements,
  onPageChange,
}: PaginationProps) {
  if (totalPages <= 1) return null;

  return (
    <div className="flex items-center justify-between mt-6">
      <p className="text-sm text-gray-500">
        Page {currentPage + 1} of {totalPages} &nbsp;·&nbsp; {totalElements}{" "}
        total
      </p>
      <div className="flex items-center gap-2">
        <button
          onClick={() => onPageChange(0)}
          disabled={currentPage === 0}
          className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg bg-white hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          «
        </button>
        <button
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage === 0}
          className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg bg-white hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          ‹ Prev
        </button>
        {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
          const start = Math.max(0, Math.min(currentPage - 2, totalPages - 5));
          const p = start + i;
          return (
            <button
              key={p}
              onClick={() => onPageChange(p)}
              className={`px-3 py-1.5 text-sm border rounded-lg transition-colors ${
                p === currentPage
                  ? "bg-blue-600 text-white border-blue-600"
                  : "border-gray-300 bg-white hover:bg-gray-50"
              }`}
            >
              {p + 1}
            </button>
          );
        })}
        <button
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage >= totalPages - 1}
          className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg bg-white hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Next ›
        </button>
        <button
          onClick={() => onPageChange(totalPages - 1)}
          disabled={currentPage >= totalPages - 1}
          className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg bg-white hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          »
        </button>
      </div>
    </div>
  );
}
