type PaginationProps = {
  currentPage: number
  pageSize: number
  totalItems: number
  onPageChange: (page: number) => void
}

function Pagination({ currentPage, pageSize, totalItems, onPageChange }: PaginationProps) {
  const totalPages = Math.max(Math.ceil(totalItems / pageSize), 1)

  if (totalItems <= pageSize) {
    return null
  }

  const startItem = (currentPage - 1) * pageSize + 1
  const endItem = Math.min(currentPage * pageSize, totalItems)

  return (
    <div className="pagination">
      <span className="muted">
        Showing {startItem}-{endItem} of {totalItems}
      </span>
      <button
        type="button"
        className="secondary"
        disabled={currentPage === 1}
        onClick={() => onPageChange(Math.max(currentPage - 1, 1))}
      >
        Previous
      </button>
      <span>
        Page {currentPage} of {totalPages}
      </span>
      <button
        type="button"
        className="secondary"
        disabled={currentPage === totalPages}
        onClick={() => onPageChange(Math.min(currentPage + 1, totalPages))}
      >
        Next
      </button>
    </div>
  )
}

export default Pagination
