import type { ReactNode } from 'react'

export type SortDirection = 'asc' | 'desc'

type TableProps = {
  columns: string[]
  rows?: Array<Record<string, ReactNode>>
  emptyMessage?: string
  sortableColumns?: string[]
  sortColumn?: string
  sortDirection?: SortDirection
  onSort?: (column: string) => void
}

function Table({
  columns,
  rows = [],
  emptyMessage = 'No records found.',
  sortableColumns = [],
  sortColumn,
  sortDirection = 'asc',
  onSort,
}: TableProps) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            {columns.map((column) => {
              const sortable = sortableColumns.includes(column) && onSort
              return (
                <th key={column}>
                  {sortable ? (
                    <button type="button" className="table-sort" onClick={() => onSort(column)}>
                      {column}
                      {sortColumn === column ? ` ${sortDirection === 'asc' ? 'up' : 'down'}` : ''}
                    </button>
                  ) : (
                    column
                  )}
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length}>{emptyMessage}</td>
            </tr>
          ) : (
            rows.map((row, index) => (
              <tr key={String(index)}>
                {columns.map((column) => (
                  <td key={column}>{row[column] ?? '-'}</td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}

export default Table
