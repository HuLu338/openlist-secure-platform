import { useEffect, useState } from 'react'
import { fetchAuditLogs, fetchLatestAuditLog } from '../api/api'
import Badge from '../components/Badge'
import Card from '../components/Card'
import Filter from '../components/Filter'
import LoadingSpinner from '../components/LoadingSpinner'
import Pagination from '../components/Pagination'
import Table from '../components/Table'
import type { AuditLog } from '../types/types'

const emptyAuditFilters = { method: '', status_code: '', success: '', api_key_used: '', path: '' }
const pageSize = 8

function AuditLogs() {
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([])
  const [latestAuditLog, setLatestAuditLog] = useState<AuditLog | null>(null)
  const [filters, setFilters] = useState(emptyAuditFilters)
  const [sortDirection, setSortDirection] = useState<'newest' | 'oldest'>('newest')
  const [currentPage, setCurrentPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  async function loadAuditLogs(nextFilters = filters) {
    setLoading(true)
    setError('')
    try {
      const [logData, latestData] = await Promise.all([
        fetchAuditLogs({
          method: nextFilters.method || undefined,
          status_code: nextFilters.status_code ? Number(nextFilters.status_code) : undefined,
          success: parseOptionalBool(nextFilters.success),
          api_key_used: parseOptionalBool(nextFilters.api_key_used),
          path: nextFilters.path || undefined,
        }),
        fetchLatestAuditLog().catch(() => null),
      ])
      setAuditLogs(logData)
      setLatestAuditLog(latestData)
      setCurrentPage(1)
    } catch {
      setError('Unable to load API audit logs.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadAuditLogs()
  }, [])

  const sortedAuditLogs = [...auditLogs].sort((left, right) => {
    const leftTime = new Date(left.timestamp).getTime()
    const rightTime = new Date(right.timestamp).getTime()
    return sortDirection === 'newest' ? rightTime - leftTime : leftTime - rightTime
  })
  const paginatedAuditLogs = sortedAuditLogs.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize,
  )

  return (
    <>
      <header className="page-header">
        <h1>API Audit Logs</h1>
        <p>Inspect recorded API activity for development and demo auditing.</p>
      </header>

      {loading ? <LoadingSpinner label="Loading audit logs..." /> : null}
      {error ? <p className="error">{error}</p> : null}

      <div className="page-grid two-row-wide-grid">
        <Card title="Latest Audit Log">
          <div className="featured-card-content">
            <strong className="featured-title">
              {latestAuditLog ? `${latestAuditLog.method} ${latestAuditLog.path}` : 'No audit log yet'}
            </strong>
            <p className="featured-description">
              {latestAuditLog?.timestamp ? formatDate(latestAuditLog.timestamp) : 'API access will appear here.'}
            </p>
            <div className="featured-meta">
              <Badge tone={latestAuditLog?.method ?? 'unknown'}>{latestAuditLog?.method ?? 'unknown'}</Badge>
              <Badge tone={String(latestAuditLog?.status_code ?? 'none')}>
                {latestAuditLog?.status_code ?? 'none'}
              </Badge>
              <Badge tone={latestAuditLog?.success ? 'success' : 'failed'}>
                {latestAuditLog ? String(latestAuditLog.success) : 'false'}
              </Badge>
              <span>API key: {latestAuditLog ? String(latestAuditLog.api_key_used) : '-'}</span>
            </div>
          </div>
        </Card>
        <Card title="Audit Filters">
          <Filter
            fields={[
              { name: 'method', label: 'Method' },
              { name: 'status_code', label: 'Status code' },
              { name: 'success', label: 'Success', placeholder: 'true or false' },
              { name: 'api_key_used', label: 'API key used', placeholder: 'true or false' },
              { name: 'path', label: 'Path' },
            ]}
            values={filters}
            onChange={(name, value) => setFilters((current) => ({ ...current, [name]: value }))}
            onSubmit={loadAuditLogs}
            onReset={() => {
              setFilters(emptyAuditFilters)
              loadAuditLogs(emptyAuditFilters)
            }}
          />
        </Card>
        <Card title="Audit Logs">
          <div className="actions">
            <button
              type="button"
              className="secondary"
              onClick={() =>
                setSortDirection((current) => (current === 'newest' ? 'oldest' : 'newest'))
              }
            >
              Sort: {sortDirection === 'newest' ? 'newest first' : 'oldest first'}
            </button>
          </div>
          <Table
            columns={['id', 'timestamp', 'method', 'path', 'status_code', 'success']}
            rows={paginatedAuditLogs.map((log) => ({
              id: log.id,
              timestamp: formatDate(log.timestamp),
              method: log.method,
              path: log.path,
              status_code: <Badge tone={String(log.status_code)}>{log.status_code}</Badge>,
              success: <Badge tone={log.success ? 'success' : 'failed'}>{String(log.success)}</Badge>,
            }))}
            emptyMessage="No audit logs match the current filters."
          />
          <Pagination
            currentPage={currentPage}
            pageSize={pageSize}
            totalItems={auditLogs.length}
            onPageChange={setCurrentPage}
          />
        </Card>
      </div>
    </>
  )
}

function parseOptionalBool(value: string) {
  if (value === 'true') {
    return true
  }
  if (value === 'false') {
    return false
  }
  return undefined
}

function formatDate(value: string) {
  return value ? new Date(value).toLocaleString() : '-'
}

export default AuditLogs
