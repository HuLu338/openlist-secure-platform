import { useEffect, useState } from 'react'
import { fetchLatestScan, fetchScans, startScan } from '../api/api'
import Badge from '../components/Badge'
import Card from '../components/Card'
import Filter from '../components/Filter'
import LoadingSpinner from '../components/LoadingSpinner'
import Pagination from '../components/Pagination'
import Table from '../components/Table'
import type { SortDirection } from '../components/Table'
import type { Scan } from '../types/types'

const emptyScanFilters = { min_score: '', max_score: '', target_path: '' }
const platformOptions = ['openlist', 'nextcloud', 'seafile']
const pageSize = 10

function ScanHistory() {
  const [scans, setScans] = useState<Scan[]>([])
  const [latestScan, setLatestScan] = useState<Scan | null>(null)
  const [filters, setFilters] = useState(emptyScanFilters)
  const [platform, setPlatform] = useState('openlist')
  const [configPath, setConfigPath] = useState('/home/g5048/openlist-secure-platform/test-config.json')
  const [currentPage, setCurrentPage] = useState(1)
  const [sortColumn, setSortColumn] = useState('scan_time')
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  async function loadScans(nextFilters = filters) {
    setLoading(true)
    setError('')
    try {
      const [scanData, latestData] = await Promise.all([
        fetchScans({
          min_score: nextFilters.min_score ? Number(nextFilters.min_score) : undefined,
          max_score: nextFilters.max_score ? Number(nextFilters.max_score) : undefined,
          target_path: nextFilters.target_path || undefined,
          platform,
        }),
        fetchLatestScan().catch(() => null),
      ])
      const platformFilteredScans = platform
        ? scanData.filter((scan) => (scan.platform || 'openlist') === platform)
        : scanData
      setScans(platformFilteredScans)
      setLatestScan(latestData)
      setCurrentPage(1)
    } catch {
      setError('Unable to load scan history.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadScans()
  }, [platform])

  async function handleStartScan() {
    setMessage('')
    setError('')
    try {
      await startScan(configPath)
      setMessage('Scan completed successfully.')
      await loadScans()
    } catch {
      setError('Unable to start scan. Check the config path and backend logs.')
    }
  }

  const sortedScans = [...scans].sort((left, right) => {
    const leftValue = getSortValue(left, sortColumn)
    const rightValue = getSortValue(right, sortColumn)

    if (leftValue < rightValue) {
      return sortDirection === 'asc' ? -1 : 1
    }
    if (leftValue > rightValue) {
      return sortDirection === 'asc' ? 1 : -1
    }
    return 0
  })
  const paginatedScans = sortedScans.slice((currentPage - 1) * pageSize, currentPage * pageSize)

  function handleSort(column: string) {
    if (column === sortColumn) {
      setSortDirection((current) => (current === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortColumn(column)
      setSortDirection('desc')
    }
  }

  return (
    <>
      <header className="page-header">
        <h1>Scan History</h1>
        <p>Review OpenList configuration scan summaries and drill into risks.</p>
      </header>

      {loading ? <LoadingSpinner label="Loading scans..." /> : null}
      {error ? <p className="error">{error}</p> : null}
      {message ? <p className="success">{message}</p> : null}

      <div className="page-grid two-by-two-grid symmetric-card-grid">
        <Card title="Run Scan">
          <label className="field">
            <span>Config path</span>
            <input value={configPath} onChange={(event) => setConfigPath(event.target.value)} />
          </label>
          <div className="card-form-action">
            <button type="button" onClick={handleStartScan}>
              Start scan
            </button>
          </div>
        </Card>
        <Card title="Latest Scan">
          <dl className="metric-list">
            <dt>ID</dt>
            <dd>{latestScan?.id ?? '-'}</dd>
            <dt>Score</dt>
            <dd>{latestScan?.total_score ?? '-'}</dd>
            <dt>Target</dt>
            <dd>{latestScan?.target_path ?? '-'}</dd>
          </dl>
        </Card>
        <Card title="Scan Filters">
          <label className="field">
            <span>Platform</span>
            <select value={platform} onChange={(event) => setPlatform(event.target.value)}>
              {platformOptions.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </label>
          <Filter
            fields={[
              { name: 'min_score', label: 'Min score' },
              { name: 'max_score', label: 'Max score' },
              { name: 'target_path', label: 'Target path' },
            ]}
            values={filters}
            onChange={(name, value) => setFilters((current) => ({ ...current, [name]: value }))}
            onSubmit={loadScans}
            onReset={() => {
              setFilters(emptyScanFilters)
              loadScans(emptyScanFilters)
            }}
          />
        </Card>
        <Card title="Scans">
          <Table
            columns={[
              'id',
              'platform',
              'scan_time',
              'target_path',
              'total_score',
              'triggered_rules_count',
            ]}
            rows={paginatedScans.map((scan) => ({
              id: scan.id,
              platform: <Badge tone="platform">{scan.platform || 'unknown'}</Badge>,
              scan_time: formatDate(scan.scan_time),
              target_path: scan.target_path,
              total_score: scan.total_score,
              triggered_rules_count: scan.triggered_rules_count,
            }))}
            emptyMessage="No scan history matches the current filters."
            sortableColumns={['scan_time', 'total_score', 'triggered_rules_count']}
            sortColumn={sortColumn}
            sortDirection={sortDirection}
            onSort={handleSort}
          />
          <Pagination
            currentPage={currentPage}
            pageSize={pageSize}
            totalItems={scans.length}
            onPageChange={setCurrentPage}
          />
        </Card>
      </div>
    </>
  )
}

function formatDate(value: string) {
  return value ? new Date(value).toLocaleString() : '-'
}

function getSortValue(scan: Scan, column: string) {
  if (column === 'total_score') {
    return scan.total_score
  }
  if (column === 'triggered_rules_count') {
    return scan.triggered_rules_count
  }
  if (column === 'scan_time') {
    return new Date(scan.scan_time).getTime()
  }
  return 0
}

export default ScanHistory
