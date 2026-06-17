import { useEffect, useState } from 'react'
import { closeAlert, fetchAlerts, fetchLatestAlert } from '../api/api'
import Badge from '../components/Badge'
import Card from '../components/Card'
import Filter from '../components/Filter'
import LoadingSpinner from '../components/LoadingSpinner'
import Pagination from '../components/Pagination'
import Table from '../components/Table'
import type { Alert } from '../types/types'

const emptyAlertFilters = { status: '', severity: '', alert_type: '' }
const pageSize = 8

function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [latestAlert, setLatestAlert] = useState<Alert | null>(null)
  const [filters, setFilters] = useState(emptyAlertFilters)
  const [selectedAlertIds, setSelectedAlertIds] = useState<number[]>([])
  const [currentPage, setCurrentPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  async function loadAlerts(nextFilters = filters) {
    setLoading(true)
    setError('')
    try {
      const [alertData, latestData] = await Promise.all([
        fetchAlerts({
          status: nextFilters.status || undefined,
          severity: nextFilters.severity || undefined,
          alert_type: nextFilters.alert_type || undefined,
        }),
        fetchLatestAlert().catch(() => null),
      ])
      setAlerts(alertData)
      setLatestAlert(latestData)
      setSelectedAlertIds([])
      setCurrentPage(1)
    } catch {
      setError('Unable to load alerts.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadAlerts()
  }, [])

  async function handleCloseAlert(id: number) {
    setMessage('')
    setError('')
    try {
      await closeAlert(id)
      setMessage(`Alert ${id} closed.`)
      await loadAlerts()
    } catch {
      setError('Unable to close alert.')
    }
  }

  async function handleBulkClose() {
    const openSelectedIds = alerts
      .filter((alert) => selectedAlertIds.includes(alert.id) && alert.status === 'open')
      .map((alert) => alert.id)

    if (openSelectedIds.length === 0) {
      setMessage('Select at least one open alert to close.')
      return
    }

    setMessage('')
    setError('')
    try {
      await Promise.all(openSelectedIds.map((id) => closeAlert(id)))
      setMessage(`Closed ${openSelectedIds.length} alerts.`)
      await loadAlerts()
    } catch {
      setError('Unable to close selected alerts.')
    }
  }

  function toggleSelectedAlert(id: number) {
    setSelectedAlertIds((current) =>
      current.includes(id) ? current.filter((alertID) => alertID !== id) : [...current, id],
    )
  }

  const paginatedAlerts = alerts.slice((currentPage - 1) * pageSize, currentPage * pageSize)

  return (
    <>
      <header className="page-header">
        <h1>Alerts</h1>
        <p>Track generated alerts and close items that have been reviewed.</p>
      </header>

      {loading ? <LoadingSpinner label="Loading alerts..." /> : null}
      {error ? <p className="error">{error}</p> : null}
      {message ? <p className="success">{message}</p> : null}

      <div className="page-grid two-row-wide-grid">
        <Card title="Latest Alert">
          <div className="featured-card-content">
            <strong className="featured-title">{latestAlert?.alert_type ?? 'No latest alert'}</strong>
            <p className="featured-description">{latestAlert?.message ?? 'No alert has been generated yet.'}</p>
            <div className="featured-meta">
              <Badge>{latestAlert?.severity ?? 'none'}</Badge>
              <Badge>{latestAlert?.status ?? 'none'}</Badge>
              <span>ID: {latestAlert?.id ?? '-'}</span>
            </div>
          </div>
        </Card>
        <Card title="Alert Filters">
          <Filter
            fields={[
              { name: 'status', label: 'Status' },
              { name: 'severity', label: 'Severity' },
              { name: 'alert_type', label: 'Alert type' },
            ]}
            values={filters}
            onChange={(name, value) => setFilters((current) => ({ ...current, [name]: value }))}
            onSubmit={loadAlerts}
            onReset={() => {
              setFilters(emptyAlertFilters)
              loadAlerts(emptyAlertFilters)
            }}
          />
        </Card>
        <Card title="Alerts">
          <div className="actions">
            <button type="button" onClick={handleBulkClose}>
              Close selected
            </button>
            <span className="muted">{selectedAlertIds.length} selected</span>
          </div>
          <Table
            columns={['select', 'id', 'alert_type', 'severity', 'status', 'message', 'action']}
            rows={paginatedAlerts.map((alert) => ({
              select: (
                <input
                  type="checkbox"
                  checked={selectedAlertIds.includes(alert.id)}
                  disabled={alert.status !== 'open'}
                  onChange={() => toggleSelectedAlert(alert.id)}
                  aria-label={`Select alert ${alert.id}`}
                />
              ),
              id: alert.id,
              alert_type: alert.alert_type,
              severity: <Badge>{alert.severity}</Badge>,
              status: <Badge>{alert.status}</Badge>,
              message: alert.message,
              action:
                alert.status === 'open' ? (
                  <button type="button" onClick={() => handleCloseAlert(alert.id)}>
                    Close
                  </button>
                ) : (
                  '-'
                ),
            }))}
            emptyMessage="No alerts match the current filters."
          />
          <Pagination
            currentPage={currentPage}
            pageSize={pageSize}
            totalItems={alerts.length}
            onPageChange={setCurrentPage}
          />
        </Card>
      </div>
    </>
  )
}

export default Alerts
