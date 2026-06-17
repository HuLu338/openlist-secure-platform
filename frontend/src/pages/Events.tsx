import { useEffect, useState } from 'react'
import { fetchEvents, fetchLatestEvent, importEvents } from '../api/api'
import Badge from '../components/Badge'
import Card from '../components/Card'
import Filter from '../components/Filter'
import LoadingSpinner from '../components/LoadingSpinner'
import Pagination from '../components/Pagination'
import Table from '../components/Table'
import type { Event } from '../types/types'

const emptyEventFilters = { event_type: '', severity: '', actor: '', platform: '' }
const pageSize = 10

function Events() {
  const [events, setEvents] = useState<Event[]>([])
  const [latestEvent, setLatestEvent] = useState<Event | null>(null)
  const [filters, setFilters] = useState(emptyEventFilters)
  const [logPath, setLogPath] = useState('/home/g5048/openlist-secure-platform/test-openlist.log')
  const [currentPage, setCurrentPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  async function loadEvents(nextFilters = filters) {
    setLoading(true)
    setError('')
    try {
      const [eventData, latestData] = await Promise.all([
        fetchEvents({
          event_type: nextFilters.event_type || undefined,
          severity: nextFilters.severity || undefined,
          actor: nextFilters.actor || undefined,
        }),
        fetchLatestEvent().catch(() => null),
      ])
      const platformFilteredEvents = nextFilters.platform
        ? eventData.filter((event) => event.platform === nextFilters.platform)
        : eventData
      setEvents(platformFilteredEvents)
      setLatestEvent(latestData)
      setCurrentPage(1)
    } catch {
      setError('Unable to load security events.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadEvents()
  }, [])

  async function handleImport() {
    setMessage('')
    setError('')
    try {
      const result = await importEvents(logPath)
      setMessage(`Imported ${result.imported_count} events.`)
      await loadEvents()
    } catch {
      setError('Unable to import log file. Check the log path and backend logs.')
    }
  }

  const paginatedEvents = events.slice((currentPage - 1) * pageSize, currentPage * pageSize)

  return (
    <>
      <header className="page-header">
        <h1>Security Events</h1>
        <p>Import, filter, and inspect parsed OpenList security events.</p>
      </header>

      {loading ? <LoadingSpinner label="Loading events..." /> : null}
      {error ? <p className="error">{error}</p> : null}
      {message ? <p className="success">{message}</p> : null}

      <div className="page-grid two-by-two-grid symmetric-card-grid">
        <Card title="Import Log">
          <label className="field">
            <span>Log path</span>
            <input value={logPath} onChange={(event) => setLogPath(event.target.value)} />
          </label>
          <div className="card-form-action">
            <button type="button" onClick={handleImport}>
              Import events
            </button>
          </div>
        </Card>
        <Card title="Latest Event">
          <dl className="metric-list">
            <dt>ID</dt>
            <dd>{latestEvent?.id ?? '-'}</dd>
            <dt>Type</dt>
            <dd>{latestEvent?.event_type ?? '-'}</dd>
            <dt>Severity</dt>
            <dd>{latestEvent?.severity ?? '-'}</dd>
          </dl>
        </Card>
        <Card title="Event Filters">
          <Filter
            fields={[
              { name: 'event_type', label: 'Type' },
              { name: 'severity', label: 'Severity' },
              { name: 'actor', label: 'Actor' },
              { name: 'platform', label: 'Platform', placeholder: 'openlist' },
            ]}
            values={filters}
            onChange={(name, value) => setFilters((current) => ({ ...current, [name]: value }))}
            onSubmit={loadEvents}
            onReset={() => {
              setFilters(emptyEventFilters)
              loadEvents(emptyEventFilters)
            }}
          />
        </Card>
        <Card title="Events">
          <Table
            columns={['id', 'platform', 'event_time', 'event_type', 'severity', 'actor', 'source_ip']}
            rows={paginatedEvents.map((event) => ({
              id: event.id,
              platform: <Badge tone="platform">{event.platform || 'unknown'}</Badge>,
              event_time: formatDate(event.event_time),
              event_type: event.event_type,
              severity: <Badge>{event.severity}</Badge>,
              actor: event.actor || '-',
              source_ip: event.source_ip || '-',
            }))}
            emptyMessage="No security events match the current filters."
          />
          <Pagination
            currentPage={currentPage}
            pageSize={pageSize}
            totalItems={events.length}
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

export default Events
