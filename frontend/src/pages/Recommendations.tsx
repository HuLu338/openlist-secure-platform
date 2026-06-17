import { useEffect, useState } from 'react'
import {
  fetchLatestRecommendations,
  fetchRecommendations,
  updateRecommendationStatus,
} from '../api/api'
import Badge from '../components/Badge'
import Card from '../components/Card'
import Filter from '../components/Filter'
import LoadingSpinner from '../components/LoadingSpinner'
import Pagination from '../components/Pagination'
import Table from '../components/Table'
import type { Recommendation } from '../types/types'

const emptyRecommendationFilters = { status: '', priority: '', scan_report_id: '' }
const recommendationStatuses = ['open', 'accepted', 'dismissed']
const pageSize = 8

function Recommendations() {
  const [recommendations, setRecommendations] = useState<Recommendation[]>([])
  const [latestRecommendations, setLatestRecommendations] = useState<Recommendation[]>([])
  const [filters, setFilters] = useState(emptyRecommendationFilters)
  const [currentPage, setCurrentPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  async function loadRecommendations(nextFilters = filters) {
    setLoading(true)
    setError('')
    try {
      const [listData, latestData] = await Promise.all([
        fetchRecommendations({
          status: nextFilters.status || undefined,
          priority: nextFilters.priority || undefined,
          scan_report_id: nextFilters.scan_report_id ? Number(nextFilters.scan_report_id) : undefined,
        }),
        fetchLatestRecommendations().catch(() => []),
      ])
      setRecommendations(listData)
      setLatestRecommendations(latestData)
      setCurrentPage(1)
    } catch {
      setError('Unable to load recommendations.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadRecommendations()
  }, [])

  async function setStatus(id: number, status: string) {
    if (!window.confirm(`Change recommendation ${id} to ${status}?`)) {
      return
    }

    setMessage('')
    setError('')
    try {
      await updateRecommendationStatus(id, status)
      setMessage(`Recommendation ${id} marked ${status}.`)
      await loadRecommendations()
    } catch {
      setError('Unable to update recommendation status.')
    }
  }

  const paginatedRecommendations = recommendations.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize,
  )

  return (
    <>
      <header className="page-header">
        <h1>Recommendations</h1>
        <p>Review remediation guidance generated from configuration scan risks.</p>
      </header>

      {loading ? <LoadingSpinner label="Loading recommendations..." /> : null}
      {error ? <p className="error">{error}</p> : null}
      {message ? <p className="success">{message}</p> : null}

      <div className="page-grid two-row-wide-grid">
        <Card title="Latest Scan Recommendations">
          <div className="featured-card-content">
            <strong className="featured-title">
              {latestRecommendations[0]?.title ?? `${latestRecommendations.length} recommendations`}
            </strong>
            <p className="featured-description">
              {latestRecommendations[0]?.recommendation ?? 'recommendations from the latest scan'}
            </p>
            <div className="featured-meta">
              <Badge>{latestRecommendations[0]?.priority ?? 'none'}</Badge>
              <Badge>{latestRecommendations[0]?.status ?? 'none'}</Badge>
              <span>Scan ID: {latestRecommendations[0]?.scan_report_id ?? '-'}</span>
            </div>
          </div>
        </Card>
        <Card title="Recommendation Filters">
          <Filter
            fields={[
              { name: 'status', label: 'Status' },
              { name: 'priority', label: 'Priority' },
              { name: 'scan_report_id', label: 'Scan report ID' },
            ]}
            values={filters}
            onChange={(name, value) => setFilters((current) => ({ ...current, [name]: value }))}
            onSubmit={loadRecommendations}
            onReset={() => {
              setFilters(emptyRecommendationFilters)
              loadRecommendations(emptyRecommendationFilters)
            }}
          />
        </Card>
        <Card title="Recommendations">
          <Table
            columns={['id', 'scan_report_id', 'rule_id', 'priority', 'status', 'action']}
            rows={paginatedRecommendations.map((recommendation) => ({
              id: recommendation.id,
              scan_report_id: recommendation.scan_report_id,
              rule_id: recommendation.rule_id,
              priority: <Badge>{recommendation.priority}</Badge>,
              status: <Badge>{recommendation.status}</Badge>,
              action: (
                <select
                  value={recommendation.status}
                  onChange={(event) => setStatus(recommendation.id, event.target.value)}
                  aria-label={`Set recommendation ${recommendation.id} status`}
                >
                  {recommendationStatuses.map((status) => (
                    <option key={status} value={status}>
                      {status}
                    </option>
                  ))}
                </select>
              ),
            }))}
            emptyMessage="No recommendations match the current filters."
          />
          <Pagination
            currentPage={currentPage}
            pageSize={pageSize}
            totalItems={recommendations.length}
            onPageChange={setCurrentPage}
          />
        </Card>
      </div>
    </>
  )
}

export default Recommendations
