import { useEffect, useState } from 'react'
import {
  fetchAlertAnalyticsSummary,
  fetchRiskTrends,
  fetchTopRiskRules,
} from '../api/api'
import Badge from '../components/Badge'
import Card from '../components/Card'
import Chart from '../components/Chart'
import LoadingSpinner from '../components/LoadingSpinner'
import Pagination from '../components/Pagination'
import Table from '../components/Table'
import type {
  AlertAnalyticsSummary,
  RiskTrendItem,
  TopRiskRuleItem,
} from '../types/types'

const platformOptions = ['openlist', 'nextcloud', 'seafile']
const topRulePageSize = 8

function Analytics() {
  const [trends, setTrends] = useState<RiskTrendItem[]>([])
  const [topRules, setTopRules] = useState<TopRiskRuleItem[]>([])
  const [alertSummary, setAlertSummary] = useState<AlertAnalyticsSummary | null>(null)
  const [platform, setPlatform] = useState('openlist')
  const [topRulePage, setTopRulePage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  async function loadAnalytics(silent = false) {
    if (!silent) {
      setLoading(true)
    }
    setError('')
    try {
      const [trendData, ruleData, alertData] = await Promise.all([
        fetchRiskTrends(platform),
        fetchTopRiskRules(platform),
        fetchAlertAnalyticsSummary(platform),
      ])
      setTrends(trendData.filter((item) => (item.platform ?? 'openlist') === platform))
      setTopRules(ruleData.filter((rule) => (rule.platform ?? 'openlist') === platform))
      setAlertSummary(platform === 'openlist' ? alertData : emptyAlertSummary())
      setTopRulePage(1)
    } catch {
      setError('Unable to load analytics data.')
    } finally {
      if (!silent) {
        setLoading(false)
      }
    }
  }

  useEffect(() => {
    loadAnalytics()
    const timer = window.setInterval(() => {
      loadAnalytics(true)
    }, 30000)

    return () => {
      window.clearInterval(timer)
    }
  }, [platform])

  const paginatedTopRules = topRules.slice(
    (topRulePage - 1) * topRulePageSize,
    topRulePage * topRulePageSize,
  )

  return (
    <>
      <header className="page-header">
        <h1>Analytics</h1>
        <p>
          Explore risk trends, frequently triggered rules, and alert summaries
          from the backend analytics APIs.
        </p>
      </header>

      <div className="actions">
        <label className="field compact-field">
          <span>Platform</span>
          <select value={platform} onChange={(event) => setPlatform(event.target.value)}>
            {platformOptions.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>
        <button type="button" className="secondary" onClick={() => loadAnalytics()}>
          Refresh analytics
        </button>
      </div>

      {loading ? <LoadingSpinner label="Loading analytics..." /> : null}
      {error ? <p className="error">{error}</p> : null}

      <div className="page-grid analytics-grid">
          <Card title="Risk Trend">
            <Chart
              title="Scan scores"
              variant="line"
              data={trends.slice(-10).map((item) => ({
                label: `#${item.scan_id}`,
                value: item.total_score,
              }))}
            />
          </Card>
          <Card title="Alert Summary">
            <dl className="metric-list">
              <dt>Total alerts</dt>
              <dd>{alertSummary?.total_alerts ?? '-'}</dd>
              <dt>Open alerts</dt>
              <dd>{alertSummary?.open_alerts ?? '-'}</dd>
              <dt>Closed alerts</dt>
              <dd>{alertSummary?.closed_alerts ?? '-'}</dd>
            </dl>
          </Card>
          <Card title="Alert Severity">
            <Chart
              title="Alerts by severity"
              variant="pie"
              data={Object.entries(alertSummary?.by_severity ?? {}).map(([label, value]) => ({
                label,
                value,
              }))}
            />
          </Card>
          <Card title="Alert Types">
            <Chart
              title="Alerts by type"
              variant="pie"
              data={Object.entries(alertSummary?.by_type ?? {}).map(([label, value]) => ({
                label,
                value,
              }))}
            />
        </Card>
        <Card title="Top Risk Rules" className="analytics-top-rules-card">
          <p className="card-subtitle-inline">Most frequently triggered security rules.</p>
          <Table
            columns={['rank', 'rule_id', 'title', 'severity', 'trigger_count']}
            rows={paginatedTopRules.map((rule, index) => ({
              rank: (topRulePage - 1) * topRulePageSize + index + 1,
              rule_id: <span className="top-risk-text-cell">{rule.rule_id}</span>,
              title: <span className="top-risk-text-cell">{rule.title}</span>,
              severity: <Badge>{rule.severity}</Badge>,
              trigger_count: <strong className="trigger-count-pill">{rule.trigger_count}</strong>,
            }))}
            emptyMessage="No triggered rules available for this platform."
          />
          <Pagination
            currentPage={topRulePage}
            pageSize={topRulePageSize}
            totalItems={topRules.length}
            onPageChange={setTopRulePage}
          />
        </Card>
      </div>
    </>
  )
}

function emptyAlertSummary(): AlertAnalyticsSummary {
  return {
    total_alerts: 0,
    open_alerts: 0,
    closed_alerts: 0,
    by_type: {},
    by_severity: {},
  }
}

export default Analytics
