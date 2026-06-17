import { useEffect, useState } from 'react'
import { fetchDashboard, fetchRiskTrends } from '../api/api'
import Badge from '../components/Badge'
import Card from '../components/Card'
import Chart from '../components/Chart'
import LoadingSpinner from '../components/LoadingSpinner'
import StatCard from '../components/StatCard'
import type { DashboardSummary, RiskTrendItem } from '../types/types'

const platformOptions = ['openlist', 'nextcloud', 'seafile']

function Dashboard() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [trends, setTrends] = useState<RiskTrendItem[]>([])
  const [platform, setPlatform] = useState('openlist')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  async function loadDashboard(silent = false) {
    if (!silent) {
      setLoading(true)
    }
    setError('')
    try {
      const [summaryData, trendData] = await Promise.all([
        fetchDashboard(platform),
        fetchRiskTrends(platform),
      ])
      const summaryPlatform = summaryData.platform || 'openlist'
      setSummary(summaryPlatform === platform ? summaryData : emptyDashboardSummary(platform))
      setTrends(trendData.filter((item) => (item.platform ?? 'openlist') === platform))
    } catch {
      setError('Unable to load dashboard data. Check that the backend is running.')
    } finally {
      if (!silent) {
        setLoading(false)
      }
    }
  }

  useEffect(() => {
    loadDashboard()
    const timer = window.setInterval(() => {
      loadDashboard(true)
    }, 30000)

    return () => {
      window.clearInterval(timer)
    }
  }, [platform])

  return (
    <>
      <header className="page-header">
        <h1>Dashboard</h1>
        <p>Overview of scan posture, event activity, alerts, and platform health.</p>
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
        <button type="button" className="secondary" onClick={() => loadDashboard()}>
          Refresh dashboard
        </button>
      </div>

      {loading ? <LoadingSpinner label="Loading dashboard..." /> : null}
      {error ? <p className="error">{error}</p> : null}

      {summary ? (
        <div className="page-grid dashboard-grid">
          <Card title="System Status" className="metric-card">
            <dl className="metric-list">
              <dt>Platform</dt>
              <dd>
                <Badge tone="platform">{summary.platform}</Badge>
              </dd>
              <dt>Status</dt>
              <dd>{summary.system_status}</dd>
            </dl>
          </Card>
          <StatCard
            title="Total Scans"
            value={summary.scan_summary.total_scans}
            hint={`latest score: ${summary.scan_summary.latest_score}`}
          />
          <StatCard
            title="Open Alerts"
            value={summary.alert_summary.open_alerts}
            hint={`total alerts: ${summary.alert_summary.total_alerts}`}
          />
          <StatCard
            title="High Severity Events"
            value={summary.event_summary.high_severity_events}
            hint={`total events: ${summary.event_summary.total_events}`}
          />
          <Card title="Scans">
            <dl className="metric-list">
              <dt>Total scans</dt>
              <dd>{summary.scan_summary.total_scans}</dd>
              <dt>Latest score</dt>
              <dd>{summary.scan_summary.latest_score}</dd>
              <dt>Triggered rules</dt>
              <dd>{summary.scan_summary.latest_triggered_rules_count}</dd>
            </dl>
          </Card>
          <Card title="Events">
            <dl className="metric-list">
              <dt>Total events</dt>
              <dd>{summary.event_summary.total_events}</dd>
              <dt>High severity</dt>
              <dd>{summary.event_summary.high_severity_events}</dd>
              <dt>Medium severity</dt>
              <dd>{summary.event_summary.medium_severity_events}</dd>
            </dl>
          </Card>
          <Card title="Alerts">
            <dl className="metric-list">
              <dt>Total alerts</dt>
              <dd>{summary.alert_summary.total_alerts}</dd>
              <dt>Open alerts</dt>
              <dd>{summary.alert_summary.open_alerts}</dd>
              <dt>Latest type</dt>
              <dd>{summary.alert_summary.latest_alert_type || '-'}</dd>
            </dl>
          </Card>
          <Card title="Risk Trend" className="dashboard-risk-trend-card">
            <Chart
              title="Latest scan scores"
              variant="line"
              data={trends.slice(-8).map((item) => ({
                label: `#${item.scan_id}`,
                value: item.total_score,
              }))}
            />
          </Card>
        </div>
      ) : !loading ? (
        <p className="muted">No dashboard data is available yet.</p>
      ) : null}
    </>
  )
}

function emptyDashboardSummary(platform: string): DashboardSummary {
  return {
    platform,
    system_status: 'no data',
    scan_summary: {
      total_scans: 0,
      latest_score: 0,
      latest_triggered_rules_count: 0,
    },
    event_summary: {
      total_events: 0,
      high_severity_events: 0,
      medium_severity_events: 0,
      low_severity_events: 0,
    },
    alert_summary: {
      total_alerts: 0,
      open_alerts: 0,
      closed_alerts: 0,
      latest_alert_type: '',
    },
  }
}

export default Dashboard
