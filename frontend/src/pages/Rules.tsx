import { useEffect, useState } from 'react'
import { fetchRules, updateRule } from '../api/api'
import Badge from '../components/Badge'
import Card from '../components/Card'
import LoadingSpinner from '../components/LoadingSpinner'
import Pagination from '../components/Pagination'
import Table from '../components/Table'
import type { Rule } from '../types/types'

const severities = ['low', 'medium', 'high', 'critical']
const pageSize = 8

function Rules() {
  const [rules, setRules] = useState<Rule[]>([])
  const [selectedRule, setSelectedRule] = useState<Rule | null>(null)
  const [platformFilter, setPlatformFilter] = useState('')
  const [currentPage, setCurrentPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  async function loadRules() {
    setLoading(true)
    setError('')
    try {
      const ruleData = await fetchRules()
      setRules(ruleData)
      setSelectedRule(ruleData[0] ?? null)
      setCurrentPage(1)
    } catch {
      setError('Unable to load rules.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadRules()
  }, [])

  async function applyRuleUpdate(rule: Rule, payload: Partial<Pick<Rule, 'enabled' | 'severity'>>) {
    setMessage('')
    setError('')
    try {
      const updatedRule = await updateRule(rule.rule_id, payload)
      setRules((current) =>
        current.map((currentRule) =>
          currentRule.rule_id === updatedRule.rule_id ? updatedRule : currentRule,
        ),
      )
      setSelectedRule(updatedRule)
      setMessage(`${rule.rule_id} updated.`)
    } catch {
      setError('Unable to update rule.')
    }
  }

  async function toggleRule(rule: Rule) {
    await applyRuleUpdate(rule, { enabled: !rule.enabled })
  }

  async function setSeverity(rule: Rule, severity: string) {
    await applyRuleUpdate(rule, { severity })
  }

  const visibleRules = platformFilter
    ? rules.filter((rule) => rule.platform === platformFilter)
    : rules
  const paginatedRules = visibleRules.slice((currentPage - 1) * pageSize, currentPage * pageSize)

  return (
    <>
      <header className="page-header">
        <h1>Rules</h1>
        <p>Manage enabled state and severity for configurable OpenList rules.</p>
      </header>

      {loading ? <LoadingSpinner label="Loading rules..." /> : null}
      {error ? <p className="error">{error}</p> : null}
      {message ? <p className="success">{message}</p> : null}

      <div className="page-grid two-row-wide-grid">
        <Card title="Selected Rule">
          <div className="featured-card-content">
            <strong className="featured-title">{selectedRule?.title ?? 'No rule selected'}</strong>
            <p className="featured-description">{selectedRule?.rule_id ?? 'Select a rule to view details.'}</p>
            <div className="featured-meta">
              <Badge>{selectedRule?.severity ?? 'none'}</Badge>
              <Badge tone={selectedRule?.enabled ? 'enabled' : 'disabled'}>
                {selectedRule ? String(selectedRule.enabled) : 'disabled'}
              </Badge>
              <Badge tone="platform">{selectedRule?.platform ?? 'unknown'}</Badge>
            </div>
          </div>
        </Card>
        <Card title="Platform Filter">
          <label className="field">
            <span>Platform</span>
            <input
              value={platformFilter}
              placeholder="openlist"
              onChange={(event) => {
                setPlatformFilter(event.target.value)
                setCurrentPage(1)
              }}
            />
          </label>
          <p className="muted">Future adapters such as Nextcloud and Seafile can appear here.</p>
        </Card>
        <Card title="Security Rules">
          <Table
            columns={['rule_id', 'platform', 'severity', 'enabled', 'action']}
            rows={paginatedRules.map((rule) => ({
              rule_id: rule.rule_id,
              platform: <Badge tone="platform">{rule.platform}</Badge>,
              severity: (
                <select
                  value={rule.severity}
                  onChange={(event) => setSeverity(rule, event.target.value)}
                  aria-label={`Set severity for ${rule.rule_id}`}
                >
                  {severities.map((severity) => (
                    <option key={severity} value={severity}>
                      {severity}
                    </option>
                  ))}
                </select>
              ),
              enabled: <Badge tone={rule.enabled ? 'enabled' : 'disabled'}>{String(rule.enabled)}</Badge>,
              action: (
                <span className="inline-actions">
                  <button type="button" onClick={() => toggleRule(rule)}>
                    {rule.enabled ? 'Disable' : 'Enable'}
                  </button>
                  <button type="button" className="secondary" onClick={() => setSelectedRule(rule)}>
                    Details
                  </button>
                </span>
              ),
            }))}
            emptyMessage="No rules match the current platform filter."
          />
          <Pagination
            currentPage={currentPage}
            pageSize={pageSize}
            totalItems={visibleRules.length}
            onPageChange={setCurrentPage}
          />
        </Card>
      </div>
    </>
  )
}

export default Rules
