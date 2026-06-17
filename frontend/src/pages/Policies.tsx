import { useEffect, useState } from 'react'
import { fetchPolicy, updatePolicy } from '../api/api'
import Card from '../components/Card'
import LoadingSpinner from '../components/LoadingSpinner'
import type { Policy } from '../types/types'

function Policies() {
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [form, setForm] = useState({
    low_score_threshold: '',
    multiple_login_failures_threshold: '',
    long_token_hours_threshold: '',
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  async function loadPolicy() {
    setLoading(true)
    setError('')
    try {
      const data = await fetchPolicy()
      setPolicy(data)
      setForm({
        low_score_threshold: String(data.low_score_threshold),
        multiple_login_failures_threshold: String(data.multiple_login_failures_threshold),
        long_token_hours_threshold: String(data.long_token_hours_threshold),
      })
    } catch {
      setError('Unable to load policy.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadPolicy()
  }, [])

  async function handleUpdate() {
    setMessage('')
    setError('')
    if (!Object.values(form).every(isPositiveInteger)) {
      setError('All threshold values must be positive integers.')
      return
    }

    try {
      const updated = await updatePolicy({
        low_score_threshold: Number(form.low_score_threshold),
        multiple_login_failures_threshold: Number(form.multiple_login_failures_threshold),
        long_token_hours_threshold: Number(form.long_token_hours_threshold),
      })
      setPolicy(updated)
      setForm({
        low_score_threshold: String(updated.low_score_threshold),
        multiple_login_failures_threshold: String(updated.multiple_login_failures_threshold),
        long_token_hours_threshold: String(updated.long_token_hours_threshold),
      })
      setMessage('Policy updated.')
    } catch {
      setError('Unable to update policy. Use positive integer values.')
    }
  }

  return (
    <>
      <header className="page-header">
        <h1>Policies</h1>
        <p>Configure platform thresholds for scan scoring and event alerting.</p>
      </header>

      {loading ? <LoadingSpinner label="Loading policy..." /> : null}
      {error ? <p className="error">{error}</p> : null}
      {message ? <p className="success">{message}</p> : null}

      <div className="page-grid policy-grid">
        <Card title="Active Policy" subtitle="Current threshold values used by backend rules.">
          <div className="policy-card-content">
            <div className="policy-value-grid">
              <div className="policy-value-row">
                <span>Low Score Threshold</span>
                <strong>{policy?.low_score_threshold ?? '-'}</strong>
              </div>
              <div className="policy-value-row">
                <span>Login Failure Threshold</span>
                <strong>{policy?.multiple_login_failures_threshold ?? '-'}</strong>
              </div>
              <div className="policy-value-row">
                <span>Long Token Hours</span>
                <strong>{policy?.long_token_hours_threshold ?? '-'}</strong>
              </div>
            </div>
            <p className="policy-helper-text">
              These values control scan alerts, login failure alerts, and token validity checks.
            </p>
          </div>
        </Card>
        <Card title="Update Policy" subtitle="Use positive integer values only.">
          <div className="policy-card-content">
            <div className="form-grid policy-form-grid">
              {Object.entries(form).map(([key, value]) => (
                <label className="field" key={key}>
                  <span>{formatPolicyLabel(key)}</span>
                  <input
                    type="number"
                    min="1"
                    value={value}
                    onChange={(event) =>
                      setForm((current) => ({ ...current, [key]: event.target.value }))
                    }
                  />
                </label>
              ))}
              <div className="policy-button-row">
                <button type="button" className="policy-submit-button" onClick={handleUpdate}>
                  Save policy
                </button>
              </div>
            </div>
          </div>
        </Card>
      </div>
    </>
  )
}

function isPositiveInteger(value: string) {
  return /^\d+$/.test(value) && Number(value) > 0
}

function formatPolicyLabel(value: string) {
  return value
    .split('_')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
}

export default Policies
