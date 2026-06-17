import type {
  Alert,
  AlertAnalyticsSummary,
  ApiDocItem,
  AssistantChatResponse,
  AuditLog,
  DashboardSummary,
  Event,
  Policy,
  Recommendation,
  RiskTrendItem,
  Rule,
  Scan,
  SecurityEventStats,
  TopRiskRuleItem,
} from '../types/types'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '/backend-api'
const API_KEY = import.meta.env.VITE_ADMIN_API_KEY ?? 'change-me-dev-key'

type QueryValue = string | number | boolean | undefined

function buildQuery(params: Record<string, QueryValue> = {}) {
  const searchParams = new URLSearchParams()

  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== '') {
      searchParams.set(key, String(value))
    }
  })

  const query = searchParams.toString()
  return query ? `?${query}` : ''
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const method = options.method ?? 'GET'
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': API_KEY,
      ...options.headers,
    },
  })

  if (!response.ok) {
    throw new Error(`Request failed with status ${response.status}`)
  }

  const data = (await response.json()) as T
  console.log(`[api] ${method} ${path}`, data)
  return data
}

export function fetchHealth() {
  return request<{ status: string }>('/health')
}

export function fetchDashboard(platform?: string) {
  return request<DashboardSummary>(`/dashboard/summary${buildQuery({ platform })}`)
}

export function startScan(configPath: string) {
  return request<Scan>('/scan/start', {
    method: 'POST',
    body: JSON.stringify({ config_path: configPath }),
  })
}

export function fetchScans(
  params: { min_score?: number; max_score?: number; target_path?: string; platform?: string } = {},
) {
  return request<Scan[]>(`/scans${buildQuery(params)}`)
}

export function fetchLatestScan() {
  return request<Scan>('/scans/latest')
}

export function fetchScanById(id: number) {
  return request<Scan>(`/scans/${id}`)
}

export function importEvents(logPath: string) {
  return request<{ imported_count: number; events: Event[] }>('/events/import', {
    method: 'POST',
    body: JSON.stringify({ log_path: logPath }),
  })
}

export function fetchEvents(params: { event_type?: string; severity?: string; actor?: string } = {}) {
  return request<Event[]>(`/events${buildQuery(params)}`)
}

export function fetchLatestEvent() {
  return request<Event>('/events/latest')
}

export function fetchEventById(id: number) {
  return request<Event>(`/events/${id}`)
}

export function fetchEventStats() {
  return request<SecurityEventStats>('/events/stats')
}

export function deleteEvents() {
  return request<{ message: string }>('/events', { method: 'DELETE' })
}

export function fetchAlerts(params: { status?: string; severity?: string; alert_type?: string } = {}) {
  return request<Alert[]>(`/alerts${buildQuery(params)}`)
}

export function fetchLatestAlert() {
  return request<Alert>('/alerts/latest')
}

export function fetchAlertById(id: number) {
  return request<Alert>(`/alerts/${id}`)
}

export function closeAlert(id: number) {
  return request<Alert>(`/alerts/${id}/close`, { method: 'PATCH' })
}

export function fetchRules() {
  return request<Rule[]>('/rules')
}

export function fetchRuleById(ruleID: string) {
  return request<Rule>(`/rules/${ruleID}`)
}

export function updateRule(ruleID: string, payload: Partial<Pick<Rule, 'enabled' | 'severity'>>) {
  return request<Rule>(`/rules/${ruleID}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  })
}

export function fetchPolicy() {
  return request<Policy>('/policies')
}

export function updatePolicy(payload: Partial<Policy>) {
  return request<Policy>('/policies', {
    method: 'PATCH',
    body: JSON.stringify(payload),
  })
}

export function fetchRecommendations(
  params: { status?: string; priority?: string; scan_report_id?: number } = {},
) {
  return request<Recommendation[]>(`/recommendations${buildQuery(params)}`)
}

export function fetchLatestRecommendations() {
  return request<Recommendation[]>('/recommendations/latest')
}

export function fetchRecommendationsByScanId(scanId: number) {
  return request<Recommendation[]>(`/recommendations/scan/${scanId}`)
}

export function updateRecommendationStatus(id: number, status: string) {
  return request<Recommendation>(`/recommendations/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  })
}

export function fetchAuditLogs(
  params: {
    method?: string
    status_code?: number
    success?: boolean
    api_key_used?: boolean
    path?: string
  } = {},
) {
  return request<AuditLog[]>(`/audit/api${buildQuery(params)}`)
}

export function fetchLatestAuditLog() {
  return request<AuditLog>('/audit/api/latest')
}

export function fetchRiskTrends(platform?: string) {
  return request<RiskTrendItem[]>(`/analytics/risk-trends${buildQuery({ platform })}`)
}

export function fetchTopRiskRules(platform?: string) {
  return request<TopRiskRuleItem[]>(`/analytics/risk-rules/top${buildQuery({ platform })}`)
}

export function fetchAlertAnalyticsSummary(platform?: string) {
  return request<AlertAnalyticsSummary>(`/analytics/alerts/summary${buildQuery({ platform })}`)
}

export function fetchApiDocs() {
  return request<Record<string, ApiDocItem[]>>('/api/docs')
}

export function chatWithAssistant(message: string) {
  return request<AssistantChatResponse>('/assistant/chat', {
    method: 'POST',
    body: JSON.stringify({ message }),
  })
}

export function resetEvents() {
  return request<{ message: string }>('/admin/reset/events', { method: 'DELETE' })
}

export function resetAlerts() {
  return request<{ message: string }>('/admin/reset/alerts', { method: 'DELETE' })
}

export function resetAuditLogs() {
  return request<{ message: string }>('/admin/reset/audit', { method: 'DELETE' })
}

export function resetRecommendations() {
  return request<{ message: string }>('/admin/reset/recommendations', {
    method: 'DELETE',
  })
}
