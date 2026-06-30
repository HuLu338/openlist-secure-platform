export type RiskItem = {
  rule_id: string
  title: string
  severity: string
  category: string
  evidence: string
  description: string
  recommendation: string
}

export type ScoringPenalty = {
  rule_id: string
  severity: string
  penalty: number
  reason: string
}

export type ScoringBreakdown = {
  base_score: number
  total_penalty: number
  final_score: number
  penalties: ScoringPenalty[]
}

export type Scan = {
  id: number
  platform: string
  scan_time: string
  target_path: string
  total_score: number
  risk_level: string
  triggered_rules_count: number
  scoring_breakdown?: ScoringBreakdown
  risks?: RiskItem[]
}

export type Event = {
  id: number
  platform: string
  event_time: string
  event_type: string
  severity: string
  actor: string
  target: string
  source_ip: string
  raw_message: string
}

export type Alert = {
  id: number
  source_type: string
  source_ref: string
  alert_type: string
  severity: string
  message: string
  status: string
  created_at: string
}

export type Recommendation = {
  id: number
  scan_report_id: number
  rule_id: string
  title: string
  priority: string
  recommendation: string
  status: string
  created_at: string
}

export type Rule = {
  id: number
  rule_id: string
  platform: string
  title: string
  severity: string
  enabled: boolean
  description: string
  recommendation: string
  updated_at: string
}

export type Policy = {
  id: number
  low_score_threshold: number
  multiple_login_failures_threshold: number
  long_token_hours_threshold: number
  updated_at: string
}

export type DashboardSummary = {
  platform: string
  system_status: string
  scan_summary: {
    total_scans: number
    latest_scan_time?: string
    latest_score: number
    latest_triggered_rules_count: number
  }
  event_summary: {
    total_events: number
    high_severity_events: number
    medium_severity_events: number
    low_severity_events: number
  }
  alert_summary: {
    total_alerts: number
    open_alerts: number
    closed_alerts: number
    latest_alert_type: string
  }
}

export type AuditLog = {
  id: number
  timestamp: string
  method: string
  path: string
  status_code: number
  client_ip: string
  user_agent: string
  api_key_used: boolean
  success: boolean
}

export type SecurityEventStats = {
  total_events: number
  by_type: Record<string, number>
  by_severity: Record<string, number>
}

export type RiskTrendItem = {
  scan_id: number
  platform?: string
  scan_time: string
  total_score: number
  risk_level: string
  triggered_rules_count: number
  target_path: string
}

export type TopRiskRuleItem = {
  rule_id: string
  platform?: string
  title: string
  severity: string
  trigger_count: number
}

export type AlertAnalyticsSummary = {
  total_alerts: number
  open_alerts: number
  closed_alerts: number
  by_type: Record<string, number>
  by_severity: Record<string, number>
}

export type ApiDocItem = {
  method: string
  path: string
  description: string
  auth_required: boolean
}

export type AssistantChatResponse = {
  answer: string
  mode: string
  sources: string[]
  suggested_actions: string[]
}
