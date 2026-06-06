/**
 * TypeScript types matching backend Pydantic schemas.
 */

export type PRStatus = 'pending' | 'queued' | 'reviewing' | 'completed' | 'failed' | 'skipped'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type AgentType =
  | 'static_analysis'
  | 'security_audit'
  | 'dependency'
  | 'compliance'
  | 'remediation'
  | 'reflection'
  | 'orchestrator'

export type AgentRunStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'

export interface PullRequest {
  id: string
  repo_full_name: string
  pr_number: number
  title: string
  author: string
  base_branch: string
  head_branch: string
  diff_url: string | null
  html_url: string | null
  body: string | null
  status: PRStatus
  risk_score: number | null
  files_changed: number
  additions: number
  deletions: number
  created_at: string
  updated_at: string
  reviewed_at: string | null
}

export interface Finding {
  id: string
  pr_id: string
  agent_type: AgentType
  severity: Severity
  category: string
  title: string
  description: string
  file_path: string | null
  line_start: number | null
  line_end: number | null
  code_snippet: string | null
  suggestion: string | null
  patch: string | null
  confidence_score: number
  false_positive: boolean
  human_feedback: string | null
  cwe_id: string | null
  owasp_category: string | null
  rule_id: string | null
  created_at: string
}

export interface AgentRun {
  id: string
  pr_id: string
  agent_type: AgentType
  status: AgentRunStatus
  started_at: string
  completed_at: string | null
  steps_taken: number
  tokens_used: number
  error_message: string | null
  trace_id: string | null
  duration_seconds: number | null
  findings_count: number
}

export interface MetricsSummary {
  period_days: number
  total_prs_reviewed: number
  total_findings: number
  false_positive_rate: number
  avg_review_duration_seconds: number
  severity_breakdown: Record<Severity, number>
  category_breakdown: Record<string, number>
}

export interface FindingOverTimePoint {
  date: string
  severity: Severity
  count: number
}

export interface TopRepo {
  repo: string
  finding_count: number
}

export interface AgentPerformance {
  agent_type: AgentType
  run_count: number
  avg_duration_seconds: number
  total_tokens_used: number
  avg_findings_per_run: number
}

export interface User {
  id: string
  github_id: string
  login: string
  email: string | null
  name: string | null
  avatar_url: string | null
  role: 'admin' | 'reviewer' | 'viewer'
  created_at: string
}

export interface Token {
  access_token: string
  token_type: string
  expires_in: number
}

// API response wrappers
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  limit: number
  offset: number
}

export interface FindingFeedbackPayload {
  false_positive: boolean
  human_feedback?: string
}

export interface TriggerReviewResponse {
  status: string
  task_id: string
  pr_id: string
}
