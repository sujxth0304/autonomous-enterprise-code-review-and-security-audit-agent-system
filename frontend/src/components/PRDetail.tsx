/**
 * PR detail page with agent timeline, findings, and code viewer.
 */

import React, { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, ExternalLink, Play, RefreshCw } from 'lucide-react'
import { usePR, usePRFindings, usePRAgentRuns, useTriggerReview } from '../hooks/usePRs'
import { useSubmitFeedback } from '../hooks/useFindings'
import { AgentTimeline } from './AgentTimeline'
import { SeverityBadge } from './SeverityBadge'
import type { Finding } from '../types'

function CodeBlock({ code, language = 'text' }: { code: string; language?: string }) {
  return (
    <pre className="bg-gray-900 text-gray-100 rounded-lg p-4 text-xs overflow-x-auto font-mono leading-relaxed">
      <code>{code}</code>
    </pre>
  )
}

function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false)
  const submitFeedback = useSubmitFeedback()

  return (
    <div className={`border rounded-lg overflow-hidden ${finding.false_positive ? 'opacity-50' : ''}`}>
      <div
        className="flex items-start gap-3 p-4 cursor-pointer hover:bg-gray-50"
        onClick={() => setExpanded((e) => !e)}
      >
        <SeverityBadge severity={finding.severity} size="sm" />
        <div className="flex-1 min-w-0">
          <div className="font-medium text-gray-900 text-sm">{finding.title}</div>
          <div className="text-xs text-gray-500 mt-0.5 flex items-center gap-2">
            {finding.file_path && (
              <span className="font-mono">
                {finding.file_path}
                {finding.line_start ? `:${finding.line_start}` : ''}
              </span>
            )}
            {finding.owasp_category && (
              <span className="bg-orange-50 text-orange-700 px-1 rounded">
                {finding.owasp_category.split(':')[0]}
              </span>
            )}
            {finding.cwe_id && (
              <span className="text-gray-400">{finding.cwe_id}</span>
            )}
          </div>
        </div>
        <div className="text-xs text-gray-400">
          {(finding.confidence_score * 100).toFixed(0)}% confidence
        </div>
        <span className="text-gray-400 text-xs">{expanded ? '▲' : '▼'}</span>
      </div>

      {expanded && (
        <div className="border-t border-gray-100 p-4 space-y-3 bg-gray-50">
          <div className="text-sm text-gray-700">{finding.description}</div>

          {finding.code_snippet && (
            <div>
              <div className="text-xs font-medium text-gray-500 mb-1.5">Vulnerable Code</div>
              <CodeBlock code={finding.code_snippet} />
            </div>
          )}

          {finding.suggestion && (
            <div>
              <div className="text-xs font-medium text-gray-500 mb-1.5">Suggestion</div>
              <div className="text-sm text-gray-700 bg-white border rounded p-3">
                {finding.suggestion}
              </div>
            </div>
          )}

          {finding.patch && (
            <div>
              <div className="text-xs font-medium text-gray-500 mb-1.5">Patch</div>
              <CodeBlock code={finding.patch} language="diff" />
            </div>
          )}

          {/* Feedback buttons */}
          <div className="flex items-center gap-2 pt-2">
            <span className="text-xs text-gray-500">Is this valid?</span>
            <button
              onClick={() =>
                submitFeedback.mutate({
                  id: finding.id,
                  feedback: { false_positive: false, human_feedback: 'Confirmed valid' },
                })
              }
              className="text-xs px-2 py-1 bg-green-100 text-green-700 rounded hover:bg-green-200 transition-colors"
              disabled={submitFeedback.isPending}
            >
              ✓ Valid
            </button>
            <button
              onClick={() =>
                submitFeedback.mutate({
                  id: finding.id,
                  feedback: { false_positive: true, human_feedback: 'False positive' },
                })
              }
              className="text-xs px-2 py-1 bg-red-100 text-red-700 rounded hover:bg-red-200 transition-colors"
              disabled={submitFeedback.isPending}
            >
              ✗ False Positive
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export const PRDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>()
  const { data: pr, isLoading: prLoading } = usePR(id!)
  const { data: findings, isLoading: findingsLoading } = usePRFindings(id!)
  const { data: agentRuns, isLoading: runsLoading } = usePRAgentRuns(id!)
  const triggerReview = useTriggerReview()

  const [activeTab, setActiveTab] = useState<'findings' | 'agents'>('findings')

  if (prLoading) {
    return (
      <div className="animate-pulse space-y-4">
        <div className="h-8 bg-gray-200 rounded w-1/3" />
        <div className="h-32 bg-gray-100 rounded" />
      </div>
    )
  }

  if (!pr) {
    return (
      <div className="text-center py-12 text-gray-500">
        <p>Pull request not found</p>
        <Link to="/prs" className="text-blue-600 text-sm mt-2 inline-block">
          ← Back to PRs
        </Link>
      </div>
    )
  }

  const criticalFindings = findings?.filter((f) => f.severity === 'critical') || []
  const highFindings = findings?.filter((f) => f.severity === 'high') || []
  const riskColor =
    (pr.risk_score ?? 0) > 0.7
      ? 'text-red-600'
      : (pr.risk_score ?? 0) > 0.3
      ? 'text-yellow-600'
      : 'text-green-600'

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <Link to="/prs" className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700 mb-3">
          <ArrowLeft className="w-4 h-4" /> Back to PRs
        </Link>
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-xl font-bold text-gray-900">{pr.title}</h1>
            <div className="flex items-center gap-3 mt-1 text-sm text-gray-500">
              <span className="font-mono">
                {pr.repo_full_name}#{pr.pr_number}
              </span>
              <span>by {pr.author}</span>
              <span>
                {pr.base_branch} ← {pr.head_branch}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {pr.html_url && (
              <a
                href={pr.html_url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700"
              >
                GitHub <ExternalLink className="w-3 h-3" />
              </a>
            )}
            <button
              onClick={() => triggerReview.mutate(id!)}
              disabled={triggerReview.isPending || pr.status === 'reviewing'}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {triggerReview.isPending ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Play className="w-3.5 h-3.5" />
              )}
              {pr.status === 'reviewing' ? 'Reviewing...' : 'Trigger Review'}
            </button>
          </div>
        </div>
      </div>

      {/* Stats strip */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {[
          { label: 'Status', value: pr.status },
          { label: 'Risk Score', value: pr.risk_score ? (
            <span className={riskColor}>{pr.risk_score.toFixed(2)}</span>
          ) : '—' },
          { label: 'Files', value: pr.files_changed },
          { label: 'Additions', value: <span className="text-green-600">+{pr.additions}</span> },
          { label: 'Deletions', value: <span className="text-red-500">-{pr.deletions}</span> },
        ].map(({ label, value }) => (
          <div key={label} className="bg-white border border-gray-100 rounded-lg p-3">
            <div className="text-xs text-gray-500">{label}</div>
            <div className="font-semibold text-gray-900 mt-0.5 text-sm">{value}</div>
          </div>
        ))}
      </div>

      {/* Critical/High highlight */}
      {(criticalFindings.length > 0 || highFindings.length > 0) && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-red-800 mb-2">
            ⚠️ {criticalFindings.length} Critical, {highFindings.length} High Severity Findings
          </h3>
          <div className="space-y-1">
            {[...criticalFindings, ...highFindings].slice(0, 3).map((f) => (
              <div key={f.id} className="text-xs text-red-700">
                • {f.title} {f.file_path ? `(${f.file_path})` : ''}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="bg-white rounded-xl border border-gray-100 shadow-sm">
        <div className="flex border-b border-gray-100">
          <button
            onClick={() => setActiveTab('findings')}
            className={`px-5 py-3 text-sm font-medium transition-colors ${
              activeTab === 'findings'
                ? 'text-blue-600 border-b-2 border-blue-600'
                : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            Findings ({findings?.length ?? 0})
          </button>
          <button
            onClick={() => setActiveTab('agents')}
            className={`px-5 py-3 text-sm font-medium transition-colors ${
              activeTab === 'agents'
                ? 'text-blue-600 border-b-2 border-blue-600'
                : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            Agent Timeline ({agentRuns?.length ?? 0})
          </button>
        </div>

        <div className="p-5">
          {activeTab === 'findings' && (
            <div className="space-y-3">
              {findingsLoading ? (
                <div className="space-y-2">
                  {[1, 2, 3].map((i) => (
                    <div key={i} className="animate-pulse h-14 bg-gray-100 rounded-lg" />
                  ))}
                </div>
              ) : !findings?.length ? (
                <div className="text-center py-8 text-gray-400">
                  {pr.status === 'completed' ? '✓ No findings for this PR' : 'Review not yet started'}
                </div>
              ) : (
                findings.map((finding) => (
                  <FindingCard key={finding.id} finding={finding} />
                ))
              )}
            </div>
          )}

          {activeTab === 'agents' && (
            <AgentTimeline agentRuns={agentRuns || []} isLoading={runsLoading} />
          )}
        </div>
      </div>
    </div>
  )
}

export default PRDetail
