/**
 * Main dashboard with stats, PR queue, and recent findings.
 */

import React from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, CheckCircle, Clock, Shield, TrendingUp } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { getMetricsSummary } from '../api/metrics'
import { usePRList } from '../hooks/usePRs'
import { SeverityBadge } from './SeverityBadge'
import type { PullRequest } from '../types'

function StatCard({
  title,
  value,
  icon: Icon,
  color,
  subtitle,
}: {
  title: string
  value: string | number
  icon: React.ElementType
  color: string
  subtitle?: string
}) {
  return (
    <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-5">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-500 font-medium">{title}</p>
          <p className="text-2xl font-bold text-gray-900 mt-1">{value}</p>
          {subtitle && <p className="text-xs text-gray-400 mt-0.5">{subtitle}</p>}
        </div>
        <div className={`p-3 rounded-full ${color}`}>
          <Icon className="w-5 h-5 text-white" />
        </div>
      </div>
    </div>
  )
}

function PRStatusBadge({ status }: { status: string }) {
  const config: Record<string, string> = {
    pending: 'bg-gray-100 text-gray-600',
    queued: 'bg-blue-100 text-blue-700',
    reviewing: 'bg-yellow-100 text-yellow-700',
    completed: 'bg-green-100 text-green-700',
    failed: 'bg-red-100 text-red-700',
    skipped: 'bg-gray-100 text-gray-500',
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${config[status] || config.pending}`}>
      {status}
    </span>
  )
}

function RiskScore({ score }: { score: number | null }) {
  if (score === null) return <span className="text-gray-300 text-sm">—</span>
  const color = score > 0.7 ? 'text-red-600' : score > 0.3 ? 'text-yellow-600' : 'text-green-600'
  return <span className={`font-mono text-sm font-medium ${color}`}>{score.toFixed(2)}</span>
}

export const Dashboard: React.FC = () => {
  const { data: metrics, isLoading: metricsLoading } = useQuery({
    queryKey: ['metrics', 'summary', 7],
    queryFn: () => getMetricsSummary(7),
    staleTime: 60_000,
    refetchInterval: 120_000,
  })

  const { data: prs, isLoading: prsLoading } = usePRList({ limit: 10 })

  const reviewingPRs = prs?.filter((pr) => pr.status === 'reviewing') || []
  const pendingPRs = prs?.filter((pr) => pr.status === 'pending' || pr.status === 'queued') || []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-sm text-gray-500 mt-1">Autonomous Code Review Agent — Last 7 days</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="PRs Reviewed"
          value={metricsLoading ? '...' : (metrics?.total_prs_reviewed ?? 0)}
          icon={CheckCircle}
          color="bg-green-500"
          subtitle="This week"
        />
        <StatCard
          title="Total Findings"
          value={metricsLoading ? '...' : (metrics?.total_findings ?? 0)}
          icon={AlertTriangle}
          color="bg-orange-500"
          subtitle={`${metrics?.severity_breakdown?.critical ?? 0} critical`}
        />
        <StatCard
          title="Avg Review Time"
          value={
            metricsLoading
              ? '...'
              : metrics?.avg_review_duration_seconds
              ? `${Math.round(metrics.avg_review_duration_seconds)}s`
              : '—'
          }
          icon={Clock}
          color="bg-blue-500"
          subtitle="Per PR"
        />
        <StatCard
          title="False Positive Rate"
          value={
            metricsLoading
              ? '...'
              : metrics?.false_positive_rate !== undefined
              ? `${(metrics.false_positive_rate * 100).toFixed(1)}%`
              : '—'
          }
          icon={TrendingUp}
          color="bg-purple-500"
          subtitle="Based on feedback"
        />
      </div>

      {/* Currently Reviewing */}
      {reviewingPRs.length > 0 && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4">
          <h2 className="text-sm font-semibold text-yellow-800 mb-2 flex items-center gap-2">
            <Shield className="w-4 h-4" />
            Currently Reviewing ({reviewingPRs.length})
          </h2>
          <div className="space-y-2">
            {reviewingPRs.map((pr) => (
              <Link
                key={pr.id}
                to={`/prs/${pr.id}`}
                className="flex items-center justify-between text-sm text-yellow-700 hover:text-yellow-900 py-1"
              >
                <span className="font-mono">
                  {pr.repo_full_name}#{pr.pr_number}
                </span>
                <span className="truncate mx-2 text-yellow-600">{pr.title}</span>
                <span className="flex-shrink-0 animate-pulse text-yellow-500">●</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* PR Queue Table */}
      <div className="bg-white rounded-xl border border-gray-100 shadow-sm">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="font-semibold text-gray-900">Recent Pull Requests</h2>
          <Link to="/prs" className="text-sm text-blue-600 hover:text-blue-700">
            View all →
          </Link>
        </div>

        {prsLoading ? (
          <div className="p-5 space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="animate-pulse h-10 bg-gray-100 rounded" />
            ))}
          </div>
        ) : !prs?.length ? (
          <div className="p-8 text-center text-gray-400">
            <Shield className="w-8 h-8 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No pull requests yet</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-xs text-gray-500 border-b border-gray-100">
                  <th className="text-left px-5 py-3 font-medium">Repository / PR</th>
                  <th className="text-left px-4 py-3 font-medium">Author</th>
                  <th className="text-left px-4 py-3 font-medium">Status</th>
                  <th className="text-left px-4 py-3 font-medium">Risk</th>
                  <th className="text-left px-4 py-3 font-medium">Changes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {prs.map((pr: PullRequest) => (
                  <tr key={pr.id} className="hover:bg-gray-50 transition-colors">
                    <td className="px-5 py-3">
                      <Link to={`/prs/${pr.id}`} className="block">
                        <div className="text-xs text-gray-400 font-mono">
                          {pr.repo_full_name}#{pr.pr_number}
                        </div>
                        <div className="text-sm font-medium text-gray-900 truncate max-w-xs">
                          {pr.title}
                        </div>
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <img
                          src={`https://github.com/${pr.author}.png?size=24`}
                          alt={pr.author}
                          className="w-6 h-6 rounded-full"
                          onError={(e) => ((e.target as HTMLImageElement).src = '/user-placeholder.png')}
                        />
                        <span className="text-sm text-gray-600">{pr.author}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <PRStatusBadge status={pr.status} />
                    </td>
                    <td className="px-4 py-3">
                      <RiskScore score={pr.risk_score} />
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-xs text-gray-500">
                        <span className="text-green-600">+{pr.additions}</span>
                        {' / '}
                        <span className="text-red-500">-{pr.deletions}</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Severity Breakdown */}
      {metrics && (
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-5">
          <h2 className="font-semibold text-gray-900 mb-4">Findings by Severity (7 days)</h2>
          <div className="flex gap-3 flex-wrap">
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
              const count = metrics.severity_breakdown?.[sev] || 0
              return count > 0 ? (
                <div key={sev} className="flex items-center gap-2">
                  <SeverityBadge severity={sev} />
                  <span className="font-mono text-sm font-medium text-gray-700">{count}</span>
                </div>
              ) : null
            })}
          </div>
        </div>
      )}
    </div>
  )
}

export default Dashboard
