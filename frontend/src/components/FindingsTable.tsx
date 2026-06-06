/**
 * Paginated findings table with filters.
 */

import React, { useState } from 'react'
import { ChevronLeft, ChevronRight, ThumbsDown, ThumbsUp } from 'lucide-react'
import { useFindingsList } from '../hooks/useFindings'
import { useSubmitFeedback } from '../hooks/useFindings'
import { SeverityBadge } from './SeverityBadge'
import type { Severity } from '../types'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const CATEGORIES = ['security', 'compliance', 'static_analysis', 'dependency', 'performance', 'maintainability']
const AGENT_TYPES = ['static_analysis', 'security_audit', 'dependency', 'compliance', 'remediation']

const PAGE_SIZE = 20

export const FindingsTable: React.FC = () => {
  const [filters, setFilters] = useState<{
    severity?: string
    category?: string
    agent_type?: string
    false_positive?: boolean
  }>({})
  const [page, setPage] = useState(0)

  const { data: findings, isLoading, error } = useFindingsList({
    ...filters,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  })

  const submitFeedback = useSubmitFeedback()

  const handleFeedback = (id: string, isFP: boolean) => {
    submitFeedback.mutate({
      id,
      feedback: {
        false_positive: isFP,
        human_feedback: isFP ? 'Marked as false positive' : 'Confirmed as valid finding',
      },
    })
  }

  if (error) {
    return (
      <div className="text-center py-8 text-red-600">
        Failed to load findings. Please try again.
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap gap-3 p-4 bg-gray-50 rounded-lg">
        <select
          className="text-sm border border-gray-200 rounded px-2 py-1.5 bg-white"
          value={filters.severity || ''}
          onChange={(e) => {
            setFilters((f) => ({ ...f, severity: e.target.value || undefined }))
            setPage(0)
          }}
        >
          <option value="">All Severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>

        <select
          className="text-sm border border-gray-200 rounded px-2 py-1.5 bg-white"
          value={filters.category || ''}
          onChange={(e) => {
            setFilters((f) => ({ ...f, category: e.target.value || undefined }))
            setPage(0)
          }}
        >
          <option value="">All Categories</option>
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c.replace('_', ' ')}
            </option>
          ))}
        </select>

        <select
          className="text-sm border border-gray-200 rounded px-2 py-1.5 bg-white"
          value={filters.agent_type || ''}
          onChange={(e) => {
            setFilters((f) => ({ ...f, agent_type: e.target.value || undefined }))
            setPage(0)
          }}
        >
          <option value="">All Agents</option>
          {AGENT_TYPES.map((a) => (
            <option key={a} value={a}>
              {a.replace('_', ' ')}
            </option>
          ))}
        </select>

        <label className="flex items-center gap-1.5 text-sm">
          <input
            type="checkbox"
            checked={filters.false_positive === false}
            onChange={(e) => {
              setFilters((f) => ({
                ...f,
                false_positive: e.target.checked ? false : undefined,
              }))
              setPage(0)
            }}
          />
          Hide false positives
        </label>
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="animate-pulse h-16 bg-gray-100 rounded" />
          ))}
        </div>
      ) : !findings?.length ? (
        <div className="text-center py-12 text-gray-500">No findings match your filters</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 text-left text-gray-600">
                <th className="pb-2 pr-4 font-medium">Severity</th>
                <th className="pb-2 pr-4 font-medium">Title</th>
                <th className="pb-2 pr-4 font-medium">File</th>
                <th className="pb-2 pr-4 font-medium">Category</th>
                <th className="pb-2 pr-4 font-medium">Confidence</th>
                <th className="pb-2 font-medium">Feedback</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {findings.map((finding) => (
                <tr
                  key={finding.id}
                  className={`hover:bg-gray-50 ${finding.false_positive ? 'opacity-50' : ''}`}
                >
                  <td className="py-3 pr-4">
                    <SeverityBadge severity={finding.severity} size="sm" />
                  </td>
                  <td className="py-3 pr-4">
                    <div className="font-medium text-gray-900 truncate max-w-xs">
                      {finding.title}
                    </div>
                    {finding.cwe_id && (
                      <div className="text-xs text-gray-400">{finding.cwe_id}</div>
                    )}
                  </td>
                  <td className="py-3 pr-4">
                    {finding.file_path ? (
                      <div className="font-mono text-xs text-gray-600 truncate max-w-[200px]">
                        {finding.file_path}
                        {finding.line_start && (
                          <span className="text-gray-400">:{finding.line_start}</span>
                        )}
                      </div>
                    ) : (
                      <span className="text-gray-300">—</span>
                    )}
                  </td>
                  <td className="py-3 pr-4">
                    <span className="text-xs bg-gray-100 text-gray-600 px-2 py-0.5 rounded-full">
                      {finding.category}
                    </span>
                  </td>
                  <td className="py-3 pr-4">
                    <div className="flex items-center gap-1">
                      <div
                        className="h-1.5 rounded-full bg-green-400"
                        style={{ width: `${finding.confidence_score * 60}px` }}
                      />
                      <span className="text-xs text-gray-500">
                        {(finding.confidence_score * 100).toFixed(0)}%
                      </span>
                    </div>
                  </td>
                  <td className="py-3">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => handleFeedback(finding.id, false)}
                        title="Confirm as valid"
                        className="p-1 rounded hover:bg-green-50 text-gray-400 hover:text-green-600 transition-colors"
                        disabled={submitFeedback.isPending}
                      >
                        <ThumbsUp className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleFeedback(finding.id, true)}
                        title="Mark as false positive"
                        className="p-1 rounded hover:bg-red-50 text-gray-400 hover:text-red-600 transition-colors"
                        disabled={submitFeedback.isPending}
                      >
                        <ThumbsDown className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      <div className="flex items-center justify-between pt-2">
        <span className="text-sm text-gray-500">
          Page {page + 1}
        </span>
        <div className="flex gap-2">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className="flex items-center gap-1 px-3 py-1.5 text-sm border border-gray-200 rounded hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <ChevronLeft className="w-4 h-4" /> Prev
          </button>
          <button
            onClick={() => setPage((p) => p + 1)}
            disabled={!findings || findings.length < PAGE_SIZE}
            className="flex items-center gap-1 px-3 py-1.5 text-sm border border-gray-200 rounded hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Next <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  )
}

export default FindingsTable
