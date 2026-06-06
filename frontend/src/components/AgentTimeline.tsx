/**
 * Visual timeline of agent execution steps.
 */

import React from 'react'
import { CheckCircle, Clock, XCircle, Loader, Circle } from 'lucide-react'
import type { AgentRun } from '../types'

interface AgentTimelineProps {
  agentRuns: AgentRun[]
  isLoading?: boolean
}

const AGENT_LABELS: Record<string, string> = {
  orchestrator: 'Orchestrator',
  static_analysis: 'Static Analysis',
  security_audit: 'Security Audit',
  dependency: 'Dependency Check',
  compliance: 'Compliance',
  remediation: 'Remediation',
  reflection: 'Reflection',
}

const STATUS_CONFIG = {
  pending: { icon: Circle, color: 'text-gray-400', bg: 'bg-gray-100', label: 'Pending' },
  running: { icon: Loader, color: 'text-blue-500', bg: 'bg-blue-50', label: 'Running' },
  completed: { icon: CheckCircle, color: 'text-green-500', bg: 'bg-green-50', label: 'Done' },
  failed: { icon: XCircle, color: 'text-red-500', bg: 'bg-red-50', label: 'Failed' },
  cancelled: { icon: XCircle, color: 'text-gray-400', bg: 'bg-gray-100', label: 'Cancelled' },
}

function formatDuration(seconds: number | null): string {
  if (seconds === null) return '--'
  if (seconds < 60) return `${seconds.toFixed(1)}s`
  const mins = Math.floor(seconds / 60)
  const secs = seconds % 60
  return `${mins}m ${secs.toFixed(0)}s`
}

export const AgentTimeline: React.FC<AgentTimelineProps> = ({ agentRuns, isLoading }) => {
  if (isLoading) {
    return (
      <div className="space-y-3">
        {[1, 2, 3].map((i) => (
          <div key={i} className="animate-pulse flex items-center gap-3">
            <div className="w-8 h-8 bg-gray-200 rounded-full" />
            <div className="flex-1">
              <div className="h-4 bg-gray-200 rounded w-1/3 mb-1" />
              <div className="h-3 bg-gray-100 rounded w-1/4" />
            </div>
          </div>
        ))}
      </div>
    )
  }

  if (agentRuns.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        <Clock className="mx-auto mb-2 w-8 h-8 opacity-50" />
        <p className="text-sm">No agent runs yet</p>
      </div>
    )
  }

  return (
    <div className="relative">
      {/* Vertical line */}
      <div className="absolute left-4 top-4 bottom-4 w-0.5 bg-gray-200" />

      <div className="space-y-4">
        {agentRuns.map((run, index) => {
          const statusConf = STATUS_CONFIG[run.status] || STATUS_CONFIG.pending
          const Icon = statusConf.icon
          const isLast = index === agentRuns.length - 1

          return (
            <div key={run.id} className="relative flex items-start gap-4 pl-2">
              {/* Status icon */}
              <div
                className={`relative z-10 flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${statusConf.bg}`}
              >
                <Icon
                  className={`w-4 h-4 ${statusConf.color} ${run.status === 'running' ? 'animate-spin' : ''}`}
                />
              </div>

              {/* Content */}
              <div className={`flex-1 pb-4 ${isLast ? '' : ''}`}>
                <div className="flex items-center justify-between">
                  <div>
                    <span className="font-medium text-gray-900 text-sm">
                      {AGENT_LABELS[run.agent_type] || run.agent_type}
                    </span>
                    <span
                      className={`ml-2 text-xs px-1.5 py-0.5 rounded-full ${statusConf.bg} ${statusConf.color}`}
                    >
                      {statusConf.label}
                    </span>
                  </div>
                  <div className="text-xs text-gray-500">
                    {formatDuration(run.duration_seconds)}
                  </div>
                </div>

                <div className="mt-1 flex items-center gap-3 text-xs text-gray-500">
                  {run.findings_count > 0 && (
                    <span>{run.findings_count} findings</span>
                  )}
                  {run.steps_taken > 0 && (
                    <span>{run.steps_taken} steps</span>
                  )}
                  {run.tokens_used > 0 && (
                    <span>{run.tokens_used.toLocaleString()} tokens</span>
                  )}
                </div>

                {run.error_message && (
                  <div className="mt-1 text-xs text-red-600 bg-red-50 rounded p-1.5">
                    {run.error_message.slice(0, 200)}
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default AgentTimeline
