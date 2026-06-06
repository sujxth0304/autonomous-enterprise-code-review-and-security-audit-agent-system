/**
 * Analytics/metrics dashboard with charts.
 */

import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  BarChart,
  Bar,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { getAgentPerformance, getFindingsOverTime, getMetricsSummary, getTopRepos } from '../api/metrics'

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#65a30d',
  info: '#0284c7',
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return <h2 className="text-base font-semibold text-gray-900 mb-4">{children}</h2>
}

export const MetricsDashboard: React.FC = () => {
  const [days, setDays] = useState(30)

  const { data: summary } = useQuery({
    queryKey: ['metrics', 'summary', days],
    queryFn: () => getMetricsSummary(days),
    staleTime: 60_000,
  })

  const { data: overTime } = useQuery({
    queryKey: ['metrics', 'over-time', days],
    queryFn: () => getFindingsOverTime(days),
    staleTime: 60_000,
  })

  const { data: topRepos } = useQuery({
    queryKey: ['metrics', 'top-repos', days],
    queryFn: () => getTopRepos(days, 10),
    staleTime: 60_000,
  })

  const { data: agentPerf } = useQuery({
    queryKey: ['metrics', 'agent-perf', days],
    queryFn: () => getAgentPerformance(days),
    staleTime: 60_000,
  })

  // Transform findings-over-time data for recharts
  const timelineData = React.useMemo(() => {
    if (!overTime) return []
    const byDate: Record<string, Record<string, number>> = {}
    overTime.forEach((point) => {
      if (!byDate[point.date]) byDate[point.date] = { date: point.date }
      byDate[point.date][point.severity] = point.count
    })
    return Object.values(byDate).sort((a, b) => a.date.localeCompare(b.date))
  }, [overTime])

  // Pie chart data from severity breakdown
  const pieData = summary
    ? Object.entries(summary.severity_breakdown || {})
        .filter(([, count]) => count > 0)
        .map(([name, value]) => ({ name, value }))
    : []

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Analytics</h1>
          <p className="text-sm text-gray-500 mt-1">Finding trends and agent performance</p>
        </div>
        <select
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white"
        >
          <option value={7}>Last 7 days</option>
          <option value={14}>Last 14 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
        </select>
      </div>

      {/* Summary KPIs */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: 'PRs Reviewed', value: summary.total_prs_reviewed },
            { label: 'Total Findings', value: summary.total_findings },
            {
              label: 'False Positive Rate',
              value: `${(summary.false_positive_rate * 100).toFixed(1)}%`,
            },
            {
              label: 'Avg Review Time',
              value: `${Math.round(summary.avg_review_duration_seconds)}s`,
            },
          ].map(({ label, value }) => (
            <div key={label} className="bg-white rounded-xl border border-gray-100 shadow-sm p-4">
              <div className="text-xs text-gray-500 font-medium">{label}</div>
              <div className="text-2xl font-bold text-gray-900 mt-1">{value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Charts grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Finding volume over time */}
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-5">
          <SectionTitle>Finding Volume Over Time</SectionTitle>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
              <XAxis
                dataKey="date"
                tick={{ fontSize: 10 }}
                tickFormatter={(v) => v.slice(5)} // Show MM-DD only
              />
              <YAxis tick={{ fontSize: 10 }} />
              <Tooltip />
              <Legend />
              {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
                <Line
                  key={sev}
                  type="monotone"
                  dataKey={sev}
                  stroke={SEVERITY_COLORS[sev]}
                  strokeWidth={2}
                  dot={false}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Severity breakdown pie */}
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-5">
          <SectionTitle>Severity Breakdown</SectionTitle>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={pieData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  label={({ name, percent }) =>
                    `${name} ${(percent * 100).toFixed(0)}%`
                  }
                  labelLine={false}
                >
                  {pieData.map((entry) => (
                    <Cell
                      key={entry.name}
                      fill={SEVERITY_COLORS[entry.name] || '#9ca3af'}
                    />
                  ))}
                </Pie>
                <Tooltip formatter={(value, name) => [value, name]} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[250px] flex items-center justify-center text-gray-400 text-sm">
              No data available
            </div>
          )}
        </div>

        {/* Top repos */}
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-5">
          <SectionTitle>Top Repositories by Findings</SectionTitle>
          {topRepos && topRepos.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={topRepos} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 10 }} />
                <YAxis
                  type="category"
                  dataKey="repo"
                  width={120}
                  tick={{ fontSize: 10 }}
                  tickFormatter={(v) => v.split('/')[1] || v}
                />
                <Tooltip />
                <Bar dataKey="finding_count" fill="#6366f1" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[250px] flex items-center justify-center text-gray-400 text-sm">
              No data available
            </div>
          )}
        </div>

        {/* Agent performance */}
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-5">
          <SectionTitle>Agent Performance</SectionTitle>
          {agentPerf && agentPerf.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-xs text-gray-500 border-b">
                    <th className="text-left py-2 font-medium">Agent</th>
                    <th className="text-right py-2 font-medium">Runs</th>
                    <th className="text-right py-2 font-medium">Avg Time</th>
                    <th className="text-right py-2 font-medium">Avg Findings</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {agentPerf.map((agent) => (
                    <tr key={agent.agent_type} className="hover:bg-gray-50">
                      <td className="py-2.5 font-medium text-gray-800">
                        {agent.agent_type.replace('_', ' ')}
                      </td>
                      <td className="py-2.5 text-right text-gray-600">{agent.run_count}</td>
                      <td className="py-2.5 text-right text-gray-600">
                        {agent.avg_duration_seconds.toFixed(1)}s
                      </td>
                      <td className="py-2.5 text-right text-gray-600">
                        {agent.avg_findings_per_run.toFixed(1)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="h-[200px] flex items-center justify-center text-gray-400 text-sm">
              No agent data available
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default MetricsDashboard
