/**
 * Metrics API functions for analytics dashboard.
 */

import client from './client'
import type { AgentPerformance, FindingOverTimePoint, MetricsSummary, TopRepo } from '../types'

export async function getMetricsSummary(days: number = 7): Promise<MetricsSummary> {
  const { data } = await client.get<MetricsSummary>('/metrics/summary', { params: { days } })
  return data
}

export async function getFindingsOverTime(days: number = 30): Promise<FindingOverTimePoint[]> {
  const { data } = await client.get<FindingOverTimePoint[]>('/metrics/findings-over-time', {
    params: { days },
  })
  return data
}

export async function getTopRepos(days: number = 30, limit: number = 10): Promise<TopRepo[]> {
  const { data } = await client.get<TopRepo[]>('/metrics/top-repos', {
    params: { days, limit },
  })
  return data
}

export async function getAgentPerformance(days: number = 7): Promise<AgentPerformance[]> {
  const { data } = await client.get<AgentPerformance[]>('/metrics/agent-performance', {
    params: { days },
  })
  return data
}
