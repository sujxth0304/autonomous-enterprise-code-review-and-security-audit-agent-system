/**
 * Pull Request API functions.
 */

import client from './client'
import type { AgentRun, Finding, PullRequest, TriggerReviewResponse } from '../types'

export interface ListPRsParams {
  status?: string
  repo?: string
  limit?: number
  offset?: number
}

export async function listPRs(params: ListPRsParams = {}): Promise<PullRequest[]> {
  const { data } = await client.get<PullRequest[]>('/prs/', { params })
  return data
}

export async function getPR(id: string): Promise<PullRequest> {
  const { data } = await client.get<PullRequest>(`/prs/${id}`)
  return data
}

export async function triggerReview(id: string): Promise<TriggerReviewResponse> {
  const { data } = await client.post<TriggerReviewResponse>(`/prs/${id}/trigger-review`)
  return data
}

export async function getPRFindings(
  id: string,
  params: { severity?: string; agent_type?: string } = {}
): Promise<Finding[]> {
  const { data } = await client.get<Finding[]>(`/prs/${id}/findings`, { params })
  return data
}

export async function getPRAgentRuns(id: string): Promise<AgentRun[]> {
  const { data } = await client.get<AgentRun[]>(`/prs/${id}/agent-runs`)
  return data
}
