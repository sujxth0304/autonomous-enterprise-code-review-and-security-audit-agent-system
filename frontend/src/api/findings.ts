/**
 * Findings API functions.
 */

import client from './client'
import type { Finding, FindingFeedbackPayload } from '../types'

export interface ListFindingsParams {
  severity?: string
  category?: string
  agent_type?: string
  false_positive?: boolean
  limit?: number
  offset?: number
}

export async function listFindings(params: ListFindingsParams = {}): Promise<Finding[]> {
  const { data } = await client.get<Finding[]>('/findings/', { params })
  return data
}

export async function getFinding(id: string): Promise<Finding> {
  const { data } = await client.get<Finding>(`/findings/${id}`)
  return data
}

export async function submitFeedback(id: string, feedback: FindingFeedbackPayload): Promise<Finding> {
  const { data } = await client.post<Finding>(`/findings/${id}/feedback`, feedback)
  return data
}
