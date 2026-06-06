/**
 * React Query hooks for pull request data.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getPR, getPRAgentRuns, getPRFindings, listPRs, triggerReview } from '../api/prs'
import type { ListPRsParams } from '../api/prs'

export const PR_KEYS = {
  all: ['prs'] as const,
  lists: () => [...PR_KEYS.all, 'list'] as const,
  list: (params: ListPRsParams) => [...PR_KEYS.lists(), params] as const,
  details: () => [...PR_KEYS.all, 'detail'] as const,
  detail: (id: string) => [...PR_KEYS.details(), id] as const,
  findings: (id: string) => [...PR_KEYS.detail(id), 'findings'] as const,
  agentRuns: (id: string) => [...PR_KEYS.detail(id), 'agent-runs'] as const,
}

export function usePRList(params: ListPRsParams = {}) {
  return useQuery({
    queryKey: PR_KEYS.list(params),
    queryFn: () => listPRs(params),
    staleTime: 30_000, // 30 seconds
    refetchInterval: 60_000, // Refresh every minute
  })
}

export function usePR(id: string) {
  return useQuery({
    queryKey: PR_KEYS.detail(id),
    queryFn: () => getPR(id),
    enabled: !!id,
    staleTime: 15_000,
    refetchInterval: 30_000,
  })
}

export function usePRFindings(id: string, params: { severity?: string; agent_type?: string } = {}) {
  return useQuery({
    queryKey: [...PR_KEYS.findings(id), params],
    queryFn: () => getPRFindings(id, params),
    enabled: !!id,
    staleTime: 30_000,
  })
}

export function usePRAgentRuns(id: string) {
  return useQuery({
    queryKey: PR_KEYS.agentRuns(id),
    queryFn: () => getPRAgentRuns(id),
    enabled: !!id,
    staleTime: 10_000,
    refetchInterval: 15_000, // Poll agent runs every 15s while reviewing
  })
}

export function useTriggerReview() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: triggerReview,
    onSuccess: (_, prId) => {
      // Invalidate PR detail to refresh status
      queryClient.invalidateQueries({ queryKey: PR_KEYS.detail(prId) })
      queryClient.invalidateQueries({ queryKey: PR_KEYS.lists() })
    },
  })
}
