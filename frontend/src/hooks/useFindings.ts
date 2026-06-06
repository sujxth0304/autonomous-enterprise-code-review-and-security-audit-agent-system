/**
 * React Query hooks for findings data.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getFinding, listFindings, submitFeedback } from '../api/findings'
import type { ListFindingsParams } from '../api/findings'
import type { FindingFeedbackPayload } from '../types'

export const FINDING_KEYS = {
  all: ['findings'] as const,
  lists: () => [...FINDING_KEYS.all, 'list'] as const,
  list: (params: ListFindingsParams) => [...FINDING_KEYS.lists(), params] as const,
  details: () => [...FINDING_KEYS.all, 'detail'] as const,
  detail: (id: string) => [...FINDING_KEYS.details(), id] as const,
}

export function useFindingsList(params: ListFindingsParams = {}) {
  return useQuery({
    queryKey: FINDING_KEYS.list(params),
    queryFn: () => listFindings(params),
    staleTime: 30_000,
  })
}

export function useFinding(id: string) {
  return useQuery({
    queryKey: FINDING_KEYS.detail(id),
    queryFn: () => getFinding(id),
    enabled: !!id,
    staleTime: 60_000,
  })
}

export function useSubmitFeedback() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, feedback }: { id: string; feedback: FindingFeedbackPayload }) =>
      submitFeedback(id, feedback),
    onSuccess: (updatedFinding) => {
      // Update the finding in cache
      queryClient.setQueryData(FINDING_KEYS.detail(updatedFinding.id), updatedFinding)
      // Invalidate lists to refresh
      queryClient.invalidateQueries({ queryKey: FINDING_KEYS.lists() })
    },
  })
}
