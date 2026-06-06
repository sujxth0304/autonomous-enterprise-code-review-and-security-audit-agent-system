/**
 * SSE (Server-Sent Events) hook for streaming agent progress updates.
 */

import { useCallback, useEffect, useRef, useState } from 'react'

interface SSEEvent {
  type: string
  data: unknown
  timestamp: string
}

interface UseSSEOptions {
  onMessage?: (event: SSEEvent) => void
  onError?: (error: Event) => void
  reconnectInterval?: number
  maxReconnectAttempts?: number
}

interface UseSSEReturn {
  events: SSEEvent[]
  isConnected: boolean
  isConnecting: boolean
  error: string | null
  reconnectCount: number
  connect: (url: string) => void
  disconnect: () => void
  clearEvents: () => void
}

export function useSSE(options: UseSSEOptions = {}): UseSSEReturn {
  const {
    onMessage,
    onError,
    reconnectInterval = 3000,
    maxReconnectAttempts = 5,
  } = options

  const [events, setEvents] = useState<SSEEvent[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const [isConnecting, setIsConnecting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reconnectCount, setReconnectCount] = useState(0)

  const sourceRef = useRef<EventSource | null>(null)
  const urlRef = useRef<string | null>(null)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectAttemptsRef = useRef(0)

  const disconnect = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }
    if (sourceRef.current) {
      sourceRef.current.close()
      sourceRef.current = null
    }
    setIsConnected(false)
    setIsConnecting(false)
    reconnectAttemptsRef.current = 0
  }, [])

  const connect = useCallback((url: string) => {
    disconnect()
    urlRef.current = url
    reconnectAttemptsRef.current = 0
    setError(null)
    setIsConnecting(true)

    const source = new EventSource(url)
    sourceRef.current = source

    source.onopen = () => {
      setIsConnected(true)
      setIsConnecting(false)
      setError(null)
      reconnectAttemptsRef.current = 0
      setReconnectCount(0)
    }

    source.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data) as SSEEvent
        setEvents((prev) => [...prev, parsed])
        onMessage?.(parsed)
      } catch {
        // Raw string event
        const rawEvent: SSEEvent = {
          type: 'message',
          data: event.data,
          timestamp: new Date().toISOString(),
        }
        setEvents((prev) => [...prev, rawEvent])
        onMessage?.(rawEvent)
      }
    }

    source.onerror = (event) => {
      setIsConnected(false)
      setIsConnecting(false)
      onError?.(event)

      if (reconnectAttemptsRef.current < maxReconnectAttempts) {
        reconnectAttemptsRef.current += 1
        setReconnectCount(reconnectAttemptsRef.current)
        setError(`Connection lost. Reconnecting (${reconnectAttemptsRef.current}/${maxReconnectAttempts})...`)

        reconnectTimerRef.current = setTimeout(() => {
          if (urlRef.current) {
            setIsConnecting(true)
            const newSource = new EventSource(urlRef.current)
            sourceRef.current = newSource
          }
        }, reconnectInterval)
      } else {
        setError('Connection failed after maximum retry attempts')
        source.close()
      }
    }

    // Listen for specific event types
    source.addEventListener('agent_progress', (event) => {
      const sseEvent: SSEEvent = {
        type: 'agent_progress',
        data: JSON.parse((event as MessageEvent).data),
        timestamp: new Date().toISOString(),
      }
      setEvents((prev) => [...prev, sseEvent])
      onMessage?.(sseEvent)
    })

    source.addEventListener('finding_created', (event) => {
      const sseEvent: SSEEvent = {
        type: 'finding_created',
        data: JSON.parse((event as MessageEvent).data),
        timestamp: new Date().toISOString(),
      }
      setEvents((prev) => [...prev, sseEvent])
      onMessage?.(sseEvent)
    })

    source.addEventListener('review_complete', (event) => {
      const sseEvent: SSEEvent = {
        type: 'review_complete',
        data: JSON.parse((event as MessageEvent).data),
        timestamp: new Date().toISOString(),
      }
      setEvents((prev) => [...prev, sseEvent])
      onMessage?.(sseEvent)
      source.close()
      setIsConnected(false)
    })
  }, [disconnect, maxReconnectAttempts, onMessage, onError, reconnectInterval])

  const clearEvents = useCallback(() => {
    setEvents([])
  }, [])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      disconnect()
    }
  }, [disconnect])

  return {
    events,
    isConnected,
    isConnecting,
    error,
    reconnectCount,
    connect,
    disconnect,
    clearEvents,
  }
}
