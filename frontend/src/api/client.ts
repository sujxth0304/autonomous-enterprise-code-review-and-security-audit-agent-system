/**
 * Axios HTTP client with JWT interceptors and auto-refresh logic.
 */

import axios, { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const API_PREFIX = '/api/v1'

let isRefreshing = false
let refreshSubscribers: Array<(token: string) => void> = []

function subscribeTokenRefresh(callback: (token: string) => void) {
  refreshSubscribers.push(callback)
}

function onRefreshed(token: string) {
  refreshSubscribers.forEach((cb) => cb(token))
  refreshSubscribers = []
}

export function getStoredToken(): string | null {
  return localStorage.getItem('access_token')
}

export function setStoredToken(token: string): void {
  localStorage.setItem('access_token', token)
}

export function clearStoredToken(): void {
  localStorage.removeItem('access_token')
}

const client: AxiosInstance = axios.create({
  baseURL: `${API_BASE_URL}${API_PREFIX}`,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor: attach JWT token
client.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = getStoredToken()
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Response interceptor: handle 401 and refresh
client.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean }

    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        // Wait for the existing refresh to complete
        return new Promise((resolve) => {
          subscribeTokenRefresh((token: string) => {
            if (originalRequest.headers) {
              originalRequest.headers.Authorization = `Bearer ${token}`
            }
            resolve(client(originalRequest))
          })
        })
      }

      originalRequest._retry = true
      isRefreshing = true

      const currentToken = getStoredToken()
      if (!currentToken) {
        clearStoredToken()
        window.location.href = '/login'
        return Promise.reject(error)
      }

      try {
        const { data } = await axios.post(`${API_BASE_URL}${API_PREFIX}/auth/refresh`, null, {
          params: { token: currentToken },
        })
        const newToken = data.access_token
        setStoredToken(newToken)
        onRefreshed(newToken)

        if (originalRequest.headers) {
          originalRequest.headers.Authorization = `Bearer ${newToken}`
        }
        return client(originalRequest)
      } catch {
        clearStoredToken()
        window.location.href = '/login'
        return Promise.reject(error)
      } finally {
        isRefreshing = false
      }
    }

    return Promise.reject(error)
  }
)

export default client
