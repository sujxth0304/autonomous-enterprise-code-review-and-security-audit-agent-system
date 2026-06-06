/**
 * Root application component with routing setup.
 */

import React, { Suspense } from 'react'
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BarChart3, Home, List, Search, Shield } from 'lucide-react'
import { Dashboard } from './components/Dashboard'
import { PRDetail } from './components/PRDetail'
import { FindingsTable } from './components/FindingsTable'
import { MetricsDashboard } from './components/MetricsDashboard'
import { usePRList } from './hooks/usePRs'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      staleTime: 30_000,
    },
  },
})

// Simple PR list page
function PRListPage() {
  const { data: prs, isLoading } = usePRList({ limit: 50 })

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-gray-900">Pull Requests</h1>
      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 10 }).map((_, i) => (
            <div key={i} className="animate-pulse h-16 bg-gray-100 rounded-lg" />
          ))}
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
          {!prs?.length ? (
            <div className="p-8 text-center text-gray-400">No pull requests found</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-xs text-gray-500">
                  <th className="text-left px-5 py-3 font-medium">PR</th>
                  <th className="text-left px-4 py-3 font-medium">Author</th>
                  <th className="text-left px-4 py-3 font-medium">Status</th>
                  <th className="text-left px-4 py-3 font-medium">Risk</th>
                  <th className="text-left px-4 py-3 font-medium">Created</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {prs.map((pr) => (
                  <tr key={pr.id} className="hover:bg-gray-50">
                    <td className="px-5 py-3">
                      <Link to={`/prs/${pr.id}`} className="block">
                        <div className="text-xs text-gray-400 font-mono">
                          {pr.repo_full_name}#{pr.pr_number}
                        </div>
                        <div className="font-medium text-gray-900 truncate max-w-md">{pr.title}</div>
                      </Link>
                    </td>
                    <td className="px-4 py-3 text-gray-600">{pr.author}</td>
                    <td className="px-4 py-3">
                      <span className="text-xs px-2 py-0.5 bg-gray-100 rounded-full">{pr.status}</span>
                    </td>
                    <td className="px-4 py-3 font-mono text-sm">
                      {pr.risk_score !== null ? pr.risk_score.toFixed(2) : '—'}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {new Date(pr.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: Home, exact: true },
  { to: '/prs', label: 'PRs', icon: List },
  { to: '/findings', label: 'Findings', icon: Search },
  { to: '/metrics', label: 'Analytics', icon: BarChart3 },
]

function NavLink({
  to,
  label,
  icon: Icon,
  exact = false,
}: {
  to: string
  label: string
  icon: React.ElementType
  exact?: boolean
}) {
  const location = useLocation()
  const isActive = exact ? location.pathname === to : location.pathname.startsWith(to)

  return (
    <Link
      to={to}
      className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
        isActive
          ? 'bg-blue-50 text-blue-700'
          : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'
      }`}
    >
      <Icon className="w-4 h-4" />
      {label}
    </Link>
  )
}

function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Sidebar */}
      <div className="fixed inset-y-0 left-0 w-56 bg-white border-r border-gray-200 flex flex-col">
        {/* Logo */}
        <div className="px-5 py-4 border-b border-gray-100">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 bg-blue-600 rounded-lg flex items-center justify-center">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <div>
              <div className="font-semibold text-gray-900 text-sm">Code Review</div>
              <div className="text-xs text-gray-400">Agent System</div>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV_ITEMS.map((item) => (
            <NavLink key={item.to} {...item} />
          ))}
        </nav>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-gray-100">
          <div className="text-xs text-gray-400">v0.1.0 · Powered by Gemini</div>
        </div>
      </div>

      {/* Main content */}
      <div className="ml-56">
        <main className="max-w-6xl mx-auto px-6 py-8">{children}</main>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Layout>
          <Suspense fallback={<div className="animate-pulse">Loading...</div>}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/prs" element={<PRListPage />} />
              <Route path="/prs/:id" element={<PRDetail />} />
              <Route path="/findings" element={<FindingsTable />} />
              <Route path="/metrics" element={<MetricsDashboard />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </Layout>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
