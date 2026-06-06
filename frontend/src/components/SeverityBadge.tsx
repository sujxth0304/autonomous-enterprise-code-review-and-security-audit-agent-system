/**
 * Color-coded severity badge component.
 */

import React from 'react'
import type { Severity } from '../types'

interface SeverityBadgeProps {
  severity: Severity
  size?: 'sm' | 'md' | 'lg'
  showIcon?: boolean
}

const SEVERITY_CONFIG: Record<
  Severity,
  { label: string; classes: string; icon: string }
> = {
  critical: {
    label: 'Critical',
    classes: 'bg-red-100 text-red-800 border-red-200',
    icon: '🔴',
  },
  high: {
    label: 'High',
    classes: 'bg-orange-100 text-orange-800 border-orange-200',
    icon: '🟠',
  },
  medium: {
    label: 'Medium',
    classes: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    icon: '🟡',
  },
  low: {
    label: 'Low',
    classes: 'bg-green-100 text-green-800 border-green-200',
    icon: '🟢',
  },
  info: {
    label: 'Info',
    classes: 'bg-blue-100 text-blue-800 border-blue-200',
    icon: '🔵',
  },
}

const SIZE_CLASSES = {
  sm: 'text-xs px-1.5 py-0.5',
  md: 'text-sm px-2 py-1',
  lg: 'text-base px-3 py-1.5',
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  showIcon = true,
}) => {
  const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border font-medium ${config.classes} ${SIZE_CLASSES[size]}`}
    >
      {showIcon && <span className="text-xs">{config.icon}</span>}
      {config.label}
    </span>
  )
}

export default SeverityBadge
