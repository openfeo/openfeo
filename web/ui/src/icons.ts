// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The icons the components use: Lucide's (ISC), each one's shapes taken from its SVG file and
// drawn by OfoIcon at the design system's own stroke. The design system asks for the SVGs
// inlined, not an icon font, and only the ones used.

import circleAlert from 'lucide-static/icons/circle-alert.svg?raw'
import circleCheck from 'lucide-static/icons/circle-check.svg?raw'
import info from 'lucide-static/icons/info.svg?raw'
import layoutDashboard from 'lucide-static/icons/layout-dashboard.svg?raw'
import logOut from 'lucide-static/icons/log-out.svg?raw'
import moon from 'lucide-static/icons/moon.svg?raw'
import sun from 'lucide-static/icons/sun.svg?raw'
import triangleAlert from 'lucide-static/icons/triangle-alert.svg?raw'

/** What is inside an SVG file's root element: its shapes, without the element's own attributes. */
function shapes(file: string): string {
  return /<svg[^>]*>([\s\S]*)<\/svg>/.exec(file)?.[1]?.trim() ?? ''
}

export const ICONS = {
  'circle-alert': shapes(circleAlert),
  'circle-check': shapes(circleCheck),
  info: shapes(info),
  'layout-dashboard': shapes(layoutDashboard),
  'log-out': shapes(logOut),
  moon: shapes(moon),
  sun: shapes(sun),
  'triangle-alert': shapes(triangleAlert),
} as const

export type IconName = keyof typeof ICONS
