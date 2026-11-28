// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The icons the components use: Lucide's (ISC), each one's shapes taken from its SVG file and
// drawn by OfoIcon at the design system's own stroke. The design system asks for the SVGs
// inlined, not an icon font, and only the ones used.

import circleAlert from 'lucide-static/icons/circle-alert.svg?raw'
import circleCheck from 'lucide-static/icons/circle-check.svg?raw'
import ethernetPort from 'lucide-static/icons/ethernet-port.svg?raw'
import fileText from 'lucide-static/icons/file-text.svg?raw'
import globe from 'lucide-static/icons/globe.svg?raw'
import info from 'lucide-static/icons/info.svg?raw'
import layoutDashboard from 'lucide-static/icons/layout-dashboard.svg?raw'
import logOut from 'lucide-static/icons/log-out.svg?raw'
import monitorSmartphone from 'lucide-static/icons/monitor-smartphone.svg?raw'
import moon from 'lucide-static/icons/moon.svg?raw'
import network from 'lucide-static/icons/network.svg?raw'
import route from 'lucide-static/icons/route.svg?raw'
import settings from 'lucide-static/icons/settings.svg?raw'
import shield from 'lucide-static/icons/shield.svg?raw'
import sun from 'lucide-static/icons/sun.svg?raw'
import text from 'lucide-static/icons/text.svg?raw'
import triangleAlert from 'lucide-static/icons/triangle-alert.svg?raw'

/** What is inside an SVG file's root element: its shapes, without the element's own attributes. */
function shapes(file: string): string {
  return /<svg[^>]*>([\s\S]*)<\/svg>/.exec(file)?.[1]?.trim() ?? ''
}

export const ICONS = {
  'circle-alert': shapes(circleAlert),
  'circle-check': shapes(circleCheck),
  'ethernet-port': shapes(ethernetPort),
  'file-text': shapes(fileText),
  globe: shapes(globe),
  info: shapes(info),
  'layout-dashboard': shapes(layoutDashboard),
  'log-out': shapes(logOut),
  'monitor-smartphone': shapes(monitorSmartphone),
  moon: shapes(moon),
  network: shapes(network),
  route: shapes(route),
  settings: shapes(settings),
  shield: shapes(shield),
  sun: shapes(sun),
  text: shapes(text),
  'triangle-alert': shapes(triangleAlert),
} as const

export type IconName = keyof typeof ICONS
