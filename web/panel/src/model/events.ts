// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The router sends an event as a topic and its fields (SPEC §10); the panel writes the
// sentence. A topic this code does not know is shown as it came: a later part's event, or a
// newer router behind a page that was cached, is something that happened and is not dropped.

import type { Event } from '@openfeo/client'

import { clock, duration } from './format'

/** A piece of a sentence; `mono` marks what a machine produced (a name, an address). */
export interface Part {
  text: string
  mono?: boolean
}

const said = (text: string): Part => ({ text })
const machine = (text: string): Part => ({ text, mono: true })

function asItCame(topic: string, fields: Record<string, string>): Part[] {
  const parts = [machine(topic === '' ? '(no topic)' : topic)]
  for (const key of Object.keys(fields).sort()) {
    parts.push(said(' '), machine(`${key}=${fields[key] ?? ''}`))
  }
  return parts
}

function known(topic: string, fields: Record<string, string>): Part[] | null {
  const [family, name = '', ...rest] = topic.split('.')
  const what = rest.join('.')
  const field = (key: string) => fields[key] ?? ''
  if (family === 'health') {
    if (topic === 'health.ok') {
      return [said('The router is healthy again.')]
    }
    if (topic === 'health.degraded') {
      const unhealthy = field('unhealthy')
      return unhealthy === '' ? [said('The router is degraded.')] : [said('The router is degraded: '), machine(unhealthy), said('.')]
    }
    return null
  }
  if (name === '') {
    return null
  }
  if (family === 'wan') {
    switch (what) {
      case 'up':
        return [machine(name), said(' up.')]
      case 'down':
        return [machine(name), said(field('reason') === '' ? ' down.' : ` down: ${field('reason')}.`)]
      case 'addr':
      case 'prefix': {
        const value = field(what === 'addr' ? 'address' : 'prefix')
        if (value === '') {
          return null
        }
        if (field('change') === 'added') {
          return [machine(name), said(what === 'addr' ? ' has ' : ' was given '), machine(value), said('.')]
        }
        if (field('change') === 'withdrawn') {
          return [machine(name), said(' lost '), machine(value), said('.')]
        }
        return null
      }
      default:
        return null
    }
  }
  if (family === 'lan' && (what === 'lease.granted' || what === 'lease.released') && field('address') !== '') {
    // A client that gave no name is known by its hardware address.
    const who = field('host') !== '' ? field('host') : field('mac')
    const whom = who === '' ? said('a client') : machine(who)
    return what === 'lease.granted'
      ? [machine(name), said(' leased '), machine(field('address')), said(' to '), whom, said('.')]
      : [machine(name), said(' took back '), machine(field('address')), said(' from '), whom, said('.')]
  }
  return null
}

/** The sentence for an event, as parts to set in the text face or in mono. */
export function sentence(event: { topic: string; fields: Record<string, string> }): Part[] {
  return known(event.topic, event.fields) ?? asItCame(event.topic, event.fields)
}

/**
 * When an event happened, as the panel shows it: by the clock once the router's clock is
 * synced, and by the time since boot before that (until SNTP answers, the wall clock is only
 * the build's).
 */
export function when(event: Pick<Event, 'timeUnixMs' | 'uptimeMs'>, timeSynced: boolean, now: Date): string {
  return timeSynced ? clock(event.timeUnixMs, now) : `up ${duration(Number(event.uptimeMs / 1000n))}`
}
