// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { mount } from '@vue/test-utils'
import { expect, test } from 'vitest'

import {
  OfoBanner,
  OfoButton,
  OfoCard,
  OfoChart,
  OfoDataTable,
  OfoEmpty,
  OfoField,
  OfoIcon,
  OfoInput,
  OfoInterfaceCard,
  OfoNav,
  OfoPageHeader,
  OfoPortStrip,
  OfoSegmented,
  OfoShell,
  OfoSkeleton,
  OfoStatTile,
  OfoStatusPill,
  OfoThemeSwitch,
  OfoWordmark,
  sparkPath,
} from '../src/index'

// Each component is the markup its guideline in docs/components/ gives for the stylesheet's
// classes; these check that markup and what each does beyond it.

test('a button is a button with its variant and size, and an icon before its label', () => {
  const plain = mount(OfoButton, { slots: { default: 'Discard' } })
  expect(plain.element.tagName).toBe('BUTTON')
  expect(plain.classes()).toEqual(['ofo-btn'])
  expect(plain.attributes('type')).toBe('button')
  expect(plain.text()).toBe('Discard')

  const primary = mount(OfoButton, {
    props: { variant: 'primary', size: 'sm', type: 'submit', icon: 'log-out' },
    slots: { default: 'Log out' },
  })
  expect(primary.classes()).toEqual(['ofo-btn', 'ofo-btn--primary', 'ofo-btn--sm'])
  expect(primary.attributes('type')).toBe('submit')
  expect(primary.element.firstElementChild?.tagName.toLowerCase()).toBe('svg')

  const off = mount(OfoButton, { props: { disabled: true } })
  expect((off.element as HTMLButtonElement).disabled).toBe(true)
})

test('a field labels its control and shows its help', () => {
  const field = mount(OfoField, {
    props: { label: 'New password', help: '12 characters or more.' },
    slots: { default: '<input class="ofo-input">' },
  })
  expect(field.element.tagName).toBe('LABEL')
  expect(field.classes()).toEqual(['ofo-field'])
  expect(field.find('.ofo-field__label').text()).toBe('New password')
  expect(field.find('.ofo-field__help').text()).toBe('12 characters or more.')
  expect(field.find('input').exists()).toBe(true)
})

test('a field with an error shows it in place of the help and marks itself', () => {
  const field = mount(OfoField, {
    props: { label: 'Password', help: '12 characters or more.', error: 'Wrong password.' },
  })
  expect(field.classes()).toContain('ofo-field--error')
  expect(field.findAll('.ofo-field__help')).toHaveLength(1)
  expect(field.find('.ofo-field__help').text()).toBe('Wrong password.')
  expect(field.text()).not.toContain('12 characters or more.')
  expect(field.find('.ofo-field__help').attributes('role')).toBe('alert')
})

test('an input carries its value both ways, and is mono when a machine reads it', async () => {
  const input = mount(OfoInput, { props: { modelValue: 'abc', type: 'password', autocomplete: 'new-password' } })
  expect(input.classes()).toEqual(['ofo-input'])
  expect((input.element as HTMLInputElement).value).toBe('abc')
  expect(input.attributes('type')).toBe('password')
  expect(input.attributes('autocomplete')).toBe('new-password')
  await input.setValue('  spaced out  ')
  expect(input.emitted('update:modelValue')?.at(-1)).toEqual(['  spaced out  '])
  expect(mount(OfoInput, { props: { modelValue: '', mono: true } }).classes()).toContain('ofo-input--mono')
})

test('a card has its title and its actions in its head', () => {
  const card = mount(OfoCard, {
    props: { title: 'Ports' },
    slots: { default: '<p>body</p>', actions: '<button>All logs</button>' },
  })
  expect(card.classes()).toEqual(['ofo-card'])
  expect(card.find('.ofo-card__head .ofo-card__title').text()).toBe('Ports')
  expect(card.find('.ofo-card__head button').text()).toBe('All logs')
  expect(card.find('p').text()).toBe('body')
  expect(mount(OfoCard, { slots: { default: 'x' } }).find('.ofo-card__head').exists()).toBe(false)
})

test('a page header has its title, one line beneath, and actions on the right', () => {
  const header = mount(OfoPageHeader, {
    props: { title: 'Dashboard', sub: 'wan0 up since 7 Nov 09:14' },
    slots: { actions: '<button>Reload</button>' },
  })
  expect(header.element.tagName).toBe('HEADER')
  expect(header.classes()).toEqual(['ofo-pagehead'])
  expect(header.find('h1.ofo-pagehead__title').text()).toBe('Dashboard')
  expect(header.find('.ofo-pagehead__sub').text()).toBe('wan0 up since 7 Nov 09:14')
  expect(header.find('.ofo-pagehead__actions button').exists()).toBe(true)
  const bare = mount(OfoPageHeader, { props: { title: 'Logs' } })
  expect(bare.find('.ofo-pagehead__sub').exists()).toBe(false)
  expect(bare.find('.ofo-pagehead__actions').exists()).toBe(false)
})

test('a status pill is its word with its tone', () => {
  const up = mount(OfoStatusPill, { props: { tone: 'ok' }, slots: { default: 'Up' } })
  expect(up.classes()).toEqual(['ofo-pill', 'ofo-pill--ok'])
  expect(up.text()).toBe('Up')
  expect(mount(OfoStatusPill, { slots: { default: 'No link' } }).classes()).toEqual(['ofo-pill'])
})

test('a danger banner is an alert, the others are a status', () => {
  const lost = mount(OfoBanner, {
    props: { tone: 'danger', title: 'Connection lost' },
    slots: { default: 'Retrying.', action: '<button>Retry now</button>' },
  })
  expect(lost.classes()).toEqual(['ofo-banner', 'ofo-banner--danger'])
  expect(lost.attributes('role')).toBe('alert')
  expect(lost.find('svg.ofo-banner__icon').exists()).toBe(true)
  expect(lost.find('.ofo-banner__body .ofo-banner__title').text()).toBe('Connection lost')
  expect(lost.find('.ofo-banner__body').text()).toContain('Retrying.')
  expect(lost.find('button').text()).toBe('Retry now')
  for (const tone of ['info', 'ok', 'warn'] as const) {
    const banner = mount(OfoBanner, { props: { tone } })
    expect(banner.attributes('role'), tone).toBe('status')
    expect(banner.classes(), tone).toContain(`ofo-banner--${tone}`)
  }
})

test('a skeleton is a bar of the size and width asked for, and says nothing', () => {
  const bar = mount(OfoSkeleton, { props: { size: 'lg', width: 60 } })
  expect(bar.classes()).toEqual(['ofo-skel', 'ofo-skel--lg', 'ofo-skel--w60'])
  expect(bar.attributes('aria-hidden')).toBe('true')
  expect(mount(OfoSkeleton).classes()).toEqual(['ofo-skel'])
})

test('a stat tile shows its number with its unit, and a foot or a sparkline', () => {
  const clients = mount(OfoStatTile, { props: { label: 'Clients', value: '14', foot: '11 on lan0 · 3 on iot' } })
  expect(clients.classes()).toEqual(['ofo-stat'])
  expect(clients.find('.ofo-stat__label').text()).toBe('Clients')
  expect(clients.find('.ofo-stat__value').text()).toBe('14')
  expect(clients.find('.ofo-stat__unit').exists()).toBe(false)
  expect(clients.find('.ofo-stat__foot').text()).toBe('11 on lan0 · 3 on iot')
  expect(clients.find('svg').exists()).toBe(false)

  const down = mount(OfoStatTile, {
    props: { label: 'Download', value: '412.6', unit: 'Mbit/s', spark: [1, 2, 3], series: 1 },
  })
  expect(down.find('.ofo-stat__value').text()).toBe('412.6Mbit/s')
  expect(down.find('.ofo-stat__unit').text()).toBe('Mbit/s')
  const spark = down.find('svg.ofo-stat__spark')
  expect(spark.classes()).toContain('ofo-spark--s1')
  expect(spark.attributes('viewBox')).toBe('0 0 180 28')
  expect(spark.find('path').attributes('d')).toBe(sparkPath([1, 2, 3]))
  const up = mount(OfoStatTile, { props: { label: 'Upload', value: '38.2', unit: 'Mbit/s', spark: [], series: 2 } })
  expect(up.find('svg.ofo-stat__spark').classes()).toContain('ofo-spark--s2')
})

test('a sparkline has one point per sample and no NaN, for one sample and for all zeros', () => {
  expect(sparkPath([])).toBe('')
  for (const samples of [[5], [0, 0, 0], Array.from({ length: 60 }, (_, i) => i), [3, Number.NaN, Number.POSITIVE_INFINITY, -4]]) {
    const path = sparkPath(samples)
    expect(path, String(samples)).not.toMatch(/NaN|Infinity/)
    expect(path.match(/[ML]/g), String(samples)).toHaveLength(Math.max(samples.length, 2))
    for (const [, x, y] of path.matchAll(/[ML]([\d.]+) ([\d.]+)/g)) {
      expect(Number(x)).toBeGreaterThanOrEqual(0)
      expect(Number(x)).toBeLessThanOrEqual(180)
      expect(Number(y)).toBeGreaterThanOrEqual(0)
      expect(Number(y)).toBeLessThanOrEqual(28)
    }
  }
  // The largest sample is at the top, a zero at the bottom, the first at the left edge.
  expect(sparkPath([0, 10])).toBe('M0 26 L180 2')
  // One sample is a level line across the tile.
  expect(sparkPath([7])).toBe('M0 2 L180 2')
})

const card = {
  name: 'wan0',
  role: 'WAN · PPPoE',
  status: { word: 'Up', tone: 'ok' as const },
  facts: [
    { key: 'IPv4', value: '203.0.113.100' },
    { key: 'Prefix', value: '2001:db8:1::/48' },
    { key: 'Interface', value: 'ppp-wan0 on p0.911' },
  ],
  rates: { rx: { value: '412.6', unit: 'Mbit/s' }, tx: { value: '38.2', unit: 'Mbit/s' } },
}

test('an interface card shows its name, role, state, facts and rates', () => {
  const iface = mount(OfoInterfaceCard, { props: { ...card, active: true } })
  expect(iface.classes()).toEqual(['ofo-iface', 'ofo-iface--active'])
  expect(iface.find('.ofo-iface__head .ofo-iface__name').text()).toBe('wan0')
  expect(iface.find('.ofo-iface__role').text()).toBe('WAN · PPPoE')
  expect(iface.find('.ofo-iface__head .ofo-pill--ok').text()).toBe('Up')
  expect(iface.findAll('dl.ofo-iface__kv dt').map((dt) => dt.text())).toEqual(['IPv4', 'Prefix', 'Interface'])
  expect(iface.findAll('dl.ofo-iface__kv dd')[2]?.text()).toBe('ppp-wan0 on p0.911')
  // A number and its unit do not part at a line's end: the space between them does not break.
  expect(iface.find('.ofo-iface__rx').text()).toBe('↓ 412.6\u00a0Mbit/s')
  expect(iface.find('.ofo-iface__tx').text()).toBe('↑ 38.2\u00a0Mbit/s')
  expect(mount(OfoInterfaceCard, { props: card }).classes()).toEqual(['ofo-iface'])
})

test('an interface card with no rates shows a dash, not a number', () => {
  const iface = mount(OfoInterfaceCard, { props: { ...card, rates: null } })
  expect(iface.find('.ofo-iface__rx').text()).toBe('↓ —')
  expect(iface.find('.ofo-iface__tx').text()).toBe('↑ —')
})

test('at most five facts are shown', () => {
  const facts = Array.from({ length: 7 }, (_, i) => ({ key: `Fact ${i}`, value: String(i) }))
  const iface = mount(OfoInterfaceCard, { props: { ...card, facts } })
  expect(iface.findAll('dt')).toHaveLength(5)
  expect(iface.findAll('dt').at(-1)?.text()).toBe('Fact 4')
})

test('a port says its speed in words as well as light', () => {
  const strip = mount(OfoPortStrip, {
    props: {
      ports: [
        { name: 'p0', speed: '2.5G', wan: true, up: true, title: 'p0 · 52:54:00:12:34:00 · WAN wan0, VLAN 911' },
        { name: 'p2', speed: '—', wan: false, up: false, title: 'p2 · lan0' },
      ],
    },
  })
  expect(strip.classes()).toEqual(['ofo-ports'])
  expect(strip.attributes('role')).toBe('list')
  const ports = strip.findAll('.ofo-port')
  expect(ports).toHaveLength(2)
  expect(ports[0]?.classes()).toEqual(['ofo-port', 'ofo-port--wan', 'ofo-port--up'])
  expect(ports[0]?.attributes('title')).toBe('p0 · 52:54:00:12:34:00 · WAN wan0, VLAN 911')
  expect(ports[0]?.find('.ofo-port__jack').exists()).toBe(true)
  expect(ports[0]?.find('.ofo-port__name').text()).toBe('p0')
  expect(ports[0]?.find('.ofo-port__speed').text()).toBe('2.5G')
  expect(ports[1]?.classes()).toEqual(['ofo-port'])
  expect(ports[1]?.find('.ofo-port__speed').text()).toBe('—')
})

test('a table has its headers, its cells typed for machines and numbers, and a slot per cell', () => {
  const table = mount(OfoDataTable, {
    props: {
      columns: [
        { key: 'interface', label: 'Interface', mono: true },
        { key: 'address', label: 'Address', mono: true },
        { key: 'leases', label: 'Leases', num: true },
        { key: 'from', label: 'From' },
      ],
      rows: [
        { interface: 'br-lan0', address: '192.168.1.1/24', leases: '11', from: 'Config' },
        { interface: '', address: 'fd12:3456:789a:1::1/64', leases: '0', from: 'ULA' },
      ],
    },
    slots: { 'cell-from': '<template #cell-from="{ value }"><em>{{ value }}</em></template>' },
  })
  expect(table.classes()).toEqual(['ofo-table-wrap'])
  expect(table.find('table').classes()).toEqual(['ofo-table'])
  expect(table.findAll('thead th').map((th) => th.text())).toEqual(['Interface', 'Address', 'Leases', 'From'])
  expect(table.findAll('thead th')[2]?.classes()).toContain('ofo-num')
  const first = table.findAll('tbody tr')[0]?.findAll('td') ?? []
  expect(first[0]?.classes()).toEqual(['ofo-mono'])
  expect(first[1]?.text()).toBe('192.168.1.1/24')
  expect(first[2]?.classes()).toEqual(['ofo-num'])
  expect(first[3]?.find('em').text()).toBe('Config')
  expect(table.findAll('tbody tr')).toHaveLength(2)
  const headless = mount(OfoDataTable, { props: { columns: [{ key: 'a', label: 'A' }], rows: [{ a: '1' }], head: false } })
  expect(headless.find('thead').exists()).toBe(false)
})

test('the shell is the nav beside a top bar and the page', () => {
  const shell = mount(OfoShell, {
    props: { host: 'openfeo.home.arpa', meta: '0.4.0 · up 3d 4h' },
    slots: { nav: '<nav class="ofo-nav" />', actions: '<button>Log out</button>', default: '<p>the page</p>' },
  })
  expect(shell.classes()).toEqual(['ofo-shell'])
  // The stylesheet's narrow layout needs the nav as the shell's own child.
  expect(shell.element.firstElementChild?.classList.contains('ofo-nav')).toBe(true)
  expect(shell.find('.ofo-shell__main > .ofo-topbar .ofo-topbar__host').text()).toBe('openfeo.home.arpa')
  expect(shell.find('.ofo-topbar__meta').text()).toBe('0.4.0 · up 3d 4h')
  expect(shell.find('.ofo-topbar__end button').text()).toBe('Log out')
  expect(shell.find('.ofo-shell__main > .ofo-shell__content p').text()).toBe('the page')
})

test('the current nav item is marked for assistive tech, and a click navigates without leaving', async () => {
  const nav = mount(OfoNav, {
    props: {
      entries: [
        { kind: 'item', label: 'Dashboard', icon: 'layout-dashboard', to: '/', current: true },
        { kind: 'group', label: 'Network' },
        { kind: 'item', label: 'WAN', icon: 'info', to: '/wan', current: false },
      ],
    },
    attachTo: document.body,
  })
  expect(nav.element.tagName).toBe('NAV')
  expect(nav.classes()).toEqual(['ofo-nav'])
  expect(nav.find('.ofo-nav__brand .ofo-nav__word img').exists()).toBe(true)
  expect(nav.find('.ofo-nav__brand .ofo-nav__mark img').exists()).toBe(true)
  expect(nav.find('.ofo-nav__group').text()).toBe('Network')
  const items = nav.findAll('a.ofo-nav__item')
  expect(items.map((item) => item.find('.ofo-nav__label').text())).toEqual(['Dashboard', 'WAN'])
  expect(items[0]?.attributes('aria-current')).toBe('page')
  expect(items[1]?.attributes('aria-current')).toBeUndefined()
  expect(items[1]?.attributes('href')).toBe('/wan')
  expect(items[0]?.find('svg').exists()).toBe(true)

  const click = new MouseEvent('click', { bubbles: true, cancelable: true })
  items[1]?.element.dispatchEvent(click)
  await nav.vm.$nextTick()
  expect(click.defaultPrevented).toBe(true)
  expect(nav.emitted('navigate')).toEqual([['/wan']])
  nav.unmount()
})

test('the theme switch asks for the other theme and names what it will do', async () => {
  const dark = mount(OfoThemeSwitch, { props: { theme: 'dark' } })
  expect(dark.attributes('aria-label')).toBe('Use light theme')
  await dark.trigger('click')
  expect(dark.emitted('change')).toEqual([['light']])
  const light = mount(OfoThemeSwitch, { props: { theme: 'light' } })
  expect(light.attributes('aria-label')).toBe('Use dark theme')
  await light.trigger('click')
  expect(light.emitted('change')).toEqual([['dark']])
  expect(dark.classes()).toEqual(['ofo-btn', 'ofo-btn--sm', 'ofo-btn--ghost'])
})

test('an icon is drawn at the design system’s stroke and says nothing', () => {
  const icon = mount(OfoIcon, { props: { name: 'sun' } })
  expect(icon.element.tagName.toLowerCase()).toBe('svg')
  expect(icon.attributes('viewBox')).toBe('0 0 24 24')
  expect(icon.attributes('stroke-width')).toBe('1.75')
  expect(icon.attributes('stroke')).toBe('currentColor')
  expect(icon.attributes('aria-hidden')).toBe('true')
  expect(icon.element.childElementCount).toBeGreaterThan(0)
  expect(icon.html()).not.toContain('lucide')
})

test('the wordmark offers both files and lets the stylesheet pick', () => {
  const word = mount(OfoWordmark)
  const images = word.findAll('img')
  expect(images.map((img) => img.classes())).toEqual([['ofo-on-dark'], ['ofo-on-light']])
  expect(images.map((img) => img.attributes('alt'))).toEqual(['OpenFeO', 'OpenFeO'])
  expect(images[0]?.attributes('src')).toContain('openfeo-wordmark-on-dark')
  expect(images[1]?.attributes('src')).toContain('openfeo-wordmark-on-light')
  const mark = mount(OfoWordmark, { props: { variant: 'mark', height: 20 } })
  expect(mark.findAll('img')[0]?.attributes('src')).toContain('openfeo-mark')
  expect(mark.findAll('img')[1]?.attributes('src')).toContain('openfeo-mark-light')
  expect(mark.findAll('img')[0]?.attributes('height')).toBe('20')
})

test('a stat tile with a sparkline and a foot shows both, the line above', () => {
  const down = mount(OfoStatTile, {
    props: { label: 'Download', value: '412.6', unit: 'Mbit/s', spark: [1, 2, 3], series: 1, foot: 'peak 918.2 Mbit/s in the last hour' },
  })
  expect(down.find('svg.ofo-stat__spark').exists()).toBe(true)
  expect(down.find('.ofo-stat__foot').text()).toBe('peak 918.2 Mbit/s in the last hour')
  expect(down.element.lastElementChild?.className).toBe('ofo-stat__foot')
})

test('a table keys its rows and classes them as it is told', () => {
  const table = mount(OfoDataTable, {
    props: {
      columns: [{ key: 'address', label: 'Address', mono: true }],
      rows: [
        { id: 'a', address: '192.168.1.143', fresh: 'yes' },
        { id: 'b', address: '192.168.1.142', fresh: '' },
      ],
      rowKey: 'id',
      rowClass: (row: Record<string, string>) => (row.fresh === 'yes' ? 'ofo-table__row--new' : undefined),
    },
  })
  const rows = table.findAll('tbody tr')
  expect(rows[0]?.classes()).toEqual(['ofo-table__row--new'])
  expect(rows[1]?.classes()).toEqual([])
})

test('a table with no rows says what its `empty` slot says, across every column', () => {
  const columns = [
    { key: 'address', label: 'Address' },
    { key: 'name', label: 'Name' },
  ]
  const none = mount(OfoDataTable, { props: { columns, rows: [] }, slots: { empty: 'No leases match <code>zzz</code>' } })
  const cell = none.find('tbody tr td')
  expect(none.findAll('tbody tr')).toHaveLength(1)
  expect(cell.attributes('colspan')).toBe('2')
  expect(cell.text()).toBe('No leases match zzz')
  // With rows, or with nothing to say, there is no such row.
  expect(mount(OfoDataTable, { props: { columns, rows: [] } }).findAll('tbody tr')).toHaveLength(0)
  const some = mount(OfoDataTable, { props: { columns, rows: [{ address: 'a', name: 'b' }] }, slots: { empty: 'nothing' } })
  expect(some.findAll('tbody tr')).toHaveLength(1)
  expect(some.text()).not.toContain('nothing')
})

test('a segmented choice is a group of buttons with the chosen one pressed, and a count where given', async () => {
  const choice = mount(OfoSegmented, {
    props: {
      label: 'LAN',
      modelValue: 'all',
      options: [
        { value: 'all', label: 'All LANs' },
        { value: 'lan0', label: 'lan0', count: 11 },
        { value: 'iot', label: 'iot', count: 0 },
      ],
    },
  })
  expect(choice.classes()).toEqual(['ofo-seg'])
  expect(choice.attributes('role')).toBe('group')
  expect(choice.attributes('aria-label')).toBe('LAN')
  const buttons = choice.findAll('button')
  expect(buttons.map((button) => button.attributes('aria-pressed'))).toEqual(['true', 'false', 'false'])
  expect(buttons.every((button) => button.attributes('type') === 'button')).toBe(true)
  expect(buttons[0]?.find('.ofo-tabs__count').exists()).toBe(false)
  expect(buttons[1]?.find('.ofo-tabs__count').text()).toBe('11')
  expect(buttons[2]?.find('.ofo-tabs__count').text()).toBe('0')
  await buttons[1]?.trigger('click')
  expect(choice.emitted('update:modelValue')).toEqual([['lan0']])
  await choice.setProps({ modelValue: 'lan0' })
  expect(choice.findAll('button').map((button) => button.attributes('aria-pressed'))).toEqual(['false', 'true', 'false'])
})

test('an empty state has the lattice, what is missing, one line, and its action', () => {
  const empty = mount(OfoEmpty, {
    props: { title: 'No leases yet', text: 'A device appears here when it takes an address.' },
    slots: { default: '<button class="ofo-btn">Add</button>' },
  })
  expect(empty.classes()).toEqual(['ofo-empty'])
  const art = empty.find('svg.ofo-empty__art')
  expect(art.attributes('aria-hidden')).toBe('true')
  expect(art.findAll('circle.fe')).toHaveLength(5)
  expect(art.findAll('circle.o')).toHaveLength(4)
  expect(empty.find('.ofo-empty__title').text()).toBe('No leases yet')
  expect(empty.find('.ofo-empty__text').text()).toBe('A device appears here when it takes an address.')
  expect(empty.find('button.ofo-btn').exists()).toBe(true)
  const bare = mount(OfoEmpty, { props: { title: 'Nothing' } })
  expect(bare.find('.ofo-empty__text').exists()).toBe(false)
})

test('a chart is a picture with a name, a legend of what is now, a grid, and its marks', () => {
  const chart = mount(OfoChart, {
    props: {
      title: 'wan0',
      label: 'Download and upload on wan0 over the last hour',
      runs: [
        [
          { at: 0, rx: 100, tx: 10 },
          { at: 1800, rx: 400, tx: 40 },
        ],
        [{ at: 3000, rx: 918.2, tx: 104 }, { at: 3600, rx: 412.6, tx: 38.2 }],
      ],
      from: 0,
      to: 3600,
      unit: 'Mbit/s',
      now: { rx: '412.6', tx: '38.2' },
      marks: [{ at: 2900, label: 'reconnected 14:12' }],
      ticks: [
        { at: 0, label: '13:20' },
        { at: 1800, label: '13:50' },
      ],
    },
    slots: { range: '<div class="ofo-seg">range</div>' },
  })
  expect(chart.classes()).toEqual(['ofo-chart'])
  expect(chart.find('.ofo-chart__head h2').text()).toBe('wan0')
  expect(chart.find('.ofo-chart__head .ofo-seg').text()).toBe('range')
  expect(chart.find('.ofo-chart__key--rx').text()).toBe('Download 412.6 Mbit/s')
  expect(chart.find('.ofo-chart__key--rx b').text()).toBe('412.6')
  expect(chart.find('.ofo-chart__key--tx').text()).toBe('Upload 38.2 Mbit/s')
  const svg = chart.find('.ofo-chart__plot svg')
  expect(svg.attributes('role')).toBe('img')
  expect(svg.attributes('aria-label')).toBe('Download and upload on wan0 over the last hour')
  expect(svg.attributes('viewBox')).toBe('0 0 720 220')
  expect(svg.findAll('g.grid line')).toHaveLength(5)
  // The scale's top is the round value above the largest point, and each level is said.
  expect(svg.findAll('g.axis text.ofo-chart__level').map((text) => text.text())).toEqual(['0', '250', '500', '750', '1000'])
  expect(svg.findAll('g.axis text.ofo-chart__tick').map((text) => text.text())).toEqual(['13:20', '13:50'])
  expect(svg.find('path.line.rx').attributes('d')).toMatch(/^M0 [\d.]+ L336 [\d.]+ M560 [\d.]+ L672 [\d.]+$/)
  expect(svg.find('path.line.tx').attributes('d')).toMatch(/^M0 /)
  expect(svg.find('path.area.rx').attributes('d')).toMatch(/Z$/)
  const events = svg.findAll('g.event')
  expect(events).toHaveLength(1)
  expect(events[0]?.find('text').text()).toBe('reconnected 14:12')
  expect(events[0]?.find('line').attributes('x1')).toBe(events[0]?.find('line').attributes('x2'))
  expect(chart.find('.ofo-chart__note').exists()).toBe(false)
  expect(chart.html()).not.toMatch(/style=/)
})

test('a chart with nothing to draw still has its scale, and says what it was told to', () => {
  const chart = mount(OfoChart, {
    props: {
      title: 'wan1',
      label: 'Download and upload on wan1 over the last five minutes',
      runs: [],
      from: 0,
      to: 300,
      unit: 'bit/s',
      now: { rx: '–', tx: '–' },
      note: 'The last hour could not be read from the router.',
    },
  })
  expect(chart.find('.ofo-chart__note').text()).toBe('The last hour could not be read from the router.')
  expect(chart.findAll('g.grid line')).toHaveLength(5)
  expect(chart.find('path.line.rx').attributes('d')).toBe('')
  expect(chart.findAll('g.event')).toHaveLength(0)
  expect(chart.find('.ofo-chart__key--rx').text()).toBe('Download – bit/s')
})
