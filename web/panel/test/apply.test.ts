// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// Applying (SPEC §8.4): the bar that counts what a settings page has changed, and the one
// dialog that says what an apply alters and interrupts before anything is sent.

import { ConfigEffectKind, ErrorCode, RouterError, type Config } from '@openfeo/client'
import { flushPromises, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import type { FakeRouter } from './fake-router'
import { NOW, pendingState, routerConfig, state } from './fixtures'
import { fieldLabelled, panelAt, signedIn, unmountAll } from './mounting'

async function page(path = '/lan', config: Config = routerConfig(), prepare: (router: FakeRouter) => void = () => undefined) {
  const router = signedIn()
  router.configNow = { config, tag: 't1', confirmSecs: 120 }
  prepare(router)
  const made = await panelAt(path, router)
  router.push('state', state())
  await flushPromises()
  return made
}

/** The page at /lan with the pool's end changed: one change to apply. */
async function changed(prepare: (router: FakeRouter) => void = () => undefined) {
  const made = await page('/lan', routerConfig(), prepare)
  await fieldLabelled(made.wrapper, 'Pool end').find('input').setValue('192.168.1.220')
  return made
}

const bar = (wrapper: VueWrapper) => wrapper.find('.ofo-savebar')
const button = (within: { findAll: VueWrapper['findAll'] }, text: string) => within.findAll('button').find((each) => each.text() === text)
const dialog = (wrapper: VueWrapper) => wrapper.find('.ofo-dialog')
/** Press Apply changes in the bar and wait for the router's validation. */
async function review(wrapper: VueWrapper) {
  await button(bar(wrapper), 'Apply changes')?.trigger('click')
  await flushPromises()
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(NOW)
  window.localStorage.clear()
  vi.stubGlobal('matchMedia', () => ({ matches: false }))
})
afterEach(() => {
  unmountAll()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

test("the bar counts the draft's changes on a settings page and is not on the dashboard", async () => {
  const { wrapper, routes, router, store } = await page()
  expect(bar(wrapper).exists()).toBe(false)
  await fieldLabelled(wrapper, 'Pool end').find('input').setValue('192.168.1.220')
  expect(bar(wrapper).text()).toContain('1 change not applied yet')
  expect(bar(wrapper).findAll('button').map((each) => each.text())).toEqual(['Discard', 'Apply changes'])
  await fieldLabelled(wrapper, 'Pool start').find('input').setValue('192.168.1.50')
  expect(bar(wrapper).text()).toContain('1 change not applied yet')
  await wrapper.findAll('table.res tbody tr')[0]?.findAll('input')[0]?.setValue('store')
  expect(bar(wrapper).text()).toContain('2 changes not applied yet')
  // It is beneath the page, inside the shell's content.
  expect(wrapper.find('.ofo-shell__content').element.lastElementChild).toBe(bar(wrapper).element)

  // The draft is the same on every page; the bar is on the settings pages only.
  await routes.push('/wan')
  await flushPromises()
  expect(bar(wrapper).text()).toContain('2 changes not applied yet')
  await routes.push('/firewall')
  await flushPromises()
  expect(bar(wrapper).text()).toContain('2 changes not applied yet')
  await routes.push('/dns')
  await flushPromises()
  expect(bar(wrapper).text()).toContain('2 changes not applied yet')
  await routes.push('/system')
  await flushPromises()
  expect(bar(wrapper).text()).toContain('2 changes not applied yet')
  await routes.push('/')
  await flushPromises()
  expect(bar(wrapper).exists()).toBe(false)
  expect(store().changes.value).toHaveLength(2)

  // A router that takes no changes has no bar to offer them with.
  await routes.push('/lan')
  const refused = state()
  refused.system!.configProblem = { $typeName: 'openfeo.v1.ConfigProblem', reason: 'invalid', violations: [] }
  router.push('state', refused)
  await flushPromises()
  expect(bar(wrapper).exists()).toBe(false)
})

test('discard empties the bar', async () => {
  const { wrapper, store } = await changed()
  await button(bar(wrapper), 'Discard')?.trigger('click')
  await flushPromises()
  expect(bar(wrapper).exists()).toBe(false)
  expect(store().changes.value).toEqual([])
  expect((fieldLabelled(wrapper, 'Pool end').find('input').element as HTMLInputElement).value).toBe('192.168.1.249')
})

test('apply changes validates first; a refused draft opens no dialog and marks its fields', async () => {
  const { wrapper, router } = await changed((fake) => {
    fake.validation = {
      violations: [{ $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[0].dhcp.range', code: 'router', message: 'the router is inside the pool' }],
      effects: [],
      caller: undefined,
    }
  })
  await review(wrapper)
  expect(router.calls.validate).toHaveLength(1)
  expect(router.calls.validate[0]?.lans[0]?.dhcp?.range[1]).toBe('192.168.1.220')
  expect(dialog(wrapper).exists()).toBe(false)
  expect(router.calls.apply).toHaveLength(0)
  const start = fieldLabelled(wrapper, 'Pool start')
  expect(start.find('[role="alert"]').text()).toBe('the router is inside the pool')
  // The first field with a problem is where the person is taken.
  expect(document.activeElement).toBe(start.find('input').element)
  expect(bar(wrapper).text()).toContain('1 change not applied yet')
})

test('a field the page itself finds wrong is put right before the router is asked', async () => {
  const { wrapper, router } = await changed()
  const address = fieldLabelled(wrapper, 'Router address').find('input')
  await address.setValue('192.168.4')
  await address.trigger('blur')
  await review(wrapper)
  expect(router.calls.validate).toHaveLength(0)
  expect(dialog(wrapper).exists()).toBe(false)
  expect(document.activeElement).toBe(address.element)
  // Put right, the review goes ahead.
  await address.setValue('192.168.1.1')
  await address.trigger('blur')
  await review(wrapper)
  expect(router.calls.validate).toHaveLength(1)
  expect(dialog(wrapper).exists()).toBe(true)
})

test('the dialog lists the changes and what the router says they interrupt', async () => {
  const { wrapper } = await changed((fake) => {
    fake.validation = {
      violations: [],
      effects: [{ $typeName: 'openfeo.v1.ConfigEffect', subject: 'lan0', kind: ConfigEffectKind.LAN_DHCP_RESTARTS }],
      caller: { $typeName: 'openfeo.v1.Caller', connectionDrops: false, lanChanges: false, lan: 'lan0', routerAfter: '192.168.1.1' },
    }
  })
  await wrapper.findAll('table.res tbody tr')[0]?.findAll('input')[0]?.setValue('store')
  await review(wrapper)
  const box = dialog(wrapper)
  expect(box.attributes('role')).toBe('alertdialog')
  expect(box.find('.ofo-dialog__title').text()).toBe('Apply 2 changes to openfeo?')
  expect(box.findAll('.ofo-changes li').map((item) => [item.find('.ofo-changes__key').text(), item.find('.ofo-changes__value').text()])).toEqual([
    ['lan0 pool', '192.168.1.100 – 192.168.1.249 → 192.168.1.100 – 192.168.1.220'],
    ['lan0 reservations', '1 changed'],
  ])
  expect(box.text()).toContain('What this interrupts')
  expect(box.findAll('.apply__effects li').map((item) => item.text())).toEqual(["lan0's DHCP server restarts; leases are kept."])
  // Nobody is moved: no warning.
  expect(box.find('.ofo-banner').exists()).toBe(false)
  expect(box.find('.apply__window').text()).toBe("You have 2 minutes to confirm once it is applied. If you don't, the router goes back to how it was.")
  expect(box.find('.apply__window strong').text()).toBe('2 minutes')
  // Cancel comes first, and is where the dialog opens.
  const buttons = box.findAll('.ofo-dialog__foot button')
  expect(buttons.map((each) => each.text())).toEqual(['Cancel', 'Apply changes'])
  expect(buttons[1]?.classes()).toContain('ofo-btn--primary')
  expect(document.activeElement).toBe(buttons[0]?.element)
})

test('one change is one change, and a change that interrupts nothing says so', async () => {
  const { wrapper } = await changed()
  await review(wrapper)
  expect(dialog(wrapper).find('.ofo-dialog__title').text()).toBe('Apply 1 change to openfeo?')
  expect(dialog(wrapper).find('.apply__effects').exists()).toBe(false)
  expect(dialog(wrapper).text()).toContain('Nothing is interrupted.')
})

test('a change that moves the caller warns, with the name and the new address', async () => {
  const { wrapper } = await changed((fake) => {
    fake.validation = {
      violations: [],
      effects: [{ $typeName: 'openfeo.v1.ConfigEffect', subject: 'lan0', kind: ConfigEffectKind.LAN_ADDRESS_MOVES }],
      caller: { $typeName: 'openfeo.v1.Caller', connectionDrops: true, lanChanges: true, lan: 'lan0', routerAfter: '192.168.2.1' },
    }
  })
  await review(wrapper)
  const warning = dialog(wrapper).find('.ofo-banner')
  expect(warning.classes()).toContain('ofo-banner--warn')
  expect(warning.find('.ofo-banner__title').text()).toBe('This moves the address you are using to reach the router')
  expect(warning.text()).toContain('Renew your DHCP lease, or change your static address, then come back to https://openfeo.home.arpa or https://192.168.2.1.')
  expect(warning.findAll('code.ofo-mono').map((code) => code.text())).toEqual(['https://openfeo.home.arpa', 'https://192.168.2.1'])
  expect(dialog(wrapper).findAll('.apply__effects li').map((item) => item.text())).toEqual(['lan0 moves: its devices need new addresses.'])
})

test('a rename says where the router will be found', async () => {
  const { wrapper, store } = await page('/system', routerConfig(), (fake) => {
    fake.validation = {
      violations: [],
      effects: [{ $typeName: 'openfeo.v1.ConfigEffect', subject: 'edge.home.arpa', kind: ConfigEffectKind.ROUTER_RENAMED }],
      caller: { $typeName: 'openfeo.v1.Caller', connectionDrops: false, lanChanges: false, lan: 'lan0', routerAfter: '192.168.1.1' },
    }
  })
  store().edit((draft) => (draft.system!.hostname = 'edge'))
  await flushPromises()
  await review(wrapper)
  const renamed = dialog(wrapper).find('.apply__renamed')
  expect(renamed.classes()).toContain('ofo-banner--warn')
  expect(renamed.find('.ofo-banner__title').text()).toBe('This renames the router')
  expect(renamed.text()).toContain(
    'It will answer at https://edge.home.arpa and no longer at https://openfeo.home.arpa, and its certificate is issued again, so the browser will ask about it once more. This page goes on working until it is closed or reloaded: confirm the change here, then open the new name. It is also at https://192.168.1.1.',
  )
  expect(renamed.findAll('code.ofo-mono').map((code) => code.text())).toEqual(['https://edge.home.arpa', 'https://openfeo.home.arpa', 'https://192.168.1.1'])
  // With no address from the router, the name alone.
  unmountAll()
  const alone = await page('/system')
  alone.store().edit((draft) => (draft.system!.domain = 'lan.example'))
  await flushPromises()
  await review(alone.wrapper)
  expect(dialog(alone.wrapper).find('.apply__renamed').text()).not.toContain('It is also at')
  expect(dialog(alone.wrapper).find('.apply__renamed').findAll('code.ofo-mono').map((code) => code.text())).toEqual(['https://openfeo.lan.example', 'https://openfeo.home.arpa'])
})

test('a change that renames nothing has no such block', async () => {
  const { wrapper } = await changed()
  await review(wrapper)
  expect(dialog(wrapper).find('.apply__renamed').exists()).toBe(false)
})

test('a caller whose subnet changes under a connection that stays is warned in other words', async () => {
  const { wrapper } = await changed((fake) => {
    fake.validation = {
      violations: [],
      effects: [{ $typeName: 'openfeo.v1.ConfigEffect', subject: 'lan0', kind: ConfigEffectKind.LAN_ADDRESS_MOVES }],
      caller: { $typeName: 'openfeo.v1.Caller', connectionDrops: false, lanChanges: true, lan: 'lan0', routerAfter: '192.168.2.1' },
    }
  })
  await review(wrapper)
  const warning = dialog(wrapper).find('.ofo-banner')
  expect(warning.find('.ofo-banner__title').text()).toBe('This changes the subnet your device is on')
  expect(warning.findAll('code.ofo-mono').map((code) => code.text())).toEqual(['https://openfeo.home.arpa', 'https://192.168.2.1'])
  unmountAll()

  // A LAN that is removed leaves no address to come back to: the name alone.
  const gone = await changed((fake) => {
    fake.validation = {
      violations: [],
      effects: [{ $typeName: 'openfeo.v1.ConfigEffect', subject: 'lan0', kind: ConfigEffectKind.LAN_REMOVED }],
      caller: { $typeName: 'openfeo.v1.Caller', connectionDrops: true, lanChanges: true, lan: 'lan0', routerAfter: '' },
    }
  })
  await review(gone.wrapper)
  const alone = dialog(gone.wrapper).find('.ofo-banner')
  expect(alone.text()).toContain('Renew your DHCP lease, or change your static address, then come back to https://openfeo.home.arpa.')
  expect(alone.findAll('code.ofo-mono').map((code) => code.text())).toEqual(['https://openfeo.home.arpa'])
})

test('the sentence takes its time from the router', async () => {
  const { wrapper } = await changed((fake) => {
    fake.configNow = { ...fake.configNow, confirmSecs: 40 }
  })
  await review(wrapper)
  expect(dialog(wrapper).find('.apply__window').text()).toBe("You have 40 seconds to confirm once it is applied. If you don't, the router goes back to how it was.")
  expect(dialog(wrapper).find('.apply__window strong').text()).toBe('40 seconds')
})

test('ticking the box changes the sentence and the button, and it is clear the next time', async () => {
  const { wrapper } = await changed()
  await review(wrapper)
  const choice = () => dialog(wrapper).find('.ofo-choice')
  expect(choice().text()).toBe('Apply immediately, no confirmation countdownThe change stays, whether or not you can reach the router afterwards.')
  expect((choice().find('input').element as HTMLInputElement).checked).toBe(false)
  await choice().find('input').setValue(true)
  expect(dialog(wrapper).find('.apply__window').text()).toBe('Nothing will undo this change by itself.')
  const apply = () => dialog(wrapper).findAll('.ofo-dialog__foot button')[1]!
  expect(apply().text()).toBe('Apply immediately')
  expect(apply().classes()).toContain('ofo-btn--danger')
  expect(apply().classes()).not.toContain('ofo-btn--primary')
  await choice().find('input').setValue(false)
  expect(apply().text()).toBe('Apply changes')
  expect(dialog(wrapper).find('.apply__window').text()).toContain('You have 2 minutes to confirm')

  // Ticked and cancelled: the next time it opens the box is clear.
  await choice().find('input').setValue(true)
  await button(dialog(wrapper), 'Cancel')?.trigger('click')
  await review(wrapper)
  expect((choice().find('input').element as HTMLInputElement).checked).toBe(false)
  expect(apply().text()).toBe('Apply changes')
})

test('apply sends immediate as the box says and closes the dialog', async () => {
  const { wrapper, router, store } = await changed((fake) => {
    fake.applyAnswer = { answered: true, tag: 't2' }
  })
  await review(wrapper)
  const letGo = router.holdCall('apply')
  await button(dialog(wrapper), 'Apply changes')?.trigger('click')
  await flushPromises()
  // While it is under way neither button can be pressed, and the box cannot be changed.
  expect(dialog(wrapper).findAll('.ofo-dialog__foot button').map((each) => (each.element as HTMLButtonElement).disabled)).toEqual([true, true])
  expect((dialog(wrapper).find('.ofo-choice input').element as HTMLInputElement).disabled).toBe(true)
  letGo()
  await flushPromises()
  expect(dialog(wrapper).exists()).toBe(false)
  expect(router.calls.apply).toHaveLength(1)
  expect(router.calls.apply[0]?.immediate).toBe(false)
  expect(router.calls.apply[0]?.tag).toBe('t1')
  expect(router.calls.apply[0]?.config.lans[0]?.dhcp?.range[1]).toBe('192.168.1.220')
  expect(store().changes.value).toEqual([])
  expect(bar(wrapper).exists()).toBe(false)

  // With the box ticked it is sent to stand at once.
  await fieldLabelled(wrapper, 'Pool end').find('input').setValue('192.168.1.230')
  await review(wrapper)
  await dialog(wrapper).find('.ofo-choice input').setValue(true)
  await button(dialog(wrapper), 'Apply immediately')?.trigger('click')
  await flushPromises()
  expect(router.calls.apply[1]?.immediate).toBe(true)
  expect(router.calls.apply[1]?.tag).toBe('t2')
  expect(dialog(wrapper).exists()).toBe(false)
})

test('the dialog closes whatever became of the apply, and a refusal keeps the draft', async () => {
  const { wrapper, router, store } = await changed((fake) => {
    fake.applyAnswer = new RouterError(ErrorCode.FAILED_PRECONDITION, 'a change of config is pending; confirm or revert it first')
  })
  await review(wrapper)
  await button(dialog(wrapper), 'Apply changes')?.trigger('click')
  await flushPromises()
  expect(dialog(wrapper).exists()).toBe(false)
  expect(router.calls.apply).toHaveLength(1)
  expect(store().notice.value).toEqual({ kind: 'refused', message: 'a change of config is pending; confirm or revert it first' })
  expect(bar(wrapper).text()).toContain('1 change not applied yet')
})

test('cancel and escape close it and send nothing', async () => {
  const { wrapper, router } = await changed()
  await review(wrapper)
  await button(dialog(wrapper), 'Cancel')?.trigger('click')
  expect(dialog(wrapper).exists()).toBe(false)
  await review(wrapper)
  expect(dialog(wrapper).exists()).toBe(true)
  document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
  await flushPromises()
  expect(dialog(wrapper).exists()).toBe(false)
  expect(router.calls.apply).toHaveLength(0)
  expect(bar(wrapper).text()).toContain('1 change not applied yet')
  // The focus is back where the dialog was opened from.
  expect(document.activeElement).toBe(button(bar(wrapper), 'Apply changes')?.element)
})

test('while a change is pending the bar says to settle it first', async () => {
  const { wrapper, router } = await changed()
  router.push('state', pendingState(10))
  await flushPromises()
  expect(bar(wrapper).text()).toContain('1 change not applied yet')
  expect(bar(wrapper).text()).toContain('Confirm or revert the change that is waiting first.')
  expect(bar(wrapper).findAll('button').map((each) => each.text())).toEqual(['Discard'])
  router.push('state', state())
  await flushPromises()
  expect(bar(wrapper).findAll('button').map((each) => each.text())).toEqual(['Discard', 'Apply changes'])
})

test('while an apply awaits the router the bar says so and offers no other', async () => {
  // An apply that had no answer: until the router says whether it took it, another would be
  // asked of a router that may be moving, and its refusal would take the place of the notice.
  const { wrapper, router, store } = await changed((fake) => {
    fake.applyAnswer = { answered: false }
  })
  await review(wrapper)
  router.configUnreachable = true
  await button(dialog(wrapper), 'Apply changes')?.trigger('click')
  await flushPromises()
  expect(router.calls.apply).toHaveLength(1)
  expect(bar(wrapper).text()).toContain('1 change not applied yet')
  expect(bar(wrapper).text()).toContain('Waiting to hear from the router what became of the change that was sent.')
  expect(bar(wrapper).findAll('button').map((each) => each.text())).toEqual(['Discard'])

  // Found again as it was: the change was not taken, and it can be applied again.
  router.setConnection('reconnecting')
  router.configUnreachable = false
  router.setConnection('open')
  router.push('state', state())
  await flushPromises()
  expect(store().awaiting.value).toBe(false)
  expect(bar(wrapper).text()).not.toContain('Waiting to hear')
  expect(bar(wrapper).findAll('button').map((each) => each.text())).toEqual(['Discard', 'Apply changes'])
})
