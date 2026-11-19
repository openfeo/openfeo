// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The components a settings page is made of (docs/components/FormSection.md, Choice.md,
// Toggle.md, Field.md): each is the markup its guideline gives for the stylesheet's classes,
// over a real control, and says what was done to it as a plain event.

import { mount } from '@vue/test-utils'
import { expect, test } from 'vitest'
import { nextTick } from 'vue'

import {
  ICONS,
  OfoAdvanced,
  OfoChangeList,
  OfoChoice,
  OfoChoiceGroup,
  OfoDialog,
  OfoFormSection,
  OfoInput,
  OfoSaveBar,
  OfoSelect,
  OfoTabs,
  OfoToggle,
  type TabEntry,
} from '../src/index'

/** Every piece of markup a test here mounted, for the last test to look through. */
const mounted: string[] = []
function seen<T extends { html(): string }>(wrapper: T): T {
  mounted.push(wrapper.html())
  return wrapper
}

test('a form section is a title and its explanation beside its fields', () => {
  const section = seen(
    mount(OfoFormSection, {
      props: { title: 'Connection', text: 'How this WAN gets its address from your ISP.' },
      slots: { default: '<input class="ofo-input">' },
    }),
  )
  expect(section.element.tagName).toBe('DIV')
  expect(section.classes()).toEqual(['ofo-formsec'])
  const [about, fields] = Array.from((section.element as HTMLElement).children)
  expect(about?.querySelector('h2.ofo-formsec__title')?.textContent).toBe('Connection')
  expect(about?.querySelector('p.ofo-formsec__text')?.textContent).toBe('How this WAN gets its address from your ISP.')
  expect(fields?.className).toBe('ofo-formsec__fields')
  expect(fields?.querySelector('input')).not.toBeNull()
})

test('a form section sets its fields in the grid, or plainly for a table', () => {
  const plain = seen(
    mount(OfoFormSection, {
      props: { title: 'Reservations', text: 'Devices that always get the same address.', plain: true },
      slots: { default: '<table></table>' },
    }),
  )
  expect(plain.find('.ofo-formsec__fields').exists()).toBe(false)
  const holder = (plain.element as HTMLElement).children[1]
  expect(holder?.tagName).toBe('DIV')
  expect(holder?.className).toBe('')
  expect(holder?.querySelector('table')).not.toBeNull()
})

test('advanced is a disclosure labelled Advanced, its fields in a grid of their own', () => {
  const advanced = seen(mount(OfoAdvanced, { slots: { default: '<input class="ofo-input">' } }))
  expect(advanced.element.tagName).toBe('DETAILS')
  expect(advanced.classes()).toEqual(['ofo-adv'])
  expect(advanced.find('summary').text()).toBe('Advanced')
  expect(advanced.find('.ofo-adv__grid input').exists()).toBe(true)
})

test('advanced is closed until told or clicked', async () => {
  const advanced = seen(mount(OfoAdvanced, { attachTo: document.body }))
  const details = advanced.element as HTMLDetailsElement
  expect(details.open).toBe(false)
  expect(advanced.attributes('open')).toBeUndefined()
  // Told: a field inside came to hold something, or a problem.
  await advanced.setProps({ open: true })
  expect(details.open).toBe(true)
  // Closed by hand, it stays closed while nothing new is said.
  details.open = false
  await advanced.trigger('toggle')
  await advanced.setProps({ open: true })
  expect(details.open).toBe(false)
  // Told again after having been told otherwise, it opens.
  await advanced.setProps({ open: false })
  await advanced.setProps({ open: true })
  expect(details.open).toBe(true)
  advanced.unmount()

  const open = seen(mount(OfoAdvanced, { props: { open: true } }))
  expect((open.element as HTMLDetailsElement).open).toBe(true)
})

test('a choice is a label around a real input, its text and its hint', () => {
  const choice = seen(
    mount(OfoChoice, {
      props: { modelValue: 'dhcp', type: 'radio', value: 'pppoe', name: 'type', label: 'PPPoE', hint: 'You log in with an account.' },
    }),
  )
  expect(choice.element.tagName).toBe('LABEL')
  expect(choice.classes()).toEqual(['ofo-choice'])
  const input = choice.find('input')
  expect(input.attributes('type')).toBe('radio')
  expect(input.attributes('name')).toBe('type')
  expect(choice.find('span').text()).toContain('PPPoE')
  expect(choice.find('.ofo-choice__hint').text()).toBe('You log in with an account.')

  const bare = seen(mount(OfoChoice, { props: { modelValue: false, label: 'p3' } }))
  expect(bare.find('input').attributes('type')).toBe('checkbox')
  expect(bare.find('.ofo-choice__hint').exists()).toBe(false)
})

test('a checkbox choice gives its state and a radio gives its value', async () => {
  const box = seen(mount(OfoChoice, { props: { modelValue: false, label: 'p3' } }))
  await box.find('input').setValue(true)
  expect(box.emitted('update:modelValue')).toEqual([[true]])
  await box.setProps({ modelValue: true })
  expect((box.find('input').element as HTMLInputElement).checked).toBe(true)
  await box.find('input').setValue(false)
  expect(box.emitted('update:modelValue')?.at(-1)).toEqual([false])

  const radio = seen(mount(OfoChoice, { props: { modelValue: 'dhcp', type: 'radio', value: 'static', label: 'Static' } }))
  await radio.find('input').setValue(true)
  expect(radio.emitted('update:modelValue')).toEqual([['static']])
})

test('a radio is checked only when the model is its value', async () => {
  const radio = seen(mount(OfoChoice, { props: { modelValue: 'dhcp', type: 'radio', value: 'static', label: 'Static' } }))
  const input = radio.find('input').element as HTMLInputElement
  expect(input.checked).toBe(false)
  await radio.setProps({ modelValue: 'static' })
  expect(input.checked).toBe(true)
  await radio.setProps({ modelValue: 'pppoe' })
  expect(input.checked).toBe(false)
})

test('a choice group is a fieldset with its legend, the choices in a row', () => {
  const group = seen(mount(OfoChoiceGroup, { props: { legend: 'Type' }, slots: { default: '<label class="ofo-choice"></label>' } }))
  expect(group.element.tagName).toBe('FIELDSET')
  expect(group.classes()).toEqual(['ofo-choices'])
  expect(group.find('legend').classes()).toEqual(['ofo-field__label'])
  expect(group.find('legend').text()).toBe('Type')
  expect(group.find('div.ofo-row .ofo-choice').exists()).toBe(true)
})

test('a toggle is a real checkbox, its track and its label', () => {
  const toggle = seen(mount(OfoToggle, { props: { modelValue: true, label: 'DHCP server' } }))
  expect(toggle.element.tagName).toBe('LABEL')
  expect(toggle.classes()).toEqual(['ofo-toggle'])
  const [input, track] = Array.from((toggle.element as HTMLElement).children)
  expect(input?.tagName).toBe('INPUT')
  expect(input?.getAttribute('type')).toBe('checkbox')
  expect((input as HTMLInputElement).checked).toBe(true)
  expect(track?.className).toBe('ofo-toggle__track')
  expect(toggle.text()).toBe('DHCP server')
})

test('a select is a real select of its options', () => {
  const select = seen(
    mount(OfoSelect, {
      props: {
        modelValue: '24',
        options: [
          { value: '24', label: '/24 · 254 addresses' },
          { value: '25', label: '/25 · 126 addresses' },
          { value: '31', label: '/31', disabled: true },
        ],
      },
    }),
  )
  expect(select.element.tagName).toBe('SELECT')
  expect(select.classes()).toEqual(['ofo-select'])
  const options = select.findAll('option')
  expect(options.map((option) => option.text())).toEqual(['/24 · 254 addresses', '/25 · 126 addresses', '/31'])
  expect(options.map((option) => option.attributes('value'))).toEqual(['24', '25', '31'])
  expect((select.element as HTMLSelectElement).value).toBe('24')
  expect((options[2]?.element as HTMLOptionElement).disabled).toBe(true)
})

test('a toggle and a select are v-models over real controls', async () => {
  const toggle = seen(mount(OfoToggle, { props: { modelValue: false, label: 'IPv6' } }))
  await toggle.find('input').setValue(true)
  expect(toggle.emitted('update:modelValue')).toEqual([[true]])

  const select = seen(
    mount(OfoSelect, {
      props: {
        modelValue: '24',
        options: [
          { value: '24', label: '/24' },
          { value: '25', label: '/25' },
        ],
      },
    }),
  )
  // (Chosen in the element itself: setting a mounted component's value only emits.)
  ;(select.element as HTMLSelectElement).value = '25'
  await select.trigger('change')
  expect(select.emitted('update:modelValue')).toEqual([['25']])
  // What is shown is the model, not what was last picked: a choice that was not taken is put back.
  await nextTick()
  expect((select.element as HTMLSelectElement).value).toBe('24')
  // And one that was taken stays.
  ;(select.element as HTMLSelectElement).value = '25'
  await select.trigger('change')
  await select.setProps({ modelValue: '25' })
  await nextTick()
  expect((select.element as HTMLSelectElement).value).toBe('25')
})

test('an input takes a placeholder and a small size', () => {
  const input = seen(mount(OfoInput, { props: { modelValue: '', placeholder: 'Unchanged', small: true, mono: true } }))
  expect(input.attributes('placeholder')).toBe('Unchanged')
  expect(input.classes()).toEqual(['ofo-input', 'ofo-input--mono', 'ofo-input--sm'])
  const plain = seen(mount(OfoInput, { props: { modelValue: 'x' } }))
  expect(plain.attributes('placeholder')).toBeUndefined()
  expect(plain.classes()).toEqual(['ofo-input'])
})

test('an input says when it is left, and when it is not valid', async () => {
  const input = seen(mount(OfoInput, { props: { modelValue: '4095' } }))
  expect(input.attributes('aria-invalid')).toBeUndefined()
  await input.trigger('blur')
  expect(input.emitted('blur')).toHaveLength(1)
  await input.setProps({ invalid: true })
  expect(input.attributes('aria-invalid')).toBe('true')
})

test('an input for a whole number lets nothing but digits in', async () => {
  const input = seen(mount(OfoInput, { props: { modelValue: '', digits: true } }))
  expect(input.attributes('inputmode')).toBe('numeric')
  // (Typed into the element itself: setting a mounted component's value only emits.)
  const typeInto = async (box: typeof input, text: string) => {
    ;(box.element as HTMLInputElement).value = text
    await box.trigger('input')
  }
  await typeInto(input, '12a.5-')
  expect(input.emitted('update:modelValue')).toEqual([['125']])
  expect((input.element as HTMLInputElement).value).toBe('125')
  // Any other input is left as it was typed, and asks for no number pad.
  const plain = seen(mount(OfoInput, { props: { modelValue: '' } }))
  expect(plain.attributes('inputmode')).toBeUndefined()
  await typeInto(plain, '12a')
  expect(plain.emitted('update:modelValue')).toEqual([['12a']])
})

test('a disabled control cannot be changed', () => {
  const choice = seen(mount(OfoChoice, { props: { modelValue: true, label: 'p3.20', disabled: true } }))
  expect((choice.find('input').element as HTMLInputElement).disabled).toBe(true)
  const toggle = seen(mount(OfoToggle, { props: { modelValue: true, label: 'IPv6', disabled: true } }))
  expect((toggle.find('input').element as HTMLInputElement).disabled).toBe(true)
  const select = seen(mount(OfoSelect, { props: { modelValue: 'a', options: [{ value: 'a', label: 'A' }], disabled: true } }))
  expect((select.element as HTMLSelectElement).disabled).toBe(true)
})

const TABS: TabEntry[] = [
  { id: 'lan0', label: 'lan0', count: '14 clients' },
  { id: 'guest', label: 'guest', count: '1 client' },
  { id: 'iot', label: 'iot', pill: { text: 'problem', tone: 'danger' } },
]

test('tabs are a tablist; the chosen one is selected and the only one in the tab order', () => {
  const tabs = seen(mount(OfoTabs, { props: { tabs: TABS, modelValue: 'guest', panel: 'lan-panel' } }))
  expect(tabs.element.tagName).toBe('DIV')
  expect(tabs.classes()).toEqual(['ofo-tabs'])
  expect(tabs.attributes('role')).toBe('tablist')
  const buttons = tabs.findAll('button')
  expect(buttons.map((button) => button.attributes('role'))).toEqual(['tab', 'tab', 'tab'])
  expect(buttons.map((button) => button.attributes('type'))).toEqual(['button', 'button', 'button'])
  expect(buttons.map((button) => button.attributes('aria-selected'))).toEqual(['false', 'true', 'false'])
  expect(buttons.map((button) => button.attributes('tabindex'))).toEqual(['-1', '0', '-1'])
  expect(buttons.map((button) => button.attributes('aria-controls'))).toEqual(['lan-panel', 'lan-panel', 'lan-panel'])
})

test('a click on a tab chooses it', async () => {
  const tabs = seen(mount(OfoTabs, { props: { tabs: TABS, modelValue: 'lan0', panel: 'p' } }))
  await tabs.findAll('button')[2]?.trigger('click')
  expect(tabs.emitted('update:modelValue')).toEqual([['iot']])
})

test('arrow keys move between tabs and choose, and stop at neither end', async () => {
  const tabs = seen(mount(OfoTabs, { props: { tabs: TABS, modelValue: 'lan0', panel: 'p' }, attachTo: document.body }))
  const buttons = tabs.findAll('button')
  const chosen = () => tabs.emitted('update:modelValue')?.at(-1)?.[0]
  await buttons[0]?.trigger('keydown', { key: 'ArrowRight' })
  expect(chosen()).toBe('guest')
  // The focus goes with the choice, so the next key is heard by the tab it chose.
  expect(document.activeElement).toBe(buttons[1]?.element)
  await tabs.setProps({ modelValue: 'guest' })
  await buttons[1]?.trigger('keydown', { key: 'End' })
  expect(chosen()).toBe('iot')
  await tabs.setProps({ modelValue: 'iot' })
  await buttons[2]?.trigger('keydown', { key: 'ArrowRight' })
  expect(chosen()).toBe('lan0')
  await tabs.setProps({ modelValue: 'lan0' })
  await buttons[0]?.trigger('keydown', { key: 'ArrowLeft' })
  expect(chosen()).toBe('iot')
  await tabs.setProps({ modelValue: 'iot' })
  await buttons[2]?.trigger('keydown', { key: 'Home' })
  expect(chosen()).toBe('lan0')
  // Any other key is the page's.
  const before = tabs.emitted('update:modelValue')?.length
  await buttons[0]?.trigger('keydown', { key: 'a' })
  expect(tabs.emitted('update:modelValue')?.length).toBe(before)
  tabs.unmount()
})

test('a tab shows its count or its pill', () => {
  const tabs = seen(mount(OfoTabs, { props: { tabs: TABS, modelValue: 'lan0', panel: 'p' } }))
  const buttons = tabs.findAll('button')
  expect(buttons[0]?.find('.ofo-tabs__count').text()).toBe('14 clients')
  expect(buttons[0]?.find('.ofo-pill').exists()).toBe(false)
  expect(buttons[2]?.find('.ofo-tabs__count').exists()).toBe(false)
  expect(buttons[2]?.find('.ofo-pill').classes()).toEqual(['ofo-pill', 'ofo-pill--danger'])
  expect(buttons[2]?.find('.ofo-pill').text()).toBe('problem')
  expect(buttons[2]?.text()).toContain('iot')
})

test('the save bar is absent with nothing to apply', () => {
  const bar = seen(mount(OfoSaveBar, { props: { count: 0 } }))
  expect(bar.find('.ofo-savebar').exists()).toBe(false)
  expect(bar.text()).toBe('')
})

test('the save bar counts in the singular and the plural, and gives discard and apply', async () => {
  const bar = seen(mount(OfoSaveBar, { props: { count: 1 } }))
  expect(bar.classes()).toEqual(['ofo-savebar'])
  expect(bar.text()).toContain('1 change not applied yet')
  expect(bar.find('strong').text()).toBe('1')
  const buttons = bar.findAll('.ofo-savebar__actions button')
  expect(buttons.map((button) => button.text())).toEqual(['Discard', 'Apply changes'])
  expect(buttons[0]?.classes()).toContain('ofo-btn--ghost')
  expect(buttons[1]?.classes()).toContain('ofo-btn--primary')
  await buttons[0]?.trigger('click')
  await buttons[1]?.trigger('click')
  expect(bar.emitted('discard')).toHaveLength(1)
  expect(bar.emitted('apply')).toHaveLength(1)

  await bar.setProps({ count: 3 })
  expect(bar.text()).toContain('3 changes not applied yet')
  expect(bar.find('strong').text()).toBe('3')

  // While something is under way neither can be pressed.
  await bar.setProps({ busy: true })
  expect(bar.findAll('button').map((button) => (button.element as HTMLButtonElement).disabled)).toEqual([true, true])
})

test('the button that applies has the focus once it is pressed', async () => {
  // A dialog opened from it gives the focus back to it, in a browser that would have left the focus where it was.
  const bar = seen(mount(OfoSaveBar, { props: { count: 1 }, attachTo: document.body }))
  const apply = bar.findAll('button')[1]
  expect(document.activeElement).not.toBe(apply?.element)
  await apply?.trigger('click')
  expect(document.activeElement).toBe(apply?.element)
  expect(bar.emitted('apply')).toHaveLength(1)
  bar.unmount()
})

test('the save bar says why an apply is held, and offers none', () => {
  const bar = seen(mount(OfoSaveBar, { props: { count: 2, held: 'Confirm or revert the change that is waiting first.' } }))
  expect(bar.findAll('button').map((button) => button.text())).toEqual(['Discard'])
  expect(bar.find('.ofo-savebar__actions').text()).toContain('Confirm or revert the change that is waiting first.')
})

const DIALOG = {
  props: { title: 'Apply 3 changes to openfeo?' },
  slots: {
    default: '<label><input id="box" type="checkbox"> Apply immediately</label>',
    foot: '<button id="cancel" type="button">Cancel</button><button id="apply" type="button">Apply changes</button>',
  },
}

test('a dialog is labelled by its title and says its role', () => {
  const dialog = seen(mount(OfoDialog, { ...DIALOG, attachTo: document.body }))
  expect(dialog.classes()).toEqual(['ofo-scrim'])
  const box = dialog.find('.ofo-dialog')
  expect(box.attributes('role')).toBe('alertdialog')
  expect(box.attributes('aria-modal')).toBe('true')
  const title = dialog.find('.ofo-dialog__body h2.ofo-dialog__title')
  expect(title.text()).toBe('Apply 3 changes to openfeo?')
  expect(title.attributes('id')).toBeTruthy()
  expect(box.attributes('aria-labelledby')).toBe(title.attributes('id'))
  expect(dialog.find('.ofo-dialog__body #box').exists()).toBe(true)
  expect(dialog.findAll('.ofo-dialog__foot button')).toHaveLength(2)
  dialog.unmount()

  const form = seen(mount(OfoDialog, { props: { title: 'Add a WAN', role: 'dialog' }, attachTo: document.body }))
  expect(form.find('.ofo-dialog').attributes('role')).toBe('dialog')
  form.unmount()
})

test('a dialog takes the focus, keeps it, and gives it back', async () => {
  const opener = document.createElement('button')
  document.body.append(opener)
  opener.focus()
  const dialog = seen(mount(OfoDialog, { ...DIALOG, attachTo: document.body }))
  const box = dialog.find('#box').element
  const apply = dialog.find('#apply').element as HTMLElement
  // It opens on its first control.
  expect(document.activeElement).toBe(box)
  // Tab from the last control comes round to the first, and Shift+Tab from the first to the last.
  apply.focus()
  const forward = new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true })
  apply.dispatchEvent(forward)
  expect(forward.defaultPrevented).toBe(true)
  expect(document.activeElement).toBe(box)
  const back = new KeyboardEvent('keydown', { key: 'Tab', shiftKey: true, bubbles: true, cancelable: true })
  box.dispatchEvent(back)
  expect(back.defaultPrevented).toBe(true)
  expect(document.activeElement).toBe(apply)
  // In the middle a Tab is the browser's own.
  const cancel = dialog.find('#cancel').element as HTMLElement
  cancel.focus()
  const middle = new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true })
  cancel.dispatchEvent(middle)
  expect(middle.defaultPrevented).toBe(false)
  // Focus that got out (a click on the page behind) is brought back by the next Tab.
  opener.focus()
  const stray = new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true })
  opener.dispatchEvent(stray)
  expect(document.activeElement).toBe(box)

  dialog.unmount()
  expect(document.activeElement).toBe(opener)
  opener.remove()
})

test('a dialog opens on the control it is told to, when it is told', () => {
  const dialog = seen(
    mount(OfoDialog, {
      props: { title: 'Apply 1 change to openfeo?' },
      slots: {
        default: '<input id="box" type="checkbox">',
        foot: '<button id="cancel" type="button" autofocus>Cancel</button><button id="apply" type="button">Apply changes</button>',
      },
      attachTo: document.body,
    }),
  )
  expect(document.activeElement).toBe(dialog.find('#cancel').element)
  dialog.unmount()
})

test('escape cancels a dialog and a click on the scrim does not', async () => {
  let cancels = 0
  const dialog = seen(mount(OfoDialog, { ...DIALOG, props: { ...DIALOG.props, onCancel: () => (cancels += 1) }, attachTo: document.body }))
  await dialog.trigger('click')
  expect(cancels).toBe(0)
  document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
  expect(cancels).toBe(1)
  dialog.unmount()
  // Gone, it listens to nothing.
  document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
  expect(cancels).toBe(1)
})

test('a change is its subject, what was, and what will be', () => {
  const list = seen(
    mount(OfoChangeList, {
      props: {
        changes: [
          { subject: 'lan0', what: 'address', before: '192.168.1.1/24', after: '192.168.2.1/24' },
          { subject: 'wan1', what: 'WAN', before: '', after: 'added: PPPoE on p1.911' },
          { subject: 'guest', what: 'LAN', before: '192.168.3.1/24 on p3', after: '' },
          { subject: 'firewall.wan_ping', what: '', before: 'true', after: 'false' },
        ],
      },
    }),
  )
  expect(list.element.tagName).toBe('UL')
  expect(list.classes()).toEqual(['ofo-changes'])
  const rows = list.findAll('li')
  expect(rows).toHaveLength(4)
  expect(rows[0]?.find('.ofo-changes__key').text()).toBe('lan0 address')
  expect(rows[0]?.find('.ofo-changes__value s').text()).toBe('192.168.1.1/24')
  expect(rows[0]?.find('.ofo-changes__value').text()).toBe('192.168.1.1/24 → 192.168.2.1/24')
  // With nothing before, nothing is struck through; with nothing after, only what was.
  expect(rows[1]?.find('s').exists()).toBe(false)
  expect(rows[1]?.find('.ofo-changes__value').text()).toBe('added: PPPoE on p1.911')
  expect(rows[2]?.find('.ofo-changes__value').text()).toBe('192.168.3.1/24 on p3')
  expect(rows[2]?.find('s').exists()).toBe(true)
  expect(rows[3]?.find('.ofo-changes__key').text()).toBe('firewall.wan_ping')
})

test('the icons of the two pages under Network are there', () => {
  expect(ICONS.globe).toContain('<')
  expect(ICONS.network).toContain('<')
})

test('no component carries a style attribute', () => {
  // The router's content security policy refuses one (SPEC §8.3). The sources are read by
  // policy.test.ts; this is what the components above actually rendered.
  expect(mounted.length).toBeGreaterThan(15)
  for (const html of mounted) {
    expect(html).not.toMatch(/\sstyle=/)
  }
})
