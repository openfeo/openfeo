// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The components a settings page is made of (docs/components/FormSection.md, Choice.md,
// Toggle.md, Field.md): each is the markup its guideline gives for the stylesheet's classes,
// over a real control, and says what was done to it as a plain event.

import { mount } from '@vue/test-utils'
import { expect, test } from 'vitest'

import { OfoAdvanced, OfoChoice, OfoChoiceGroup, OfoFormSection, OfoInput, OfoSelect, OfoToggle } from '../src/index'

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
  await select.setValue('25')
  expect(select.emitted('update:modelValue')).toEqual([['25']])
  // What is shown is the model, not what was last picked.
  await select.setProps({ modelValue: '24' })
  expect((select.element as HTMLSelectElement).value).toBe('24')
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

test('a disabled control cannot be changed', () => {
  const choice = seen(mount(OfoChoice, { props: { modelValue: true, label: 'p3.20', disabled: true } }))
  expect((choice.find('input').element as HTMLInputElement).disabled).toBe(true)
  const toggle = seen(mount(OfoToggle, { props: { modelValue: true, label: 'IPv6', disabled: true } }))
  expect((toggle.find('input').element as HTMLInputElement).disabled).toBe(true)
  const select = seen(mount(OfoSelect, { props: { modelValue: 'a', options: [{ value: 'a', label: 'A' }], disabled: true } }))
  expect((select.element as HTMLSelectElement).disabled).toBe(true)
})

test('no component carries a style attribute', () => {
  // The router's content security policy refuses one (SPEC §8.3). The sources are read by
  // policy.test.ts; this is what the components above actually rendered.
  expect(mounted.length).toBeGreaterThan(15)
  for (const html of mounted) {
    expect(html).not.toMatch(/\sstyle=/)
  }
})
