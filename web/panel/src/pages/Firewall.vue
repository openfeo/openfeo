<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { create, FirewallSchema, type Firewall, type PortForward, type Rule } from '@openfeo/client'
import { OfoBanner, OfoButton, OfoChoice, OfoFormSection, OfoPageHeader, OfoSkeleton, OfoToggle } from '@openfeo/ui'
import { computed, inject, provide, watch } from 'vue'

import { CONFIG } from '../config'
import { FIELDS, forgetFrom, listText, numberText, pageFields, toNumber, under } from '../fields'
import {
  FORWARD_PROTOCOLS,
  forwardProblems,
  fromOptions,
  newForward,
  newRule,
  parsePorts,
  publicBlocks,
  reachGrid,
  RULE_PROTOCOLS,
  ruleProblems,
  setReach,
  settle,
} from '../model/firewall'
import RefusedList from '../parts/RefusedList.vue'
import SettingCell from '../parts/SettingCell.vue'

// The Firewall page (SPEC §7.5, §8.4): which network may start connections to which, as a
// grid of ticks; port forwards and rules, as tables edited in place; and whether the router
// answers ping from the internet. It edits the one draft; what it knows beyond arranging
// fields is model/firewall. "May reach" is a setting of each LAN, changed here and shown on
// LAN & DHCP.
const store = inject(CONFIG)!
const fields = pageFields()
provide(FIELDS, fields)
// A draft that is another one (discarded, applied, read again with something new in it) starts clean.
watch(
  () => store.draft.value,
  (now, before) => {
    if (now !== before) {
      fields.left.clear()
      fields.typed.clear()
    }
  },
)

const draft = computed(() => store.draft.value)
const editable = computed(() => store.readOnly.value === null && store.draft.value !== null)

// ---- Between networks ----

const grid = computed(() => (draft.value === null ? [] : reachGrid(draft.value)))
function reach(row: number, to: string, on: boolean): void {
  store.edit((config) => {
    const lan = config.lans[row]
    if (lan !== undefined) {
      setReach(
        lan,
        to,
        on,
        config,
        store.base.value?.lans.find((each) => each.name === lan.name),
      )
    }
  })
  // What the router said of these ticks was said of what they were.
  const path = `lans[${row}].reaches`
  store.violations.value = store.violations.value.filter((violation) => !under(violation.path, path))
}
/** What the router refused about a LAN's ticks, by the LAN's name. */
const reachSaid = computed(() =>
  grid.value.flatMap((row, n) => {
    const message = store.problemAt(`lans[${n}].reaches`)
    return message === undefined ? [] : [{ lan: row.lan, message }]
  }),
)

// ---- Port forwards and rules ----

const forwards = computed(() => draft.value?.firewall?.portForwards ?? [])
const rules = computed(() => draft.value?.firewall?.rules ?? [])
/** Whether a forward may listen on an address of its own: only with a public block. */
const listens = computed(() => draft.value !== null && publicBlocks(draft.value))
const froms = computed(() => (draft.value === null ? [] : fromOptions(draft.value)))

/** Change the firewall's settings; a router that had none and has none again is left without. */
function change(edit: (firewall: Firewall) => void): void {
  store.edit((config) => {
    config.firewall ??= create(FirewallSchema, {})
    edit(config.firewall)
    settle(config, store.base.value)
  })
}
function forward(at: number, edit: (forward: PortForward) => void): void {
  change((firewall) => {
    const row = firewall.portForwards[at]
    if (row !== undefined) {
      edit(row)
    }
  })
}
function rule(at: number, edit: (rule: Rule) => void): void {
  change((firewall) => {
    const row = firewall.rules[at]
    if (row !== undefined) {
      edit(row)
    }
  })
}
function removeForward(at: number): void {
  change((firewall) => firewall.portForwards.splice(at, 1))
  // The rows after it each have another place now: what was said of them by place goes too.
  forgetFrom(fields, store, 'firewall.port_forwards', at)
}
function removeRule(at: number): void {
  change((firewall) => firewall.rules.splice(at, 1))
  forgetFrom(fields, store, 'firewall.rules', at)
}
/** The same forward as the router has it, by its name; none for one that is only in the draft. */
function wasForward(row: PortForward): PortForward | undefined {
  return store.base.value?.firewall?.portForwards.find((each) => each.name === row.name)
}
function wasRule(row: Rule): Rule | undefined {
  return store.base.value?.firewall?.rules.find((each) => each.name === row.name)
}
function ports(at: number, text: string): void {
  fields.typed.set(`firewall.rules[${at}].ports`, text)
  rule(at, (row) => (row.ports = parsePorts(text)))
}
function protocol(at: number, proto: string): void {
  rule(at, (row) => (row.proto = proto))
  // A choice is made, not typed: what it makes of the ports beside it is said at once.
  fields.left.add(`firewall.rules[${at}].ports`)
}

// ---- The router itself ----

const pings = computed(() => draft.value?.firewall?.wanPing === true)

// ---- What the router refused where no field is ----

const FORWARD_FIELDS = ['name', 'proto', 'port', 'to', 'to_port']
const RULE_FIELDS = ['name', 'from', 'to', 'proto', 'ports']
/** Whether a field of this page is for `path`, and so says what the router said of it. */
function claimed(path: string): boolean {
  const row = /^firewall\.(port_forwards|rules)\[\d+\]\.([a-z_]+)/.exec(path)
  if (row !== null) {
    const field = row[2] ?? ''
    return row[1] === 'rules' ? RULE_FIELDS.includes(field) : FORWARD_FIELDS.includes(field) || (field === 'address' && listens.value)
  }
  return /^lans\[\d+\]\.reaches(\[|$)/.test(path)
}
/**
 * What the router refused that no field here shows: a whole row, a setting of another page.
 * Said above the page, so that pressing Apply changes never looks like nothing happened.
 */
const unplaced = computed(() => store.violations.value.filter((violation) => !claimed(violation.path)))
</script>

<template>
  <div class="page">
    <OfoPageHeader title="Firewall" sub="What may reach what. Nothing on the internet gets in unless you say so here." />
    <OfoBanner v-if="store.readOnly.value" class="readonly" tone="info">{{ store.readOnly.value }}</OfoBanner>
    <RefusedList :violations="unplaced" />
    <template v-if="draft === null">
      <OfoSkeleton :lines="6" />
    </template>
    <template v-else>
      <OfoFormSection title="Between networks" text="A tick lets devices on the row's LAN start connections to the column. Replies always get back." plain>
        <div class="ofo-table-wrap">
          <table class="ofo-table reach">
            <thead>
              <tr>
                <th>From</th>
                <th>Internet</th>
                <th v-for="row in grid" :key="row.lan">{{ row.lan }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(row, n) in grid" :key="row.lan">
                <td>{{ row.lan }}</td>
                <td v-for="cell in row.cells" :key="cell.to">
                  <span v-if="cell.own" class="ofo-muted">—</span>
                  <OfoChoice
                    v-else
                    bare
                    :label="`${row.lan} may reach ${cell.label}`"
                    :model-value="cell.ticked"
                    :disabled="!editable"
                    @update:model-value="(on) => reach(n, cell.to, on === true)"
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-if="reachSaid.length > 0" class="reach__said">
          <p v-for="said in reachSaid" :key="said.lan" class="ofo-field__help ofo-field--error" role="alert">{{ said.lan }}: {{ said.message }}</p>
        </div>
      </OfoFormSection>

      <OfoFormSection title="Port forwards" text="A port on the router's internet address that leads to one device. It works from inside your network too." plain>
        <div v-if="forwards.length > 0" class="ofo-table-wrap">
          <table class="ofo-table res fwd">
            <thead>
              <tr>
                <th>Name</th>
                <th>Protocol</th>
                <th>Port</th>
                <th>To address</th>
                <th>To port</th>
                <th v-if="listens">Listens on</th>
                <th />
              </tr>
            </thead>
            <tbody>
              <tr v-for="(row, n) in forwards" :key="n">
                <SettingCell
                  :path="`firewall.port_forwards[${n}].name`"
                  :value="row.name"
                  :problem="forwardProblems(forwards, n).name"
                  @update="(text) => forward(n, (each) => (each.name = text))"
                />
                <SettingCell
                  :path="`firewall.port_forwards[${n}].proto`"
                  :value="row.proto"
                  :options="FORWARD_PROTOCOLS"
                  @update="(text) => forward(n, (each) => (each.proto = text))"
                />
                <SettingCell
                  :path="`firewall.port_forwards[${n}].port`"
                  :value="numberText(row.port)"
                  :was="wasForward(row) && numberText(wasForward(row)!.port)"
                  :problem="forwardProblems(forwards, n).port"
                  mono
                  digits
                  @update="(text) => forward(n, (each) => (each.port = toNumber(text)))"
                />
                <SettingCell
                  :path="`firewall.port_forwards[${n}].to`"
                  :value="row.to"
                  :was="wasForward(row)?.to"
                  :problem="forwardProblems(forwards, n).to"
                  mono
                  @update="(text) => forward(n, (each) => (each.to = text))"
                />
                <SettingCell
                  :path="`firewall.port_forwards[${n}].to_port`"
                  :value="numberText(row.toPort)"
                  :was="wasForward(row) && numberText(wasForward(row)!.toPort)"
                  :problem="forwardProblems(forwards, n).to_port"
                  :placeholder="numberText(row.port)"
                  mono
                  digits
                  @update="(text) => forward(n, (each) => (each.toPort = toNumber(text)))"
                />
                <SettingCell
                  v-if="listens"
                  :path="`firewall.port_forwards[${n}].address`"
                  :value="row.address"
                  :was="wasForward(row)?.address"
                  :problem="forwardProblems(forwards, n).address"
                  placeholder="The WAN's own"
                  mono
                  @update="(text) => forward(n, (each) => (each.address = text))"
                />
                <td>
                  <OfoButton size="sm" variant="ghost" :disabled="!editable" @click="removeForward(n)">Remove</OfoButton>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="res__add">
          <OfoButton size="sm" :disabled="!editable" @click="change((firewall) => firewall.portForwards.push(newForward()))">Add forward</OfoButton>
        </div>
        <p class="ofo-muted page__none">
          To port: leave empty for the same port.
          <template v-if="listens">Listens on: an address of your public block; empty for the WAN’s own.</template>
        </p>
      </OfoFormSection>

      <OfoFormSection
        title="Rules"
        text="A way in with no address translation: for a device's IPv6 address, for a LAN with public addresses, or from one LAN to one device on another."
        plain
      >
        <div v-if="rules.length > 0" class="ofo-table-wrap">
          <table class="ofo-table res rules">
            <thead>
              <tr>
                <th>Name</th>
                <th>From</th>
                <th>To</th>
                <th>Protocol</th>
                <th>Ports</th>
                <th />
              </tr>
            </thead>
            <tbody>
              <tr v-for="(row, n) in rules" :key="n">
                <SettingCell
                  :path="`firewall.rules[${n}].name`"
                  :value="row.name"
                  :problem="ruleProblems(rules, n).name"
                  @update="(text) => rule(n, (each) => (each.name = text))"
                />
                <SettingCell :path="`firewall.rules[${n}].from`" :value="row.from" :options="froms" @update="(text) => rule(n, (each) => (each.from = text))" />
                <SettingCell
                  :path="`firewall.rules[${n}].to`"
                  :value="row.to"
                  :was="wasRule(row)?.to"
                  :problem="ruleProblems(rules, n).to"
                  mono
                  @update="(text) => rule(n, (each) => (each.to = text))"
                />
                <SettingCell :path="`firewall.rules[${n}].proto`" :value="row.proto" :options="RULE_PROTOCOLS" @update="(text) => protocol(n, text)" />
                <SettingCell
                  :path="`firewall.rules[${n}].ports`"
                  :value="listText(fields, `firewall.rules[${n}].ports`, row.ports)"
                  :was="wasRule(row)?.ports.join(', ')"
                  :means="row.ports.join(', ')"
                  :problem="ruleProblems(rules, n).ports"
                  mono
                  @update="(text) => ports(n, text)"
                />
                <td>
                  <OfoButton size="sm" variant="ghost" :disabled="!editable" @click="removeRule(n)">Remove</OfoButton>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="res__add">
          <OfoButton size="sm" :disabled="!editable" @click="change((firewall) => firewall.rules.push(newRule()))">Add rule</OfoButton>
        </div>
        <p class="ofo-muted page__none">
          To: one address, a range such as 192.168.1.10-192.168.1.20, or a block such as 192.168.1.0/28. Ports: one, several, or a range such as 1000-1010.
        </p>
      </OfoFormSection>

      <OfoFormSection title="The router itself" text="What the router answers from the internet.">
        <OfoToggle label="Answer ping from the internet" :model-value="pings" :disabled="!editable" @update:model-value="(on) => change((firewall) => (firewall.wanPing = on))" />
      </OfoFormSection>
    </template>
  </div>
</template>
