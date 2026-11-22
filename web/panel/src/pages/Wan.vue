<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { WanPhase, type Ipv6Wan, type Wan } from '@openfeo/client'
import {
  OfoAdvanced,
  OfoBanner,
  OfoButton,
  OfoChoice,
  OfoChoiceGroup,
  OfoFormSection,
  OfoPageHeader,
  OfoSkeleton,
  OfoTabs,
  OfoToggle,
  type TabEntry,
  type Tone,
} from '@openfeo/ui'
import { computed, inject, provide, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { CONFIG } from '../config'
import { FIELDS, forgetFrom, listText, numberText, pageFields, parseList, toNumber, under } from '../fields'
import { LIVE } from '../live'
import { ipv6On, newWan, portOptions, setIpv6, setType, typeOf, WAN_FIELDS, wanProblems, type WanType } from '../model/wan'
import NameDialog from '../parts/NameDialog.vue'
import RefusedList from '../parts/RefusedList.vue'
import SettingField from '../parts/SettingField.vue'
import { PAGES } from '../routes'

// The WAN page (SPEC §8.4): a tab per WAN, and for the one shown every setting the config
// has for it. It edits the one draft; what it knows beyond arranging fields is model/wan.
const store = inject(CONFIG)!
const live = inject(LIVE)!
const route = useRoute()
const routes = useRouter()
const fields = pageFields()
provide(FIELDS, fields)

/** What was typed for a type, or for IPv6, that has since been switched away from. */
const keptTypes = new Map<string, Wan['kind']>()
const keptV6 = new Map<string, Ipv6Wan>()
// A draft that is another one (discarded, applied, read again with something new in it)
// starts clean: nothing kept from the one before, a typed password least of all, and no
// field counted as left.
watch(
  () => store.draft.value,
  (now, before) => {
    if (now !== before) {
      keptTypes.clear()
      keptV6.clear()
      fields.left.clear()
      fields.typed.clear()
    }
  },
)

const wans = computed(() => store.draft.value?.wans ?? [])
/** The WAN the address names, or the first. */
const index = computed(() => Math.max(0, wans.value.findIndex((each) => each.name === route.params.name)))
const wan = computed(() => wans.value[index.value])
/** The same WAN as the router has it; none for one that is only in the draft. */
const base = computed(() => store.base.value?.wans.find((each) => each.name === wan.value?.name))
const at = computed(() => `wans[${index.value}]`)
const editable = computed(() => store.readOnly.value === null && store.draft.value !== null)

const PHASES: Partial<Record<WanPhase, { text: string; tone: Tone }>> = {
  [WanPhase.UP]: { text: 'up', tone: 'ok' },
  [WanPhase.CONNECTING]: { text: 'connecting', tone: 'info' },
  [WanPhase.DOWN]: { text: 'down', tone: 'danger' },
}

/** Whether a WAN has something wrong that is being shown: the router said so, or a field that was left says so. */
function troubled(at: number): boolean {
  const prefix = `wans[${at}]`
  const typed = wans.value[at]
  return (
    store.violations.value.some((violation) => under(violation.path, prefix)) ||
    (typed !== undefined && Object.keys(wanProblems(typed)).some((path) => fields.left.has(`${prefix}.${path}`)))
  )
}

const tabs = computed<TabEntry[]>(() =>
  wans.value.map((each, at) => {
    const running = live.state.value?.wans.find((state) => state.name === each.name)
    const pill = troubled(at) ? { text: 'problem', tone: 'danger' as const } : running === undefined ? undefined : PHASES[running.phase]
    return pill === undefined ? { id: each.name, label: each.name } : { id: each.name, label: each.name, pill }
  }),
)

/** What the router refused under this WAN at a path no field of the page is for. */
const unplaced = computed(() =>
  store.violations.value.filter((violation) => {
    if (!under(violation.path, at.value)) {
      return false
    }
    const within = violation.path.slice(at.value.length + 1)
    return !WAN_FIELDS.some((field) => under(within, field))
  }),
)
/**
 * What it refused that is not about the WAN shown: another page's, or another WAN's (a clash
 * between two is reported at the later one, which is often not the tab that is open). Said
 * above the page, so that pressing Apply changes never looks like nothing happened.
 */
const elsewhere = computed(() => store.violations.value.filter((violation) => !under(violation.path, at.value)))

const local = computed(() => (wan.value === undefined ? {} : wanProblems(wan.value)))
/** Whether a field of this WAN is showing something wrong. */
function wrong(field: string): boolean {
  const path = `${at.value}.${field}`
  return store.problemAt(path) !== undefined || (fields.left.has(path) && local.value[field] !== undefined)
}

const type = computed(() => (wan.value === undefined ? 'dhcp' : typeOf(wan.value)))
const pppoe = computed(() => (wan.value?.kind.case === 'pppoe' ? wan.value.kind.value : undefined))
const fixed = computed(() => (wan.value?.kind.case === 'static' ? wan.value.kind.value : undefined))
const dhcp = computed(() => (wan.value?.kind.case === 'dhcp' ? wan.value.kind.value : undefined))
const wasPppoe = computed(() => (base.value?.kind.case === 'pppoe' ? base.value.kind.value : undefined))
const wasFixed = computed(() => (base.value?.kind.case === 'static' ? base.value.kind.value : undefined))
const wasDhcp = computed(() => (base.value?.kind.case === 'dhcp' ? base.value.kind.value : undefined))
/** What a field of the type's own table was: nothing to compare with for a WAN that is new, empty where the router has another type. */
function wasOf(value: string | undefined): string | undefined {
  return base.value === undefined ? undefined : (value ?? '')
}
const v6 = computed(() => (wan.value !== undefined && ipv6On(wan.value) ? wan.value.ipv6 : undefined))
const wasV6 = computed(() => (base.value !== undefined && ipv6On(base.value) ? base.value.ipv6 : undefined))
const ports = computed(() => (wan.value === undefined || store.draft.value === null ? [] : portOptions(live.state.value?.ports ?? [], store.draft.value, wan.value)))

/** Change the WAN that is shown. */
function change(edit: (wan: Wan) => void): void {
  store.edit((draft) => {
    const shown = draft.wans[index.value]
    if (shown !== undefined) {
      edit(shown)
    }
  })
}

function show(name: string): void {
  void routes.push(`${PAGES.wan}/${name}`)
}

const adding = ref(false)
const taken = computed(() => [...wans.value.map((each) => each.name), ...(store.draft.value?.lans.map((lan) => lan.name) ?? [])])
function add(name: string): void {
  adding.value = false
  store.edit((draft) => draft.wans.push(newWan(draft, live.state.value?.ports ?? [], name)))
  show(name)
}
function remove(): void {
  const gone = index.value
  const name = wan.value?.name
  store.edit((draft) => draft.wans.splice(gone, 1))
  // The WANs after it each have another place now: what was said of them by place goes too.
  forgetFrom(fields, store, 'wans', gone)
  // And what was typed for it, kept under its name, a password with it: a WAN added under
  // the same name starts from nothing.
  if (name !== undefined) {
    for (const kept of [...keptTypes.keys()]) {
      if (kept.startsWith(`${name}:`)) {
        keptTypes.delete(kept)
      }
    }
    keptV6.delete(name)
  }
  const first = wans.value[0]
  void routes.replace(first === undefined ? PAGES.wan : `${PAGES.wan}/${first.name}`)
}
</script>

<template>
  <div class="page">
    <OfoPageHeader title="WAN" sub="How the router reaches the internet.">
      <template #actions>
        <OfoButton size="sm" :disabled="!editable" @click="adding = true">Add WAN</OfoButton>
      </template>
    </OfoPageHeader>
    <OfoBanner v-if="store.readOnly.value" class="readonly" tone="info">{{ store.readOnly.value }}</OfoBanner>
    <RefusedList :violations="elsewhere" />

    <div v-if="store.draft.value === null" class="dash__waiting" aria-busy="true">
      <OfoSkeleton size="lg" :width="40" />
      <OfoSkeleton :width="80" />
      <OfoSkeleton :width="60" />
    </div>
    <p v-else-if="!wan" class="ofo-muted page__none">No WAN is set up. Without one the router reaches nothing beyond its own LANs.</p>
    <template v-else>
      <div class="tabsrow">
        <OfoTabs :tabs="tabs" :model-value="wan.name" panel="wan-panel" @update:model-value="show" />
      </div>
      <div id="wan-panel" role="tabpanel">
        <RefusedList :violations="unplaced" />

        <OfoFormSection title="Connection" text="How this WAN gets its address from your ISP.">
          <OfoChoiceGroup legend="Type" class="ofo-span-2">
            <OfoChoice
              v-for="choice in [
                { value: 'dhcp', label: 'DHCP', hint: 'The ISP hands out the address.' },
                { value: 'pppoe', label: 'PPPoE', hint: 'You log in with an account.' },
                { value: 'static', label: 'Static', hint: 'You type the address.' },
              ]"
              :key="choice.value"
              type="radio"
              name="wan-type"
              :value="choice.value"
              :label="choice.label"
              :hint="choice.hint"
              :model-value="type"
              :disabled="!editable"
              @update:model-value="(chosen) => change((shown) => setType(shown, chosen as WanType, keptTypes, base))"
            />
          </OfoChoiceGroup>

          <template v-if="pppoe">
            <SettingField
              label="Username"
              :path="`${at}.pppoe.username`"
              :value="pppoe.username"
              :was="wasOf(wasPppoe?.username)"
              mono
              autocomplete="off"
              @update="(text) => change((shown) => shown.kind.case === 'pppoe' && (shown.kind.value.username = text))"
            />
            <SettingField
              label="Password"
              :path="`${at}.pppoe.password`"
              :value="pppoe.password"
              type="password"
              autocomplete="new-password"
              :placeholder="wasPppoe ? 'Unchanged' : undefined"
              :help="wasPppoe ? 'Kept on the router and never shown. Type a new one to change it.' : 'The account\'s password.'"
              @update="(text) => change((shown) => shown.kind.case === 'pppoe' && (shown.kind.value.password = text))"
            />
            <OfoAdvanced :open="pppoe.service !== '' || pppoe.ac !== '' || wrong('pppoe.service') || wrong('pppoe.ac')">
              <SettingField
                label="Service name"
                :path="`${at}.pppoe.service`"
                :value="pppoe.service"
                :was="wasOf(wasPppoe?.service)"
                help="Only connect to this service. Leave empty for any."
                @update="(text) => change((shown) => shown.kind.case === 'pppoe' && (shown.kind.value.service = text))"
              />
              <SettingField
                label="Access concentrator"
                :path="`${at}.pppoe.ac`"
                :value="pppoe.ac"
                :was="wasOf(wasPppoe?.ac)"
                help="Only connect to this one. Leave empty for any."
                @update="(text) => change((shown) => shown.kind.case === 'pppoe' && (shown.kind.value.ac = text))"
              />
            </OfoAdvanced>
          </template>

          <template v-else-if="fixed">
            <SettingField
              label="Address"
              :path="`${at}.static.address`"
              :value="fixed.address"
              :was="wasOf(wasFixed?.address)"
              :problem="local['static.address']"
              help="The address and the size of the ISP's subnet."
              mono
              @update="(text) => change((shown) => shown.kind.case === 'static' && (shown.kind.value.address = text))"
            />
            <SettingField
              label="Gateway"
              :path="`${at}.static.gateway`"
              :value="fixed.gateway"
              :was="wasOf(wasFixed?.gateway)"
              :problem="local['static.gateway']"
              mono
              @update="(text) => change((shown) => shown.kind.case === 'static' && (shown.kind.value.gateway = text))"
            />
            <SettingField
              label="DNS servers"
              :path="`${at}.static.dns`"
              :value="listText(fields, `${at}.static.dns`, fixed.dns)"
              :means="fixed.dns.join(', ')"
              :was="wasOf(wasFixed?.dns.join(', '))"
              :problem="local['static.dns']"
              help="One or more, separated by commas."
              mono
              span
              @update="
                (text) => {
                  fields.typed.set(`${at}.static.dns`, text)
                  change((shown) => shown.kind.case === 'static' && (shown.kind.value.dns = parseList(text)))
                }
              "
            />
          </template>

          <template v-else-if="dhcp">
            <p class="ofo-muted ofo-span-2 page__none">Nothing to fill in: the address, gateway and DNS servers come from the ISP.</p>
            <OfoAdvanced :open="dhcp.hostname !== '' || dhcp.vendorClass !== '' || wrong('dhcp.hostname') || wrong('dhcp.vendor_class')">
              <SettingField
                label="Hostname sent"
                :path="`${at}.dhcp.hostname`"
                :value="dhcp.hostname"
                :was="wasOf(wasDhcp?.hostname)"
                help="Option 12. Leave empty to send none."
                mono
                @update="(text) => change((shown) => shown.kind.case === 'dhcp' && (shown.kind.value.hostname = text))"
              />
              <SettingField
                label="Vendor class sent"
                :path="`${at}.dhcp.vendor_class`"
                :value="dhcp.vendorClass"
                :was="wasOf(wasDhcp?.vendorClass)"
                help="Option 60, for ISPs that ask for one."
                mono
                @update="(text) => change((shown) => shown.kind.case === 'dhcp' && (shown.kind.value.vendorClass = text))"
              />
            </OfoAdvanced>
          </template>
        </OfoFormSection>

        <OfoFormSection title="Port" text="Where the ISP's cable goes, and the VLAN it expects.">
          <SettingField label="Port" :path="`${at}.port`" :value="wan.port" :was="base?.port" :options="ports" @update="(port) => change((shown) => (shown.port = port))" />
          <SettingField
            label="VLAN tag"
            :path="`${at}.vlan`"
            :value="numberText(wan.vlan)"
            :was="base === undefined ? undefined : numberText(base.vlan)"
            :problem="local.vlan"
            help="1 to 4094. Leave empty for a line with no tag."
            mono
            digits
            @update="(text) => change((shown) => (shown.vlan = toNumber(text)))"
          />
          <SettingField
            label="Priority"
            :path="`${at}.priority`"
            :value="String(wan.priority)"
            :was="base === undefined ? undefined : String(base.priority)"
            help="The lowest number wins when more than one WAN is up."
            mono
            digits
            @update="(text) => change((shown) => (shown.priority = toNumber(text)))"
          />
        </OfoFormSection>

        <OfoFormSection title="IPv6" text="Whether this WAN carries IPv6, and the prefix your LANs take theirs from.">
          <OfoToggle class="ofo-span-2" label="IPv6" :model-value="v6 !== undefined" :disabled="!editable" @update:model-value="(on) => change((shown) => setIpv6(shown, on, keptV6, base))" />
          <template v-if="v6">
            <SettingField
              label="Routed prefix"
              :path="`${at}.ipv6.prefix`"
              :value="v6.prefix"
              :was="wasOf(wasV6?.prefix)"
              :problem="local['ipv6.prefix']"
              help="A fixed prefix your ISP routes to you, such as 2001:db8:1::/48. Leave empty to ask the ISP for one."
              mono
              span
              @update="(text) => change((shown) => shown.ipv6 && (shown.ipv6.prefix = text))"
            />
            <OfoAdvanced :open="v6.pdHint !== 0 || v6.gateway !== '' || wrong('ipv6.pd_hint') || wrong('ipv6.gateway')">
              <SettingField
                label="Prefix length to ask for"
                :path="`${at}.ipv6.pd_hint`"
                :value="numberText(v6.pdHint)"
                :was="wasOf(wasV6 === undefined ? undefined : numberText(wasV6.pdHint))"
                :problem="local['ipv6.pd_hint']"
                help="48 to 64, when no prefix is typed."
                placeholder="56"
                mono
                digits
                @update="(text) => change((shown) => shown.ipv6 && (shown.ipv6.pdHint = toNumber(text)))"
              />
              <SettingField
                label="Gateway"
                :path="`${at}.ipv6.gateway`"
                :value="v6.gateway"
                :was="wasOf(wasV6?.gateway)"
                :problem="local['ipv6.gateway']"
                help="Leave empty to learn it from the ISP."
                mono
                @update="(text) => change((shown) => shown.ipv6 && (shown.ipv6.gateway = text))"
              />
            </OfoAdvanced>
          </template>
        </OfoFormSection>

        <div class="page__foot">
          <OfoButton size="sm" variant="ghost" :disabled="!editable" @click="remove">Remove {{ wan.name }}</OfoButton>
        </div>
      </div>
    </template>

    <NameDialog v-if="adding" title="Add a WAN" :taken="taken" :longest="11" @name="add" @cancel="adding = false" />
  </div>
</template>
