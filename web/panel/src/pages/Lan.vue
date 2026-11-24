<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { create, StaticLeaseSchema, type Lan, type LanDhcp, type StaticLease } from '@openfeo/client'
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
} from '@openfeo/ui'
import { computed, inject, provide, ref, watch } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'

import { CONFIG } from '../config'
import { FIELDS, forgetFrom, listText, numberText, pageFields, parseList, toNumber, under } from '../fields'
import { LIVE } from '../live'
import { address4, cidr4 } from '../model/check'
import { durationWords } from '../model/format'
import { format4, parse4, parseCidr4, parseMac } from '../model/ip'
import {
  blockers,
  claimed,
  lanProblems,
  leaseOptions,
  leaseValue,
  newLan,
  portChoices,
  rangeWords,
  setDhcp,
  setLanIpv6,
  setLease,
  sizeOptions,
  stillUnfit,
  unfitWords,
} from '../model/lan'
import { carried } from '../model/renumber'
import NameDialog from '../parts/NameDialog.vue'
import RefusedList from '../parts/RefusedList.vue'
import SettingCell from '../parts/SettingCell.vue'
import SettingField from '../parts/SettingField.vue'
import { PAGES } from '../routes'

// The LAN & DHCP page (SPEC §8.4): a tab per LAN, and for the one shown its address and
// ports, its DHCP server, its reservations and its IPv6. It edits the one draft; what it
// knows beyond arranging fields is model/lan. Changing a LAN's address or size carries along
// every address in the config that lay in its subnet (model/renumber): each field here says
// what it was, and one that found no place says so.
const store = inject(CONFIG)!
const live = inject(LIVE)!
const route = useRoute()
const routes = useRouter()
const fields = pageFields()
provide(FIELDS, fields)

/** The DHCP server of a LAN whose server has since been switched off. */
const keptDhcp = new Map<string, LanDhcp>()
// A draft that is another one (discarded, applied, read again with something new in it) starts clean.
watch(
  () => store.draft.value,
  (now, before) => {
    if (now !== before) {
      keptDhcp.clear()
      fields.left.clear()
      fields.typed.clear()
    }
  },
)

const lans = computed(() => store.draft.value?.lans ?? [])
/** The LAN the address names, or the first. */
const index = computed(() => Math.max(0, lans.value.findIndex((each) => each.name === route.params.name)))
const lan = computed(() => lans.value[index.value])
/** The same LAN as the router has it; none for one that is only in the draft. */
const base = computed(() => store.base.value?.lans.find((each) => each.name === lan.value?.name))
const at = computed(() => `lans[${index.value}]`)
const editable = computed(() => store.readOnly.value === null && store.draft.value !== null)

/** The addresses a renumbering could not place and that are still where it left them. */
const adrift = computed(() => {
  const draft = store.draft.value
  return draft === null ? [] : store.unfit.value.filter((unfit) => stillUnfit(draft, unfit))
})
/** Those that are settings of no LAN: a forward's or a rule's on Firewall, a local name's on DNS. */
const adriftElsewhere = computed(() => adrift.value.filter((unfit) => !unfit.path.startsWith('lans[')))
/** What a field at `path` (or, for a list, beneath it) says when its address found no place. */
function unfitAt(path: string): string | undefined {
  const unfit = adrift.value.find((each) => under(each.path, path))
  return unfit === undefined || store.base.value === null || store.draft.value === null ? undefined : unfitWords(store.base.value, store.draft.value, unfit.value)
}

/** Whether a LAN has something wrong that is being shown. */
function troubled(at: number): boolean {
  const prefix = `lans[${at}]`
  const typed = lans.value[at]
  return (
    store.violations.value.some((violation) => under(violation.path, prefix)) ||
    adrift.value.some((unfit) => under(unfit.path, prefix)) ||
    (typed !== undefined && Object.keys(lanProblems(typed)).some((path) => fields.left.has(`${prefix}.${path}`))) ||
    (fields.left.has(`${prefix}.ipv4`) && fields.typed.has(`${prefix}.ipv4`))
  )
}

const tabs = computed<TabEntry[]>(() =>
  lans.value.map((each, at) => {
    const running = live.state.value?.lans.find((state) => state.name === each.name)
    const entry: TabEntry = { id: each.name, label: each.name }
    if (running !== undefined) {
      entry.count = `${running.leases} client${running.leases === 1 ? '' : 's'}`
    }
    if (troubled(at)) {
      entry.pill = { text: 'problem', tone: 'danger' }
    }
    return entry
  }),
)

/** What the router refused under this LAN at a path no field of the page is for. */
const unplaced = computed(() => store.violations.value.filter((violation) => under(violation.path, at.value) && !claimed(violation.path.slice(at.value.length + 1))))
/**
 * What it refused that is not about the LAN shown: another page's, or another LAN's (a clash
 * between two is reported at the later one, which is often not the tab that is open). Said
 * above the page, so that pressing Apply changes never looks like nothing happened.
 */
const elsewhere = computed(() => store.violations.value.filter((violation) => !under(violation.path, at.value)))

const local = computed(() => (lan.value === undefined ? {} : lanProblems(lan.value)))
function wrong(field: string): boolean {
  const path = `${at.value}.${field}`
  return store.problemAt(path) !== undefined || (fields.left.has(path) && local.value[field] !== undefined)
}

/** Change the LAN that is shown. */
function change(edit: (lan: Lan) => void): void {
  store.edit((draft) => {
    const shown = draft.lans[index.value]
    if (shown !== undefined) {
      edit(shown)
    }
  })
}

// ---- The address and the size ----

const subnet = computed(() => parseCidr4(lan.value?.ipv4 ?? ''))
const wasSubnet = computed(() => parseCidr4(base.value?.ipv4 ?? ''))
/** The size chosen: the subnet's, or for a LAN with no address yet the one picked for when it has. */
const prefix = computed(() => subnet.value?.prefix ?? Number(fields.typed.get(`${at.value}.size`) ?? 24))
/** The address as it is being typed, until the field is left with something that is one. */
const addressText = computed(() => fields.typed.get(`${at.value}.ipv4`) ?? (subnet.value === null ? '' : format4(subnet.value.address)))
const addressProblem = computed(() => {
  const typed = fields.typed.get(`${at.value}.ipv4`)
  return typed === undefined ? null : typed.includes('/') ? cidr4(typed) : address4(typed)
})

/**
 * The LAN's address or size was taken, and the addresses of this LAN that follow it may have
 * moved. Their fields count as left: what the move made of them is said at once, and not
 * first when Apply changes is pressed. A pool whose start was carried past its end is the
 * case that matters: each end has a place, and together they are no pool.
 */
function leaveCarried(): void {
  const rows = lan.value?.dhcp?.static
  if (rows === undefined) {
    return
  }
  for (const field of ['dhcp.range', 'dhcp.range[1]', 'dhcp.dns', 'dhcp.ntp', ...rows.map((_, row) => `dhcp.static[${row}].ip`)]) {
    fields.left.add(`${at.value}.${field}`)
  }
}

/** The address field was left: an address (alone, or with its size) is taken, and what lay in the subnet follows. */
function leaveAddress(): void {
  const typed = fields.typed.get(`${at.value}.ipv4`)
  if (typed === undefined || lan.value === undefined) {
    return
  }
  const whole = typed === '' || typed.includes('/') ? typed : `${typed}/${prefix.value}`
  if (whole === '' || parseCidr4(whole) !== null) {
    store.setLanAddress(lan.value.name, whole)
    fields.typed.delete(`${at.value}.ipv4`)
    if (whole !== '') {
      leaveCarried()
    }
  }
}

function setSize(size: string): void {
  if (lan.value === undefined) {
    return
  }
  const typed = fields.typed.get(`${at.value}.ipv4`)
  const address = typed !== undefined && parse4(typed) !== null ? typed : subnet.value === null ? null : format4(subnet.value.address)
  if (address === null) {
    // No address yet: the size waits for one.
    fields.typed.set(`${at.value}.size`, size)
  } else {
    store.setLanAddress(lan.value.name, `${address}/${size}`)
    fields.typed.delete(`${at.value}.ipv4`)
    leaveCarried()
  }
}

/** Said of a field whose address is what the renumbering made of the router's: it moved with the subnet. */
function moved(was: string | undefined, now: string): string | undefined {
  if (was === undefined || base.value === undefined || lan.value === undefined || base.value.ipv4 === lan.value.ipv4) {
    return undefined
  }
  return was !== now && carried(was, base.value.ipv4, lan.value.ipv4) === now ? 'Moved with the subnet.' : undefined
}

// ---- Ports and what it may reach ----

const ports = computed(() => (lan.value === undefined || store.draft.value === null ? [] : portChoices(live.state.value?.ports ?? [], store.draft.value, lan.value)))
function tick(port: string, ticked: boolean): void {
  change((shown) => {
    shown.ports = ticked ? [...shown.ports.filter((member) => member !== port), port] : shown.ports.filter((member) => member !== port)
  })
  // What the router refused at a port is kept by the port's place in the list, which is another list now.
  store.violations.value = store.violations.value.filter((violation) => !under(violation.path, `${at.value}.ports`))
}
/** What this LAN may start connections to, in words: an empty list is the internet alone. */
const reach = computed(() => {
  const may = lan.value === undefined || lan.value.reaches.length === 0 ? ['wan'] : lan.value.reaches.filter((name) => name !== 'none')
  return may.length === 0 ? 'nothing' : may.map((name) => (name === 'wan' ? 'the internet' : name)).join(', ')
})

// ---- DHCP ----

const dhcp = computed(() => lan.value?.dhcp)
const wasDhcp = computed(() => base.value?.dhcp)
/** What a field of the DHCP server was: nothing to compare with on a LAN that is new, empty where the router runs no server. */
function wasOf(value: string | undefined): string | undefined {
  return base.value === undefined ? undefined : (value ?? '')
}
function setRange(end: 0 | 1, text: string): void {
  change((shown) => {
    if (shown.dhcp !== undefined) {
      const range = [shown.dhcp.range[0] ?? '', shown.dhcp.range[1] ?? '']
      range[end] = text
      shown.dhcp.range = range.every((each) => each === '') ? [] : range
    }
  })
}

const leaseWords = (secs: number) => durationWords(secs === 0 ? 43_200 : secs)
/** Other was chosen, or the time is none of the four. */
const otherLease = computed(() => dhcp.value !== undefined && (fields.typed.has(`${at.value}.lease`) || leaseValue(dhcp.value.leaseSecs) === 'other'))
function chooseLease(choice: string): void {
  if (choice === 'other') {
    fields.typed.set(`${at.value}.lease`, 'other')
    return
  }
  fields.typed.delete(`${at.value}.lease`)
  change((shown) => shown.dhcp !== undefined && setLease(shown.dhcp, Number(choice), wasDhcp.value))
}

// ---- Reservations ----

/** A reservation is the same one when its MAC is (every one the router takes has a MAC), or its client identifier while it has none. */
const key = (lease: StaticLease) => (lease.mac !== '' ? lease.mac : `id:${lease.clientId}`)
/** The same reservation as the router has it. */
function wasLease(lease: StaticLease): StaticLease | undefined {
  return key(lease) === 'id:' ? undefined : wasDhcp.value?.static.find((each) => key(each) === key(lease))
}
/**
 * Matched by client identifier: shown and kept, and only to be removed. The router matches
 * by the identifier whenever there is one, and still wants a MAC on every reservation, so
 * such a reservation has both and its MAC decides nothing.
 */
const byIdentifier = (lease: StaticLease) => lease.clientId !== ''
function lease(at: number, edit: (lease: StaticLease) => void): void {
  change((shown) => {
    const row = shown.dhcp?.static[at]
    if (row !== undefined) {
      edit(row)
    }
  })
}
/** Take a reservation away, and with it what was said of the rows whose places change. */
function removeLease(row: number): void {
  change((shown) => shown.dhcp?.static.splice(row, 1))
  forgetFrom(fields, store, `${at.value}.dhcp.static`, row)
}
/** What the router said of a reservation as a whole, or of its identifier: said under its name. */
function rowProblem(row: number): string | undefined {
  const path = `${at.value}.dhcp.static[${row}]`
  return store.violations.value.find((violation) => violation.path === path || under(violation.path, `${path}.client_id`))?.message
}
/** The start of an address in this subnet, for an empty address to hint at: `192.168.1.` */
const leading = computed(() => {
  if (subnet.value === null) {
    return undefined
  }
  const fixed = Math.floor(subnet.value.prefix / 8)
  return fixed === 0 || fixed === 4 ? undefined : `${format4(subnet.value.address).split('.').slice(0, fixed).join('.')}.`
})

// ---- IPv6 ----

const carries6 = computed(() => lan.value !== undefined && lan.value.ipv6 !== 'none')
const had6 = computed(() => (base.value !== undefined && base.value.ipv6 !== 'none' ? base.value : undefined))

// ---- Tabs, adding and removing ----

function show(name: string): void {
  void routes.push(`${PAGES.lan}/${name}`)
}

const adding = ref(false)
const taken = computed(() => [...(store.draft.value?.wans.map((wan) => wan.name) ?? []), ...lans.value.map((each) => each.name)])
function add(name: string): void {
  adding.value = false
  store.edit((draft) => draft.lans.push(newLan(name)))
  show(name)
}
/** What still points at this LAN: it cannot go until each is removed where it is edited, on Firewall. */
const inTheWay = computed(() => (lan.value === undefined || store.draft.value === null ? [] : blockers(store.draft.value, lan.value)))
function remove(): void {
  const gone = index.value
  const name = lan.value?.name
  store.edit((draft) => draft.lans.splice(gone, 1))
  // The LANs after it each have another place now: what was said of them by place goes too.
  forgetFrom(fields, store, 'lans', gone)
  // And the DHCP server kept under its name: a LAN added under the same name starts from nothing.
  if (name !== undefined) {
    keptDhcp.delete(name)
  }
  const first = lans.value[0]
  void routes.replace(first === undefined ? PAGES.lan : `${PAGES.lan}/${first.name}`)
}
</script>

<template>
  <div class="page">
    <OfoPageHeader title="LAN &amp; DHCP" sub="The networks behind the router, and the addresses it hands out.">
      <template #actions>
        <OfoButton size="sm" :disabled="!editable" @click="adding = true">Add LAN</OfoButton>
      </template>
    </OfoPageHeader>
    <OfoBanner v-if="store.readOnly.value" class="readonly" tone="info">{{ store.readOnly.value }}</OfoBanner>
    <RefusedList :violations="elsewhere" />
    <OfoBanner v-if="adriftElsewhere.length > 0" class="unfit" tone="warn" title="These addresses have no place in the new subnet">
      <ul class="said__list">
        <li v-for="unfit in adriftElsewhere" :key="unfit.path">
          <code class="ofo-mono">{{ unfit.path }}</code>: {{ unfit.value }}
        </li>
      </ul>
      <p class="said__line">
        They are set on other pages: a forward or a rule on <RouterLink :to="PAGES.firewall">Firewall</RouterLink>, a local name on DNS. Choose a subnet they fit in, or change them
        there first.
      </p>
    </OfoBanner>

    <div v-if="store.draft.value === null" class="dash__waiting" aria-busy="true">
      <OfoSkeleton size="lg" :width="40" />
      <OfoSkeleton :width="80" />
      <OfoSkeleton :width="60" />
    </div>
    <p v-else-if="!lan" class="ofo-muted page__none">No LAN is set up. Without one nothing is behind the router.</p>
    <template v-else>
      <div class="tabsrow">
        <OfoTabs :tabs="tabs" :model-value="lan.name" panel="lan-panel" @update:model-value="show" />
      </div>
      <div id="lan-panel" role="tabpanel">
        <RefusedList :violations="unplaced" />

        <OfoFormSection title="Network" text="The router's own address on this LAN, the size of the subnet, and the ports that belong to it.">
          <SettingField
            label="Router address"
            :path="`${at}.ipv4`"
            :value="addressText"
            :means="subnet === null ? '' : format4(subnet.address)"
            :was="base === undefined ? undefined : wasSubnet === null ? '' : format4(wasSubnet.address)"
            :problem="addressProblem"
            mono
            @update="(text) => fields.typed.set(`${at}.ipv4`, text)"
            @left="leaveAddress"
          />
          <SettingField
            label="Subnet size"
            :path="`${at}.ipv4.size`"
            :value="String(prefix)"
            :options="sizeOptions(prefix)"
            :means="`/${prefix}`"
            :was="wasSubnet === null ? undefined : `/${wasSubnet.prefix}`"
            :help="rangeWords(lan.ipv4)"
            @update="setSize"
          />
          <OfoChoiceGroup legend="Ports" class="ofo-span-2">
            <OfoChoice
              v-for="port in ports"
              :key="port.name"
              :label="port.name"
              :hint="port.hint"
              :model-value="port.ticked"
              :disabled="port.fixed || !editable"
              @update:model-value="(ticked) => tick(port.name, ticked === true)"
            />
            <span v-if="ports.length === 0" class="ofo-muted">No port is free.</span>
          </OfoChoiceGroup>
          <p class="reach ofo-muted ofo-span-2 page__none">May reach: {{ reach }}. Changed on the <RouterLink :to="PAGES.firewall">Firewall</RouterLink> page.</p>
        </OfoFormSection>

        <OfoFormSection title="DHCP" text="The addresses the router hands out on this LAN, and what it tells each device.">
          <OfoToggle
            class="ofo-span-2"
            label="DHCP server"
            :model-value="dhcp !== undefined"
            :disabled="!editable"
            @update:model-value="(on) => change((shown) => setDhcp(shown, on, keptDhcp, base))"
          />
          <template v-if="dhcp">
            <SettingField
              label="Pool start"
              :path="`${at}.dhcp.range`"
              :value="dhcp.range[0] ?? ''"
              :was="wasOf(wasDhcp?.range[0])"
              :note="moved(wasDhcp?.range[0], dhcp.range[0] ?? '')"
              :problem="local['dhcp.range']"
              :error="unfitAt(`${at}.dhcp.range[0]`)"
              mono
              @update="(text) => setRange(0, text)"
            />
            <SettingField
              label="Pool end"
              :path="`${at}.dhcp.range[1]`"
              :value="dhcp.range[1] ?? ''"
              :was="wasOf(wasDhcp?.range[1])"
              :note="moved(wasDhcp?.range[1], dhcp.range[1] ?? '')"
              :problem="local['dhcp.range[1]']"
              :error="unfitAt(`${at}.dhcp.range[1]`)"
              mono
              @update="(text) => setRange(1, text)"
            />
            <SettingField
              label="Lease time"
              :path="`${at}.dhcp.lease_secs.choice`"
              :value="otherLease ? 'other' : leaseValue(dhcp.leaseSecs)"
              :options="leaseOptions()"
              :means="leaseWords(dhcp.leaseSecs)"
              :was="wasDhcp === undefined ? undefined : leaseWords(wasDhcp.leaseSecs)"
              @update="chooseLease"
            />
            <SettingField
              v-if="otherLease"
              label="Seconds"
              :path="`${at}.dhcp.lease_secs`"
              :value="String(dhcp.leaseSecs === 0 ? 43200 : dhcp.leaseSecs)"
              :problem="local['dhcp.lease_secs']"
              help="How long a device keeps its address before asking again."
              mono
              digits
              @update="(text) => change((shown) => shown.dhcp !== undefined && setLease(shown.dhcp, toNumber(text), wasDhcp))"
            />
            <span v-else />
            <SettingField
              label="DNS servers handed out"
              :path="`${at}.dhcp.dns`"
              :value="listText(fields, `${at}.dhcp.dns`, dhcp.dns)"
              :means="dhcp.dns.join(', ')"
              :was="wasOf(wasDhcp?.dns.join(', '))"
              :note="moved(wasDhcp?.dns.join(', '), dhcp.dns.join(', '))"
              :problem="local['dhcp.dns']"
              :error="unfitAt(`${at}.dhcp.dns`)"
              help="Leave empty for the router itself."
              placeholder="The router"
              mono
              @update="
                (text) => {
                  fields.typed.set(`${at}.dhcp.dns`, text)
                  change((shown) => shown.dhcp !== undefined && (shown.dhcp.dns = parseList(text)))
                }
              "
            />
            <SettingField
              label="NTP servers handed out"
              :path="`${at}.dhcp.ntp`"
              :value="listText(fields, `${at}.dhcp.ntp`, dhcp.ntp)"
              :means="dhcp.ntp.join(', ')"
              :was="wasOf(wasDhcp?.ntp.join(', '))"
              :note="moved(wasDhcp?.ntp.join(', '), dhcp.ntp.join(', '))"
              :problem="local['dhcp.ntp']"
              :error="unfitAt(`${at}.dhcp.ntp`)"
              help="Leave empty for the router itself."
              placeholder="The router"
              mono
              @update="
                (text) => {
                  fields.typed.set(`${at}.dhcp.ntp`, text)
                  change((shown) => shown.dhcp !== undefined && (shown.dhcp.ntp = parseList(text)))
                }
              "
            />
          </template>
        </OfoFormSection>

        <OfoFormSection v-if="dhcp" title="Reservations" text="Devices that always get the same address, and the name they are found by." plain>
          <div class="ofo-table-wrap">
            <table class="ofo-table res">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>MAC address</th>
                  <th>Address</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                <tr v-for="(row, n) in dhcp.static" :key="n">
                  <SettingCell
                    :path="`${at}.dhcp.static[${n}].hostname`"
                    :value="row.hostname"
                    :was="wasLease(row)?.hostname"
                    :error="rowProblem(n)"
                    :fixed="byIdentifier(row)"
                    placeholder="Optional"
                    @update="(text) => lease(n, (each) => (each.hostname = text))"
                  />
                  <td v-if="byIdentifier(row)">
                    <code class="ofo-mono">{{ row.clientId }}</code>
                    <span class="ofo-field__help">Matched by this client identifier.{{ row.mac === '' ? '' : ` Its MAC address is ${row.mac}.` }}</span>
                  </td>
                  <SettingCell
                    v-else
                    :path="`${at}.dhcp.static[${n}].mac`"
                    :value="row.mac"
                    :was="wasLease(row)?.mac"
                    :problem="local[`dhcp.static[${n}].mac`]"
                    placeholder="02:00:00:00:00:00"
                    mono
                    @update="(text) => lease(n, (each) => (each.mac = parseMac(text) ?? text))"
                  />
                  <SettingCell
                    :path="`${at}.dhcp.static[${n}].ip`"
                    :value="row.ip"
                    :was="wasLease(row)?.ip"
                    :note="moved(wasLease(row)?.ip, row.ip)"
                    :problem="local[`dhcp.static[${n}].ip`]"
                    :error="unfitAt(`${at}.dhcp.static[${n}].ip`)"
                    :fixed="byIdentifier(row)"
                    :placeholder="leading"
                    mono
                    @update="(text) => lease(n, (each) => (each.ip = text))"
                  />
                  <td>
                    <OfoButton size="sm" variant="ghost" :disabled="!editable" @click="removeLease(n)">Remove</OfoButton>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="res__add">
            <OfoButton size="sm" :disabled="!editable" @click="change((shown) => shown.dhcp?.static.push(create(StaticLeaseSchema, {})))">Add reservation</OfoButton>
          </div>
        </OfoFormSection>

        <OfoFormSection title="IPv6" text="Whether this LAN carries IPv6 and tells devices about it.">
          <OfoToggle label="IPv6" :model-value="carries6" :disabled="!editable" @update:model-value="(on) => change((shown) => setLanIpv6(shown, on, base))" />
          <template v-if="carries6">
            <OfoToggle
              label="Router advertisements"
              :model-value="lan.ra !== false"
              :disabled="!editable"
              @update:model-value="(on) => change((shown) => (shown.ra = on ? (had6?.ra === true ? true : undefined) : false))"
            />
            <OfoAdvanced :open="lan.ipv6 !== '' || lan.ipv6Index !== 0 || wrong('ipv6') || wrong('ipv6_index')">
              <SettingField
                label="Routed /64"
                :path="`${at}.ipv6`"
                :value="lan.ipv6"
                :was="base === undefined ? undefined : (had6?.ipv6 ?? '')"
                :problem="local.ipv6"
                help="This LAN's own /64 inside the WAN's routed prefix."
                mono
                @update="(text) => change((shown) => (shown.ipv6 = text))"
              />
              <SettingField
                label="Subnet number"
                :path="`${at}.ipv6_index`"
                :value="numberText(lan.ipv6Index)"
                :was="base === undefined ? undefined : numberText(had6?.ipv6Index ?? 0)"
                :problem="local.ipv6_index"
                :placeholder="String(index + 1)"
                help="This LAN's place in a prefix the ISP delegates."
                mono
                digits
                @update="(text) => change((shown) => (shown.ipv6Index = toNumber(text)))"
              />
            </OfoAdvanced>
          </template>
        </OfoFormSection>

        <div class="page__foot">
          <OfoButton size="sm" variant="ghost" :disabled="!editable || inTheWay.length > 0" @click="remove">Remove {{ lan.name }}</OfoButton>
          <span v-if="editable && inTheWay.length > 0" class="ofo-muted page__why">
            Cannot be removed yet:
            <template v-for="(each, n) in inTheWay" :key="each.text">
              <RouterLink :to="PAGES.firewall">{{ each.text }}</RouterLink>{{ n === inTheWay.length - 1 ? '.' : '; ' }}
            </template>
          </span>
        </div>
      </div>
    </template>

    <NameDialog v-if="adding" title="Add a LAN" :taken="taken" :longest="12" @name="add" @cancel="adding = false" />
  </div>
</template>
