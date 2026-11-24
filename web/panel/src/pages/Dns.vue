<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { create, DnsSchema, type Dns, type Record as DnsRecord } from '@openfeo/client'
import { OfoAdvanced, OfoBanner, OfoButton, OfoFormSection, OfoPageHeader, OfoSkeleton, OfoToggle } from '@openfeo/ui'
import { computed, inject, provide, watch } from 'vue'

import { CONFIG } from '../config'
import { FIELDS, forgetFrom, listText, pageFields, parseList } from '../fields'
import { LIVE } from '../live'
import { addressList } from '../model/check'
import { becomes, domainOf, inUse, newRecord, recordProblems, settleDns, setUsesWan, usesWan } from '../model/dns'
import RefusedList from '../parts/RefusedList.vue'
import SettingCell from '../parts/SettingCell.vue'
import SettingField from '../parts/SettingField.vue'

// The DNS page (SPEC §7.7, §8.4): the owner's resolvers and whether the WAN's are used too,
// with the resolvers the router says it is asking now; local names, as a table edited in
// place; and the names let through the rebinding guard, under Advanced. It edits the one
// draft; `dns.blocklists`, which the router has no use for yet, is carried through untouched.
const store = inject(CONFIG)!
const live = inject(LIVE)!
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
const dns = computed(() => draft.value?.dns)
const upstreams = computed(() => dns.value?.upstreams ?? [])
const records = computed(() => dns.value?.records ?? [])
const through = computed(() => dns.value?.rebindAllow ?? [])

/** Change the DNS settings; a router that had none and has none again is left without. */
function change(edit: (dns: Dns) => void): void {
  store.edit((config) => {
    config.dns ??= create(DnsSchema, {})
    edit(config.dns)
    settleDns(config, store.base.value)
  })
}
/** What a list's field was in the router's config; nothing to compare with until that is read. */
function wasList(list: (dns: Dns | undefined) => string[] | undefined): string | undefined {
  return store.base.value === null ? undefined : (list(store.base.value.dns) ?? []).join(', ')
}

// ---- Resolvers ----

function setUpstreams(text: string): void {
  fields.typed.set('dns.upstreams', text)
  change((shown) => (shown.upstreams = parseList(text)))
}
function setWan(on: boolean): void {
  store.edit((config) => setUsesWan(config, on, store.base.value))
}
/** The resolvers the router says it is asking; null until it has said. */
const using = computed(() => (live.state.value === null ? null : inUse(live.state.value.dns)))

// ---- Local names ----

function record(at: number, edit: (record: DnsRecord) => void): void {
  change((shown) => {
    const row = shown.records[at]
    if (row !== undefined) {
      edit(row)
    }
  })
}
function removeRecord(at: number): void {
  change((shown) => shown.records.splice(at, 1))
  // The rows after it each have another place now: what was said of them by place goes too.
  forgetFrom(fields, store, 'dns.records', at)
}
/** The same name as the router has it: by its name and its address's family. */
function wasRecord(row: DnsRecord): DnsRecord | undefined {
  const six = row.address.includes(':')
  return store.base.value?.dns?.records.find((each) => each.name.toLowerCase() === row.name.toLowerCase() && each.address.includes(':') === six)
}
const domain = computed(() => (draft.value === null ? '' : domainOf(draft.value)))
/** A name to show what one with no dot becomes: the first such name in the table, or `www`. */
const example = computed(() => records.value.find((row) => becomes(row.name, domain.value) !== null)?.name.trim().toLowerCase() ?? 'www')

// ---- Protection ----

function setThrough(text: string): void {
  fields.typed.set('dns.rebind_allow', text)
  change((shown) => (shown.rebindAllow = parseList(text)))
}

// ---- What the router refused where no field is ----

/** Whether a field of this page is for `path`, and so says what the router said of it. */
function claimed(path: string): boolean {
  return /^dns\.(upstreams|rebind_allow)(\[|$)/.test(path) || /^dns\.records\[\d+\]\.(name|address)$/.test(path)
}
/**
 * What the router refused that no field here shows: a whole row, a setting of another page.
 * Said above the page, so that pressing Apply changes never looks like nothing happened.
 */
const unplaced = computed(() => store.violations.value.filter((violation) => !claimed(violation.path)))
</script>

<template>
  <div class="page">
    <OfoPageHeader title="DNS" sub="How names are looked up for every device on your network." />
    <OfoBanner v-if="store.readOnly.value" class="readonly" tone="info">{{ store.readOnly.value }}</OfoBanner>
    <RefusedList :violations="unplaced" />
    <template v-if="draft === null">
      <OfoSkeleton :lines="6" />
    </template>
    <template v-else>
      <OfoFormSection title="Resolvers" text="Where the router sends the questions it cannot answer itself.">
        <SettingField
          label="Your own resolvers"
          path="dns.upstreams"
          :value="listText(fields, 'dns.upstreams', upstreams)"
          :was="wasList((each) => each?.upstreams)"
          :means="upstreams.join(', ')"
          :problem="addressList(upstreams.join(', '))"
          help="Asked first, in this order. Leave empty to use only the ones the WAN gives."
          mono
          span
          @update="setUpstreams"
        />
        <div class="ofo-span-2">
          <OfoToggle label="Also use the resolvers the WAN gives" :model-value="usesWan(dns)" :disabled="!editable" @update:model-value="setWan" />
        </div>
        <p v-if="using !== null" class="dns__inuse ofo-field__help ofo-span-2 page__none">
          <template v-if="using.length === 0">In use now: none. Names outside your network cannot be looked up.</template>
          <template v-else>
            In use now:
            <template v-for="(group, n) in using" :key="n">
              <span class="ofo-mono">{{ group.addresses.join(', ') }}</span> {{ group.from }}{{ n === using.length - 1 ? '.' : '; ' }}
            </template>
          </template>
        </p>
      </OfoFormSection>

      <OfoFormSection
        title="Local names"
        text="Names the router answers itself. A device that gives a name with its lease, and every reservation with a name, is already found without a row here."
        plain
      >
        <div v-if="records.length > 0" class="ofo-table-wrap">
          <table class="ofo-table res names">
            <thead>
              <tr>
                <th>Name</th>
                <th>Address</th>
                <th />
              </tr>
            </thead>
            <tbody>
              <tr v-for="(row, n) in records" :key="n">
                <SettingCell
                  :path="`dns.records[${n}].name`"
                  :value="row.name"
                  :problem="recordProblems(records, n).name"
                  mono
                  @update="(text) => record(n, (each) => (each.name = text))"
                />
                <SettingCell
                  :path="`dns.records[${n}].address`"
                  :value="row.address"
                  :was="wasRecord(row)?.address"
                  :problem="recordProblems(records, n).address"
                  mono
                  @update="(text) => record(n, (each) => (each.address = text))"
                />
                <td>
                  <OfoButton size="sm" variant="ghost" :disabled="!editable" @click="removeRecord(n)">Remove</OfoButton>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="res__add">
          <OfoButton size="sm" :disabled="!editable" @click="change((shown) => shown.records.push(newRecord()))">Add name</OfoButton>
        </div>
        <p class="names__note ofo-field__help page__note">
          A name with no dot is under <span class="ofo-mono">{{ domain }}</span
          >: <span class="ofo-mono">{{ example }}</span> is <span class="ofo-mono">{{ example }}.{{ domain }}</span
          >. One name may have an IPv4 and an IPv6 address.
        </p>
      </OfoFormSection>

      <OfoFormSection title="Protection" text="The router drops answers from outside that point at addresses inside your network.">
        <OfoAdvanced :open="through.length > 0 || store.problemAt('dns.rebind_allow') !== undefined">
          <SettingField
            label="Names let through"
            path="dns.rebind_allow"
            :value="listText(fields, 'dns.rebind_allow', through)"
            :was="wasList((each) => each?.rebindAllow)"
            :means="through.join(', ')"
            help="A name here, and everything under it, may answer with a private address."
            mono
            span
            @update="setThrough"
          />
        </OfoAdvanced>
      </OfoFormSection>
    </template>
  </div>
</template>
