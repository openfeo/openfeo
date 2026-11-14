// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// Changing the router's config from the panel (SPEC §8.4). The panel holds one draft of the
// whole config, in this tab's memory and nowhere else: every page edits its own fields of
// it, and the whole of it is sent back, so what no page shows is carried through unchanged.
// What has changed is the difference between the draft and the config it was read from.
//
// An apply is pending until it is confirmed, and the router goes back by itself when it is
// not (SPEC §5.5). What became of a change is the router's to say, and it says it in three
// places: its state (whether a change is pending), its config and tag, and its events. The
// store reads them and never guesses: an apply that was not answered, because the change
// took away the address the answer would have come back to, is settled by what the router
// says when it is next reached.

import { clone, ConfigSchema, equals, type Caller, type Config, type ConfigEffect, type ConfigView, type ConfigViolation, type Event, type PendingConfig } from '@openfeo/client'
import { computed, effectScope, ref, shallowRef, watch, type ComputedRef, type EffectScope, type InjectionKey, type Ref } from 'vue'

import type { LiveData } from './live'
import { changes as changesOf, type Change } from './model/changes'
import { renumber, type Unfit } from './model/renumber'
import type { PanelRouter } from './session'

/** Something the pages say above themselves until it is dismissed or replaced. */
export type Notice =
  /** The config was changed from another session while this draft had changes of its own. */
  | { kind: 'changed-elsewhere' }
  /** A change went back: by hand, by its window running out, or nobody here saw why. */
  | { kind: 'reverted'; why: 'asked' | 'timeout' | 'unknown'; appliedAt: Date | null; draftKept: boolean }
  /** The change took away the address this tab reached the router at: its name, and where it is now ('' when its LAN is gone). */
  | { kind: 'moved'; name: string; address: string }
  /** The router's own words for an apply, a confirm or a revert it refused. */
  | { kind: 'refused'; message: string }

/** What the dialog shows before an apply: the draft's changes, and what the router says they do. */
export interface Review {
  changes: Change[]
  effects: ConfigEffect[]
  caller: Caller | undefined
}

export interface ConfigStore {
  /** The config as the router has it, its secrets empty; `null` until it is first read. */
  base: Ref<Config | null>
  /** What the pages edit: a copy of `base`, changed. Edited through {@link edit} alone. */
  draft: Ref<Config | null>
  /** The window the router gives an apply, in seconds. */
  confirmSecs: Ref<number>
  /** What applying the draft would alter. */
  changes: ComputedRef<Change[]>
  /** What the router found wrong with the draft when it was last reviewed. */
  violations: Ref<ConfigViolation[]>
  /** The addresses the last renumbering of a LAN could not place. */
  unfit: Ref<Unfit[]>
  /** Why nothing may be changed, or `null`. */
  readOnly: ComputedRef<string | null>
  /** The change that is waiting to be confirmed, whoever applied it. */
  pending: ComputedRef<PendingConfig | undefined>
  notice: Ref<Notice | null>
  /** A review, an apply, a confirm or a revert is under way. */
  busy: Ref<boolean>
  /** Change the draft. Does nothing on a router that takes no changes. */
  edit(change: (draft: Config) => void): void
  /** Set a LAN's address and, when the old and the new are both valid, carry what lay in its subnet along. */
  setLanAddress(lan: string, ipv4: string): void
  /** The message of a violation at `path` or beneath it. */
  problemAt(path: string): string | undefined
  /** Make the draft the router's config again. */
  discard(): void
  /** Have the router validate the draft. `null` when it has violations, which are then in `violations`. */
  review(): Promise<Review | null>
  /** Apply the draft that was reviewed: pending until confirmed, or at once and for good. */
  apply(review: Review, immediate: boolean): Promise<void>
  confirm(): Promise<void>
  revert(): Promise<void>
  /** Start reading the router's config and following what becomes of it. */
  start(): void
  stop(): void
}

const READ_ONLY = 'The router refused its config file and runs on defaults. Mend or remove the file to change settings here.'

/**
 * How far the uptime a pending change was applied at may be from when this tab's apply was
 * answered and still be that apply's change. Nothing else can be applied while one is pending.
 */
const OURS_WITHIN_MS = 60_000

/** The change this tab applied, until the router has said what became of it. */
interface Mine {
  /** What was sent: the draft as it was, a typed password included. It becomes the draft again if the change is reverted. */
  sent: Config
  /** The tag of the config it was edited from. */
  fromTag: string
  /** `false` while the apply has had no answer and the router has not yet said whether it took it. */
  answered: boolean
  immediate: boolean
  /** The router's uptime when the apply returned, where known. */
  at: number | undefined
  /** The pending change that is this one, by when the router says it was applied. */
  applied: bigint | null
  /** For an apply with no answer: a read made since, and whether the state has been heard since. */
  read: ConfigView | null
  stateSeen: boolean
}

/** The pending change the state last showed. */
interface Watched {
  applied: bigint
  /** When that was, by the browser's clock. */
  appliedAt: Date | null
  /** The tag read while it was pending. */
  tag: string | null
  /** The state no longer shows it. */
  gone: boolean
  /** The config has been read since it went. */
  readSinceGone: boolean
}

function withoutPasswords(config: Config): Config {
  const copy = clone(ConfigSchema, config)
  for (const wan of copy.wans) {
    if (wan.kind.case === 'pppoe') {
      wan.kind.value.password = ''
    }
  }
  return copy
}

function whyOf(event: Event): 'asked' | 'timeout' | 'unknown' {
  const why = event.fields.why
  return why === 'asked' || why === 'timeout' ? why : 'unknown'
}

/**
 * The store of one router's config for one tab. `host` is the router's full name, for the
 * tab that a change leaves behind to say where the router went.
 */
export function useConfig(router: PanelRouter, live: LiveData, host: () => string): ConfigStore {
  const base = shallowRef<Config | null>(null)
  // Reactive all the way down: a page that shows one field of one WAN is told when that
  // field changes, and `changes` when anything does.
  const draft = ref(null) as Ref<Config | null>
  const confirmSecs = ref(120)
  const violations = ref<ConfigViolation[]>([])
  const unfit = ref<Unfit[]>([])
  const notice = ref<Notice | null>(null)
  const busy = ref(false)
  const changes = computed(() => (base.value === null || draft.value === null ? [] : changesOf(base.value, draft.value)))
  const pending = computed(() => live.state.value?.system?.pendingConfig)
  const readOnly = computed(() => (live.state.value?.system?.configProblem === undefined ? null : READ_ONLY))

  /** The tag of `base`. */
  let tag = ''
  let mine: Mine | null = null
  let watched: Watched | null = null
  /** The change whose going back was said with no reason, for the event that may yet give one. */
  let saidUnknown: bigint | null = null
  /** The `moved` notice is up and the connection has been lost since: the next read is the router found again. */
  let leftBehind = false
  /** The newest config event already acted on. */
  let lastEvent = ''

  let reading = false
  let again = false
  let scope: EffectScope | undefined
  let unhearEnd: (() => void) | undefined
  let asking = false

  function refused(error: unknown): void {
    notice.value = { kind: 'refused', message: error instanceof Error ? error.message : String(error) }
  }

  /** Read the config. One read at a time: asked for during a read, it is read once more after. */
  async function read(): Promise<void> {
    if (reading) {
      again = true
      return
    }
    reading = true
    try {
      do {
        again = false
        let view: ConfigView
        try {
          view = await router.config()
        } catch {
          // Not reachable, or no longer logged in: read again when the socket next opens.
          break
        }
        if (scope === undefined) {
          break
        }
        took(view)
      } while (again)
    } finally {
      reading = false
    }
  }

  /** The router's config was read. */
  function took(view: ConfigView): void {
    const first = base.value === null
    const changed = changes.value.length > 0
    const another = !first && view.tag !== tag
    base.value = view.config
    tag = view.tag
    confirmSecs.value = view.confirmSecs
    if (leftBehind && notice.value?.kind === 'moved') {
      notice.value = null
    }
    leftBehind = false
    if (mine !== null && !mine.answered) {
      // The draft waits for the router to say whether it took the apply.
      mine.read = view
      settleUnanswered()
    } else if (first || !changed) {
      draft.value = clone(ConfigSchema, view.config)
    } else if (another && notice.value?.kind !== 'refused') {
      // (A refusal that is already up says it in the router's own words.)
      notice.value = { kind: 'changed-elsewhere' }
    }
    if (watched !== null) {
      if (watched.gone) {
        watched.readSinceGone = true
      } else {
        watched.tag = view.tag
      }
    }
    settlePending()
  }

  /** An apply that had no answer: once the config has been read and the state heard, the router has said. */
  function settleUnanswered(): void {
    if (mine === null || mine.answered || mine.read === null || !mine.stateSeen || base.value === null) {
      return
    }
    const now = pending.value
    if (mine.read.tag !== mine.fromTag || now !== undefined) {
      // Taken. A draft nobody touched since is the router's config now.
      if (draft.value === null || equals(ConfigSchema, draft.value, mine.sent)) {
        draft.value = clone(ConfigSchema, base.value)
      }
      if (now !== undefined && !mine.immediate) {
        mine.answered = true
        mine.applied = now.appliedUptimeMs
      } else {
        mine = null
      }
    } else {
      // Neither pending nor in force: refused where nobody heard, or gone back already.
      draft.value = clone(ConfigSchema, mine.sent)
      mine = null
      notice.value = { kind: 'reverted', why: 'unknown', appliedAt: null, draftKept: true }
    }
  }

  /** What became of a change that is no longer pending, when the router has said enough to tell. */
  function outcome(change: Watched): { reverted: boolean; why: 'asked' | 'timeout' | 'unknown' } | null {
    if (!change.readSinceGone) {
      return null
    }
    const said = live.events.value.find((event) => (event.topic === 'config.reverted' || event.topic === 'config.confirmed') && event.uptimeMs >= change.applied)
    if (said !== undefined) {
      return { reverted: said.topic === 'config.reverted', why: whyOf(said) }
    }
    // No event yet. Another tag than the one read while it was pending is the old config
    // back; so is a router that has been up for less time than when the change was applied.
    // Two configs that differ only in a password share a tag, so a tag that is the same says
    // nothing: the event, when it comes, will.
    const up = live.sinceBootMs.value
    if ((change.tag !== null && tag !== change.tag) || (up !== undefined && up < Number(change.applied))) {
      return { reverted: true, why: 'unknown' }
    }
    return null
  }

  function settlePending(): void {
    if (watched === null || !watched.gone) {
      return
    }
    const became = outcome(watched)
    if (became === null) {
      return
    }
    const change = watched
    watched = null
    const own = mine !== null && mine.answered && mine.applied === change.applied ? mine : null
    if (own !== null) {
      mine = null
    }
    if (!became.reverted) {
      // Confirmed: it is the router's config, and nothing is said.
      return
    }
    if (own !== null) {
      // The tab that made the change has its changes back, over the config just read.
      draft.value = clone(ConfigSchema, own.sent)
    }
    notice.value = { kind: 'reverted', why: became.why, appliedAt: change.appliedAt, draftKept: own !== null }
    saidUnknown = became.why === 'unknown' ? change.applied : null
  }

  /** The state changed: a change is pending, is another one, or is no longer. */
  function stateChanged(): void {
    if (mine !== null && !mine.answered) {
      mine.stateSeen = true
    }
    const now = pending.value
    if (now !== undefined) {
      if (watched === null || watched.applied !== now.appliedUptimeMs) {
        const up = live.sinceBootMs.value
        watched = {
          applied: now.appliedUptimeMs,
          appliedAt: up === undefined ? null : new Date(live.now.value.getTime() - Math.max(0, up - Number(now.appliedUptimeMs))),
          tag: null,
          gone: false,
          readSinceGone: false,
        }
        if (mine !== null && mine.answered) {
          const ours = mine.applied === null ? mine.at === undefined || Math.abs(Number(now.appliedUptimeMs) - mine.at) < OURS_WITHIN_MS : mine.applied === now.appliedUptimeMs
          if (ours) {
            mine.applied = now.appliedUptimeMs
            // This tab knows the tag of what it applied without reading it.
            watched.tag = tag
          } else {
            mine = null
          }
        }
        void read()
      }
    } else if (watched !== null && !watched.gone) {
      watched.gone = true
      void read()
    }
    settleUnanswered()
    settlePending()
  }

  /** An event came: one about the config is a reason to read it, and may say why a change went back. */
  function eventsChanged(): void {
    const newest = live.events.value.find((event) => event.topic.startsWith('config.'))
    const key = newest === undefined ? '' : `${newest.topic} ${newest.uptimeMs} ${newest.timeUnixMs}`
    if (key === lastEvent) {
      return
    }
    lastEvent = key
    if (newest === undefined) {
      return
    }
    if (notice.value?.kind === 'reverted' && notice.value.why === 'unknown' && saidUnknown !== null && newest.topic === 'config.reverted' && newest.uptimeMs >= saidUnknown) {
      notice.value = { ...notice.value, why: whyOf(newest) }
      saidUnknown = null
    }
    void read()
    settlePending()
  }

  function ask(event: BeforeUnloadEvent): void {
    event.preventDefault()
  }

  /** Leaving the page asks first while the draft has changes, and only then. */
  function guard(dirty: boolean): void {
    if (dirty && !asking) {
      window.addEventListener('beforeunload', ask)
      asking = true
    } else if (!dirty && asking) {
      window.removeEventListener('beforeunload', ask)
      asking = false
    }
  }

  /** The session is over: the draft may hold a typed password, and goes with everything remembered of it. */
  function forget(): void {
    base.value = null
    draft.value = null
    tag = ''
    mine = null
    watched = null
    saidUnknown = null
    leftBehind = false
    notice.value = null
    violations.value = []
    unfit.value = []
  }

  function edit(change: (draft: Config) => void): void {
    if (readOnly.value !== null || draft.value === null) {
      return
    }
    change(draft.value)
  }

  return {
    base,
    draft,
    confirmSecs,
    changes,
    violations,
    unfit,
    readOnly,
    pending,
    notice,
    busy,
    edit,
    setLanAddress: (name, ipv4) => {
      edit((config) => {
        const lan = config.lans.find((each) => each.name === name)
        if (lan !== undefined) {
          const from = lan.ipv4
          lan.ipv4 = ipv4
          unfit.value = renumber(config, from, ipv4)
        }
      })
    },
    problemAt: (path) => violations.value.find((violation) => violation.path === path || violation.path.startsWith(`${path}.`) || violation.path.startsWith(`${path}[`))?.message,
    discard: () => {
      draft.value = base.value === null ? null : clone(ConfigSchema, base.value)
      violations.value = []
      unfit.value = []
    },
    review: async () => {
      if (draft.value === null) {
        return null
      }
      busy.value = true
      try {
        const answer = await router.validate(draft.value)
        violations.value = answer.violations
        return answer.violations.length > 0 ? null : { changes: changes.value, effects: answer.effects, caller: answer.caller }
      } catch (error) {
        refused(error)
        return null
      } finally {
        busy.value = false
      }
    },
    apply: async (review, immediate) => {
      if (draft.value === null) {
        return
      }
      busy.value = true
      const sent = clone(ConfigSchema, draft.value)
      const fromTag = tag
      try {
        const applied = await router.apply(sent, fromTag, { immediate })
        const remembered: Mine = { sent, fromTag, answered: applied.answered, immediate, at: live.sinceBootMs.value, applied: null, read: null, stateSeen: false }
        if (applied.answered) {
          // It is the router's config now. The password that was typed has been sent and is
          // kept nowhere a page can show it: only with what is remembered of this change,
          // so that its going back gives the draft back whole.
          base.value = withoutPasswords(sent)
          draft.value = clone(ConfigSchema, base.value)
          tag = applied.tag
          mine = immediate ? null : remembered
        } else {
          mine = remembered
        }
        violations.value = []
        unfit.value = []
        if (review.caller?.connectionDrops === true) {
          notice.value = { kind: 'moved', name: host(), address: review.caller.routerAfter }
          leftBehind = live.connection.value !== 'open'
        } else {
          notice.value = null
        }
        if (!applied.answered) {
          void read()
        }
      } catch (error) {
        // The router's own words; what it has now is read again, and the draft stays.
        refused(error)
        void read()
      } finally {
        busy.value = false
      }
    },
    confirm: async () => {
      busy.value = true
      try {
        await router.confirm()
      } catch (error) {
        refused(error)
      } finally {
        busy.value = false
      }
    },
    revert: async () => {
      busy.value = true
      try {
        // Answered or not, the state says what became of it.
        await router.revert()
      } catch (error) {
        refused(error)
      } finally {
        busy.value = false
      }
    },
    start: () => {
      if (scope !== undefined) {
        return
      }
      scope = effectScope(true)
      scope.run(() => {
        watch(
          live.connection,
          (now) => {
            if (now !== 'open') {
              leftBehind = notice.value?.kind === 'moved'
            } else if (!reading) {
              void read()
            }
          },
          { flush: 'sync' },
        )
        watch(live.state, stateChanged, { flush: 'sync' })
        watch(live.events, eventsChanged, { flush: 'sync' })
        watch(() => changes.value.length > 0, guard, { immediate: true })
      })
      unhearEnd = router.onSessionEnd(forget)
      void read()
    },
    stop: () => {
      scope?.stop()
      scope = undefined
      unhearEnd?.()
      unhearEnd = undefined
      guard(false)
    },
  }
}

export const CONFIG: InjectionKey<ConfigStore> = Symbol('the config and its draft')
