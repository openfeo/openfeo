// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// A socket and a clock that a test turns by hand: the client's own tests need no router.

import { create, fromBinary, toBinary, type MessageInitShape } from '@bufbuild/protobuf'

import { ClientMsgSchema, ServerMsgSchema, type ClientMsg } from '../src/gen/openfeo/v1/api_pb.js'
import type { Timers, WebSocketLike } from '../src/index.js'

type ServerInit = MessageInitShape<typeof ServerMsgSchema>

/** The router's end of a socket, as a script. */
export class ScriptedSocket implements WebSocketLike {
  binaryType = 'blob'
  onopen: (() => void) | null = null
  onmessage: ((event: { data: unknown }) => void) | null = null
  onclose: ((event: { code: number }) => void) | null = null
  onerror: (() => void) | null = null
  /** Every frame the client sent, decoded, in order. */
  readonly sent: ClientMsg[] = []
  /** The code the client closed it with, once it has. */
  closedWith: number | undefined

  constructor(readonly url: string) {}

  send(data: Uint8Array): void {
    this.sent.push(fromBinary(ClientMsgSchema, data))
  }

  close(code?: number): void {
    this.closedWith ??= code ?? 1000
  }

  /** The handshake is done. */
  open(): void {
    this.onopen?.()
  }

  /** The router sends a frame. */
  receive(init: ServerInit): void {
    const bytes = toBinary(ServerMsgSchema, create(ServerMsgSchema, init))
    this.onmessage?.({ data: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) })
  }

  /** The router sends bytes that are whatever the test says. */
  receiveRaw(data: unknown): void {
    this.onmessage?.({ data })
  }

  /** The router acknowledges a frame: the last one sent, or the one with this id. */
  ack(id?: number): void {
    this.receive({ id: id ?? this.last().id, body: { case: 'response', value: {} } })
  }

  /** The socket ends from the far side (or the network) with this close code. */
  drop(code: number): void {
    this.onclose?.({ code })
  }

  last(): ClientMsg {
    const frame = this.sent.at(-1)
    if (frame === undefined) {
      throw new Error('the client has sent nothing')
    }
    return frame
  }

  /** The kind of each frame sent, in order: 'auth', 'subscribe', 'request' and so on. */
  kinds(): (string | undefined)[] {
    return this.sent.map((frame) => frame.body.case)
  }

  /** Open, and acknowledge the Auth frame the client then sends. */
  accept(): void {
    this.open()
    this.ack()
  }
}

/** A factory for {@link RouterOptions.webSocket} that keeps every socket it made. */
export function scripted(): { factory: (url: string) => WebSocketLike; sockets: ScriptedSocket[] } {
  const sockets: ScriptedSocket[] = []
  return {
    factory: (url) => {
      const socket = new ScriptedSocket(url)
      sockets.push(socket)
      return socket
    },
    sockets,
  }
}

/** A clock that moves only when told, and dice that roll what they are told. */
export class ManualTimers implements Timers {
  #now = 0
  #next = 1
  readonly #due = new Map<number, { at: number; fn: () => void }>()
  /** What {@link random} returns: 1 gives a backoff its whole step. */
  roll = 1

  set(fn: () => void, ms: number): unknown {
    const handle = this.#next++
    this.#due.set(handle, { at: this.#now + ms, fn })
    return handle
  }

  clear(handle: unknown): void {
    this.#due.delete(handle as number)
  }

  now(): number {
    return this.#now
  }

  random(): number {
    return this.roll
  }

  /** How many timers are waiting. */
  get pending(): number {
    return this.#due.size
  }

  /** Move the clock on, running what falls due in order, including what those set. */
  advance(ms: number): void {
    const until = this.#now + ms
    for (;;) {
      let next: [number, { at: number; fn: () => void }] | undefined
      for (const entry of this.#due) {
        if (entry[1].at <= until && (next === undefined || entry[1].at < next[1].at)) {
          next = entry
        }
      }
      if (next === undefined) {
        break
      }
      this.#due.delete(next[0])
      this.#now = next[1].at
      next[1].fn()
    }
    this.#now = until
  }
}

/** Let promises that are already settled run their continuations. */
export async function settle(): Promise<void> {
  for (let i = 0; i < 5; i++) {
    await Promise.resolve()
  }
}
