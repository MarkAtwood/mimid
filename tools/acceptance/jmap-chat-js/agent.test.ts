// jmap-chat-js's protocol layer (src/lib/jmap/session.ts, client.ts),
// unmodified, against two mimid-agent daemons (bead mimid-1wgh.13.11).
//
// What jmap-chat-js has today is fetchSession and the JMAPClient request
// batcher; there is no UI for chats and no EventSource code yet. This
// drives exactly those, the way an app built on them would.
//
// fetchSession sends no Authorization header (session.ts:91), and the
// daemon requires its token on every path, the Session included, so the
// first test records that refusal. The rest wrap globalThis.fetch to add
// the bearer token to requests for a daemon's origin, which is the one
// thing an app would have to do around the library; the library code
// itself is as committed.

import { afterEach, describe, expect, it } from 'vitest'
import { fetchSession, SessionFetchError, type JMAPSession } from '../src/lib/jmap/session.js'
import { createClient, type JMAPClient } from '../src/lib/jmap/client.js'
import { eventually, fixture, type Daemon } from './fixture.js'

const CHAT = 'urn:ietf:params:jmap:chat'
const { alice, bob } = fixture()
const realFetch = globalThis.fetch

afterEach(() => {
  globalThis.fetch = realFetch
})

/** Adds each daemon's bearer token to requests for its origin. */
function withTokens(...daemons: Daemon[]) {
  globalThis.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : input.toString())
    const daemon = daemons.find(d => new URL(d.url).origin === url.origin)
    if (!daemon) return realFetch(input, init)
    const headers = new Headers(init?.headers)
    headers.set('Authorization', `Bearer ${daemon.token}`)
    return realFetch(input, { ...init, headers })
  }
}

interface User {
  session: JMAPSession
  client: JMAPClient
  account: string
}

async function connect(daemon: Daemon): Promise<User> {
  const session = await fetchSession(daemon.url)
  return {
    session,
    client: createClient(session, () => Promise.resolve(daemon.token)),
    account: session.primaryAccounts[CHAT],
  }
}

type Obj = Record<string, unknown> & { id: string }

type NotCreated = Record<string, { type: string; existingId?: string }>

async function create(u: User, type: string, object: Record<string, unknown>): Promise<Obj> {
  const r = await u.client.call<{ created?: Record<string, Obj>; notCreated?: NotCreated }>(
    `${type}/set`,
    { accountId: u.account, create: { k: object } },
  )
  // A ChatContact for that identity may exist from an earlier test.
  const existing = r.notCreated?.k
  if (type === 'ChatContact' && existing?.type === 'alreadyExists' && existing.existingId) {
    return { id: existing.existingId }
  }
  expect(r.notCreated ?? null).toBeNull()
  return r.created!.k
}

async function get(u: User, type: string, ids: string[] | null): Promise<Obj[]> {
  const r = await u.client.call<{ list: Obj[] }>(`${type}/get`, { accountId: u.account, ids })
  return r.list
}

async function messages(u: User, chatId: string): Promise<Obj[]> {
  // Two calls queued in one tick go out as one batched request.
  const [query] = await Promise.all([
    u.client.call<{ ids: string[] }>('Message/query', {
      accountId: u.account,
      filter: { chatId },
    }),
    u.client.call('Core/echo', { ping: true }),
  ])
  return get(u, 'Message', query.ids)
}

describe('fetchSession as committed', () => {
  it('is refused with 401: it sends no Authorization header', async () => {
    const err = await fetchSession(alice.url).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(SessionFetchError)
    expect((err as SessionFetchError).status).toBe(401)
  })
})

describe('session.ts and client.ts against two daemons', () => {
  it('accepts the daemon Session', async () => {
    withTokens(alice)
    const { session, account } = await connect(alice)
    expect(session.username).toBe(alice.user)
    expect(Object.keys(session.capabilities).sort()).toEqual([
      'urn:ietf:params:jmap:chat',
      'urn:ietf:params:jmap:core',
    ])
    expect(session.accounts[account].name).toBe(alice.user)
  })

  it('creates a group Chat and exchanges Messages both ways', async () => {
    withTokens(alice, bob)
    const a = await connect(alice)
    const b = await connect(bob)

    const bobContact = await create(a, 'ChatContact', { identity: bob.user })
    const chatA = await create(a, 'Chat', {
      kind: 'group',
      name: 'from jmap-chat-js',
      memberIds: [bobContact.id],
    })
    expect(String(chatA.roomId)).toMatch(/^mimi:\/\/a\.example\/r\//)

    // No EventSource in jmap-chat-js: poll.
    const chatB = await eventually(async () => {
      const chats = await get(b, 'Chat', null)
      return chats.find(c => c.roomId === chatA.roomId)
    })
    expect(chatB.name).toBe('from jmap-chat-js')

    await create(a, 'Message', {
      chatId: chatA.id,
      body: 'hello bob',
      bodyType: 'text/plain',
      sentAt: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    })
    const got = await eventually(async () => {
      const list = await messages(b, chatB.id)
      return list.length > 0 ? list : undefined
    })
    expect(got.map(m => m.body)).toEqual(['hello bob'])
    const [sender] = await get(b, 'ChatContact', [String(got[0].senderId)])
    expect(sender.identity).toBe(alice.user)

    await create(b, 'Message', {
      chatId: chatB.id,
      body: 'hi alice',
      bodyType: 'text/plain',
      sentAt: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    })
    const reply = await eventually(async () => {
      const list = await messages(a, chatA.id)
      return list.find(m => m.body === 'hi alice')
    })
    expect(reply.senderId).toBe(bobContact.id)
  })
})
