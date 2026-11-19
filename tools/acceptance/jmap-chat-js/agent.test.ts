// jmap-chat-js's protocol layer (src/lib/jmap/session.ts, client.ts and
// src/lib/push/eventsource.ts), unmodified, against two mimid-agent
// daemons (bead mimid-1wgh.13.11).
//
// jmap-chat-js has fetchSession, the JMAPClient request batcher and
// startPush; there is no UI for chats yet. This drives exactly those, the
// way an app built on them would.

import { describe, expect, it } from 'vitest'
import { fetchSession, SessionFetchError, type JMAPSession } from '../src/lib/jmap/session.js'
import { createClient, type JMAPClient } from '../src/lib/jmap/client.js'
import { startPush } from '../src/lib/push/eventsource.js'
import { eventually, fixture, type Daemon } from './fixture.js'

const CHAT = 'urn:ietf:params:jmap:chat'
const { alice, bob } = fixture()

function tokenOf(daemon: Daemon) {
  return () => Promise.resolve(daemon.token)
}

interface User {
  session: JMAPSession
  client: JMAPClient
  account: string
}

async function connect(daemon: Daemon): Promise<User> {
  const session = await fetchSession(daemon.url, tokenOf(daemon))
  return {
    session,
    client: createClient(session, tokenOf(daemon)),
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

describe('fetchSession', () => {
  it('is refused with 401 without a token and accepted with one', async () => {
    const err = await fetchSession(alice.url).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(SessionFetchError)
    expect((err as SessionFetchError).status).toBe(401)

    const session = await fetchSession(alice.url, tokenOf(alice))
    expect(session.username).toBe(alice.user)
  })
})

describe('session.ts and client.ts against two daemons', () => {
  it('accepts the daemon Session', async () => {
    const { session, account } = await connect(alice)
    expect(session.username).toBe(alice.user)
    expect(Object.keys(session.capabilities).sort()).toEqual([
      'urn:ietf:params:jmap:chat',
      'urn:ietf:params:jmap:core',
    ])
    expect(session.accounts[account].name).toBe(alice.user)
  })

  it('creates a group Chat and exchanges Messages both ways', async () => {
    const a = await connect(alice)
    const b = await connect(bob)

    const bobContact = await create(a, 'ChatContact', { identity: bob.user })
    const chatA = await create(a, 'Chat', {
      kind: 'group',
      name: 'from jmap-chat-js',
      memberIds: [bobContact.id],
    })
    expect(String(chatA.roomId)).toMatch(/^mimi:\/\/a\.example\/r\//)

    // The push test below covers StateChange; here, poll.
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

describe('startPush against two daemons', () => {
  it('delivers Chat StateChanges to both users, and close() ends it', async () => {
    const a = await connect(alice)
    const b = await connect(bob)
    const seen = { alice: [] as string[], bob: [] as string[] }
    const errors: unknown[] = []
    const push = (u: User, d: Daemon, log: string[]) =>
      startPush({
        session: u.session,
        getToken: tokenOf(d),
        ping: 0,
        onError: e => errors.push(e),
        refreshers: {
          Chat: accountId => { log.push(`Chat ${accountId}`) },
          Message: accountId => { log.push(`Message ${accountId}`) },
        },
      })
    const pa = push(a, alice, seen.alice)
    const pb = push(b, bob, seen.bob)
    try {
      // The streams open asynchronously; a change made before a stream is
      // open would not be announced on it.
      await new Promise(r => setTimeout(r, 500))
      const bobContact = await create(a, 'ChatContact', { identity: bob.user })
      await create(a, 'Chat', { kind: 'group', name: 'push', memberIds: [bobContact.id] })
      await eventually(async () => (seen.alice.includes(`Chat ${a.account}`) ? true : undefined))
      await eventually(async () => (seen.bob.includes(`Chat ${b.account}`) ? true : undefined))
    } finally {
      pa.close()
      pb.close()
    }
    await Promise.all([pa.done, pb.done])
    expect(errors).toEqual([])
  })
})
