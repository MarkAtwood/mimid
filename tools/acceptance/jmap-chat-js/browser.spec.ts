// jmap-chat-js's protocol layer, unmodified, in Chromium, served from its
// own Vite dev server, against two mimid-agent daemons on another origin
// (bead mimid-1wgh.13.11). The page imports src/lib/jmap/*.ts from the dev
// server as the app does; every request to a daemon is cross-origin, so
// these also check the daemon's CORS answers.

import { expect, test } from '@playwright/test'
import { fixture } from './fixture.js'

const { alice, bob } = fixture()

test.beforeEach(async ({ page }) => {
  await page.goto('/')
})

test('fetchSession: 401 without a token, readable cross-origin; accepted with one', async ({ page }) => {
  const outcome = await page.evaluate(async d => {
    const { fetchSession } = await import('/src/lib/jmap/session.ts')
    let without: string
    try {
      await fetchSession(d.url)
      without = 'accepted'
    } catch (e) {
      const err = e as { name: string; status?: number; message: string }
      without = `${err.name}:${err.status ?? err.message}`
    }
    const session = await fetchSession(d.url, () => Promise.resolve(d.token))
    return { without, username: session.username }
  }, alice)
  expect(outcome).toEqual({ without: 'SessionFetchError:401', username: alice.user })
})

test('a group Chat and Messages both ways, cross-origin', async ({ page }) => {
  const outcome = await page.evaluate(
    async ({ alice, bob }) => {
      type Obj = Record<string, unknown> & { id: string }
      const { fetchSession } = await import('/src/lib/jmap/session.ts')
      const { createClient } = await import('/src/lib/jmap/client.ts')
      const connect = async (d: typeof alice) => {
        const getToken = () => Promise.resolve(d.token)
        const session = await fetchSession(d.url, getToken)
        const client = createClient(session, getToken)
        const accountId = session.primaryAccounts['urn:ietf:params:jmap:chat']
        const call = <T,>(m: string, args: Record<string, unknown>) =>
          client.call(m, { accountId, ...args }) as Promise<T>
        type NotCreated = Record<string, { type: string; existingId?: string }>
        const create = async (type: string, obj: Record<string, unknown>) => {
          const r = await call<{ created?: Record<string, Obj>; notCreated?: NotCreated }>(
            `${type}/set`, { create: { k: obj } })
          // The Node half may have made bob's ChatContact already.
          const existing = r.notCreated?.k
          if (existing?.type === 'alreadyExists' && existing.existingId) return { id: existing.existingId }
          if (!r.created?.k) throw new Error(`${type}/set: ${JSON.stringify(r.notCreated)}`)
          return r.created.k
        }
        const get = async (type: string, ids: string[] | null) =>
          (await call<{ list: Obj[] }>(`${type}/get`, { ids })).list
        const messages = async (chatId: string) =>
          get('Message', (await call<{ ids: string[] }>('Message/query', { filter: { chatId } })).ids)
        return { session, create, get, messages }
      }
      const eventually = async <T,>(probe: () => Promise<T | undefined>) => {
        const deadline = Date.now() + 20_000
        for (;;) {
          const got = await probe()
          if (got !== undefined) return got
          if (Date.now() > deadline) throw new Error('timed out')
          await new Promise(r => setTimeout(r, 100))
        }
      }
      const now = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z')

      const a = await connect(alice)
      const b = await connect(bob)
      const contact = await a.create('ChatContact', { identity: bob.user })
      const chatA = await a.create('Chat', { kind: 'group', name: 'browser', memberIds: [contact.id] })
      const chatB = await eventually(async () =>
        (await b.get('Chat', null)).find(c => c.roomId === chatA.roomId))
      await a.create('Message', { chatId: chatA.id, body: 'hello bob', bodyType: 'text/plain', sentAt: now() })
      const atB = await eventually(async () => {
        const l = await b.messages(chatB.id)
        return l.length ? l : undefined
      })
      const [sender] = await b.get('ChatContact', [String(atB[0].senderId)])
      await b.create('Message', { chatId: chatB.id, body: 'hi alice', bodyType: 'text/plain', sentAt: now() })
      const reply = await eventually(async () =>
        (await a.messages(chatA.id)).find(m => m.body === 'hi alice'))
      return {
        username: a.session.username,
        bodyAtBob: atB.map(m => m.body),
        senderAtBob: sender.identity,
        replySender: reply.senderId === contact.id,
      }
    },
    { alice, bob },
  )
  expect(outcome).toEqual({
    username: alice.user,
    bodyAtBob: ['hello bob'],
    senderAtBob: alice.user,
    replySender: true,
  })
})

test('push: startPush delivers Chat StateChanges to both users, cross-origin', async ({ page }) => {
  const outcome = await page.evaluate(
    async ({ alice, bob }) => {
      const { fetchSession } = await import('/src/lib/jmap/session.ts')
      const { createClient } = await import('/src/lib/jmap/client.ts')
      const { startPush } = await import('/src/lib/push/eventsource.ts')
      const errors: string[] = []
      const start = async (d: typeof alice) => {
        const getToken = () => Promise.resolve(d.token)
        const session = await fetchSession(d.url, getToken)
        const accountId = session.primaryAccounts['urn:ietf:params:jmap:chat']
        const seen: string[] = []
        const push = startPush({
          session, getToken, ping: 0,
          onError: e => errors.push(String(e)),
          refreshers: { Chat: acct => { seen.push(acct) } },
        })
        return { client: createClient(session, getToken), accountId, seen, push }
      }
      const waitFor = async (pred: () => boolean) => {
        const deadline = Date.now() + 20_000
        while (!pred()) {
          if (Date.now() > deadline) throw new Error('timed out')
          await new Promise(r => setTimeout(r, 100))
        }
      }
      const a = await start(alice)
      const b = await start(bob)
      try {
        await new Promise(r => setTimeout(r, 500))
        type SetResult = { created?: Record<string, { id: string }>; notCreated?: Record<string, { type: string; existingId?: string }> }
        const c = await a.client.call<SetResult>('ChatContact/set',
          { accountId: a.accountId, create: { k: { identity: bob.user } } })
        const contactId = c.created?.k.id ?? c.notCreated?.k.existingId
        await a.client.call('Chat/set', {
          accountId: a.accountId,
          create: { k: { kind: 'group', name: 'browser push', memberIds: [contactId] } },
        })
        await waitFor(() => a.seen.includes(a.accountId))
        await waitFor(() => b.seen.includes(b.accountId))
      } finally {
        a.push.close()
        b.push.close()
      }
      await Promise.all([a.push.done, b.push.done])
      return { errors }
    },
    { alice, bob },
  )
  expect(outcome).toEqual({ errors: [] })
})
