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

test('fetchSession is refused with 401, readable cross-origin', async ({ page }) => {
  const outcome = await page.evaluate(async url => {
    const { fetchSession } = await import('/src/lib/jmap/session.ts')
    try {
      await fetchSession(url)
      return 'accepted'
    } catch (e) {
      const err = e as { name: string; status?: number; message: string }
      return `${err.name}:${err.status ?? err.message}`
    }
  }, alice.url)
  expect(outcome).toBe('SessionFetchError:401')
})

test('a group Chat and Messages both ways, cross-origin', async ({ page }) => {
  const outcome = await page.evaluate(
    async ({ alice, bob }) => {
      type Obj = Record<string, unknown> & { id: string }
      const { fetchSession } = await import('/src/lib/jmap/session.ts')
      const { createClient } = await import('/src/lib/jmap/client.ts')
      // The one thing around the library: fetchSession sends no token.
      const realFetch = window.fetch.bind(window)
      window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(input instanceof Request ? input.url : input.toString())
        const d = [alice, bob].find(x => new URL(x.url).origin === url.origin)
        if (!d) return realFetch(input, init)
        const headers = new Headers(init?.headers)
        headers.set('Authorization', `Bearer ${d.token}`)
        return realFetch(input, { ...init, headers })
      }
      const connect = async (d: typeof alice) => {
        const session = await fetchSession(d.url)
        const client = createClient(session, () => Promise.resolve(d.token))
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

test('push: EventSource cannot authenticate, a fetch stream can', async ({ page }) => {
  const outcome = await page.evaluate(async d => {
    const sessionRes = await fetch(`${d.url}/.well-known/jmap`, {
      headers: { Authorization: `Bearer ${d.token}` },
    })
    const session = (await sessionRes.json()) as { eventSourceUrl: string; apiUrl: string; primaryAccounts: Record<string, string> }
    const url = session.eventSourceUrl
      .replace('{types}', '*').replace('{closeafter}', 'state').replace('{ping}', '0')

    // The browser EventSource API sends no Authorization header.
    const viaEventSource = await new Promise<string>(resolve => {
      const es = new EventSource(url)
      es.onopen = () => { es.close(); resolve('open') }
      es.onerror = () => { const s = es.readyState; es.close(); resolve(`error readyState=${s}`) }
    })

    // A fetch with the header works; closeafter=state ends after one event.
    const res = await fetch(url, { headers: { Authorization: `Bearer ${d.token}` } })
    const pending = res.text()
    const accountId = session.primaryAccounts['urn:ietf:params:jmap:chat']
    await fetch(session.apiUrl, {
      method: 'POST',
      headers: { Authorization: `Bearer ${d.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:chat'],
        methodCalls: [['ChatContact/set', { accountId, create: { k: { identity: 'mimi://a.example/u/carol' } } }, 'c0']],
      }),
    })
    const text = await pending
    return { viaEventSource, status: res.status, stateEvent: /event: ?state/.test(text) }
  }, alice)
  expect(outcome).toEqual({ viaEventSource: 'error readyState=2', status: 200, stateEvent: true })
})
