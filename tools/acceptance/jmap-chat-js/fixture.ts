// The daemons run.sh started: AGENT_FIXTURE is the JSON line
// mimid-agent's acceptance_fixture example prints.

export interface Daemon {
  url: string
  token: string
  user: string
}

export interface Fixture {
  alice: Daemon
  bob: Daemon
}

export function fixture(): Fixture {
  const text = process.env.AGENT_FIXTURE
  if (!text) throw new Error('AGENT_FIXTURE is not set; use run.sh')
  return JSON.parse(text) as Fixture
}

/** Polls `probe` until it returns a value, or fails after `ms`. */
export async function eventually<T>(probe: () => Promise<T | undefined>, ms = 20_000): Promise<T> {
  const deadline = Date.now() + ms
  for (;;) {
    const got = await probe()
    if (got !== undefined) return got
    if (Date.now() > deadline) throw new Error('timed out')
    await new Promise(r => setTimeout(r, 100))
  }
}
