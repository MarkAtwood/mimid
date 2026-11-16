// Vitest configuration for the mimid-agent acceptance test of jmap-chat-js
// (bead mimid-1wgh.13.11). run.sh copies this directory to acceptance/ in
// a scratch copy of jmap-chat-js; the app's own files stay as committed.
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  // The app's root, the parent of this directory.
  root: fileURLToPath(new URL('..', import.meta.url)),
  test: {
    // Node's fetch: no CORS. The browser path is browser.spec.ts.
    environment: 'node',
    include: ['acceptance/**/*.test.ts'],
    testTimeout: 60_000,
    globals: false,
  },
})
