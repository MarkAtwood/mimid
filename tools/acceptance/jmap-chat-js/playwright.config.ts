// Playwright configuration for the browser half of the mimid-agent
// acceptance test of jmap-chat-js (bead mimid-1wgh.13.11). The app's own
// Vite dev server serves its unmodified sources at http://localhost:PORT;
// run.sh starts the daemons with that origin in allowed_origins.
import { defineConfig, devices } from '@playwright/test'

const port = Number(process.env.APP_PORT ?? 5173)

export default defineConfig({
  testDir: '.',
  testMatch: 'browser.spec.ts',
  reporter: 'list',
  timeout: 90_000,
  use: { baseURL: `http://localhost:${port}` },
  // channel 'chromium': the full Chromium build in new headless mode, so
  // no separate headless shell download is needed.
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], channel: 'chromium' } }],
  webServer: {
    command: `npx vite --port ${port} --strictPort`,
    cwd: '..',
    url: `http://localhost:${port}`,
    reuseExistingServer: false,
  },
})
