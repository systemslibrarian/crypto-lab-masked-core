import { defineConfig, devices } from '@playwright/test';

/**
 * E2E runs against the production build served by `vite preview`, so what
 * passes here is what ships.
 *
 * Port 4694 is unique to this lab across the fleet, in committed state, and is
 * never the Vite default 4173 — with 190 labs side by side a shared port means
 * `reuseExistingServer` silently scans a DIFFERENT lab's preview, which has
 * really happened here.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  // ONE worker, deliberately. The a11y drive and the claims suite each run real
  // attacks inside the page -- up to 120,000 streamed traces for a single
  // reproduction -- and several parallel Chromium workers alongside the preview
  // server were enough to take the server down mid-run, which surfaces as a
  // confusing ERR_CONNECTION_REFUSED rather than as a test failure.
  workers: 1,
  timeout: 180_000,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4694/crypto-lab-masked-core/',
    colorScheme: 'dark', // dark is the only theme
  },
  projects: [
    { name: 'a11y', testMatch: /a11y\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
    { name: 'claims', testMatch: /claims\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    // Build before serving: `vite preview` only serves whatever is already in
    // dist/, so without this a failing build leaves the previous good bundle in
    // place and the suite passes green against code that no longer compiles.
    command: 'npm run build && npm run preview -- --port 4694 --strictPort',
    url: 'http://localhost:4694/crypto-lab-masked-core/',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
