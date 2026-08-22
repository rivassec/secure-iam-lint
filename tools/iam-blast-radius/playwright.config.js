// Playwright config for the IAM Blast Radius UI shell (IAM-007).
//
// Browser-level acceptance that node --test cannot cover: real DOM XSS
// inertness, keyboard accessibility, worker execution, and zero network
// egress. The tool ships verbatim under content/tools/iam-blast-radius/, so we
// serve the repo `content/` dir statically and drive the real files - no build
// step. Runs in CI (see .github/workflows/iam-blast-radius-ci.yml); not part of
// the deterministic authoring loop.

import { defineConfig, devices } from '@playwright/test';

const PORT = 8080;
const BASE = `http://127.0.0.1:${PORT}`;

export default defineConfig({
  testDir: './tests/e2e',
  testMatch: /.*\.spec\.js/,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: BASE,
    trace: 'on-first-retry',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
  webServer: {
    // Serve the repo content/ root so /tools/iam-blast-radius/ resolves exactly
    // as it will in production (index.html + app.js + worker.js + engine/).
    command: `python3 -m http.server ${PORT} --directory ../../content`,
    url: `${BASE}/tools/iam-blast-radius/index.html`,
    reuseExistingServer: !process.env.CI,
    timeout: 30000,
  },
});
