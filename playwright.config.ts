import { defineConfig, devices } from '@playwright/test';

const devBaseURL = process.env.E2E_DEV_BASE_URL || 'http://localhost:3002';
const prodBaseURL = process.env.E2E_PROD_BASE_URL || 'http://localhost:3000';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'dev-desktop',
      testMatch: ['smoke.spec.ts', 'dev.spec.ts', 'syslog.spec.ts'],
      use: { ...devices['Desktop Chrome'], baseURL: devBaseURL },
    },
    {
      name: 'dev-narrow',
      testMatch: ['responsive.spec.ts', 'syslog.spec.ts'],
      use: { ...devices['Desktop Chrome'], baseURL: devBaseURL, viewport: { width: 390, height: 844 } },
    },
    {
      name: 'prod-desktop',
      testMatch: 'prod.spec.ts',
      use: { ...devices['Desktop Chrome'], baseURL: prodBaseURL },
    },
    {
      name: 'prod-narrow',
      testMatch: 'prod.spec.ts',
      use: { ...devices['Desktop Chrome'], baseURL: prodBaseURL, viewport: { width: 390, height: 844 } },
    },
  ],
});
