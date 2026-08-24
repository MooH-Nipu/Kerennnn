import { test, expect } from '@playwright/test';
import { expectNoHorizontalOverflow, installSession, requiredEnv, stubTeamFilterReads } from './helpers';

const READ_ONLY_PAGE_API_PATHS = new Set([
  '/api/auth/me',
  '/api/user-prefs',
  '/api/v1/charlie-clients',
]);

test.describe('read-only production smoke', () => {
  test.beforeEach(async ({ context, baseURL }) => {
    await installSession(context, baseURL!, requiredEnv('E2E_SESSION_TOKEN'));
  });

  test('health, navigation, responsive layout, and Charlie scope are safe', async ({ page, request }) => {
    const mutations: string[] = [];
    const blockedReads: string[] = [];
    await page.route('**/api/**', async route => {
      const request = route.request();
      if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method())) {
        mutations.push(`${request.method()} ${request.url()}`);
        await route.abort();
        return;
      }
      const path = new URL(request.url()).pathname;
      if (!READ_ONLY_PAGE_API_PATHS.has(path)) {
        blockedReads.push(path);
        await route.abort();
        return;
      }
      await route.continue();
    });
    const teamFilterReads: Record<string, string>[] = [];
    await stubTeamFilterReads(page, headers => teamFilterReads.push(headers));

    const health = await request.get('/api/health');
    expect(health.ok()).toBe(true);
    expect(await health.json()).toEqual({ ok: true });

    await page.goto('/');
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await page.getByLabel('Settings').click();
    const team = page.getByLabel('Active Team Filter context');
    await expect(team).toBeVisible();
    expect((await team.locator('option').allTextContents()).sort()).toEqual(['CHARLIE', 'PAC']);
    await team.selectOption('CHARLIE');
    await page.getByRole('button', { name: 'Team Filter', exact: true }).click();
    const clients = page.getByLabel('Charlie client filter');
    await expect(clients).toBeVisible();
    expect((await clients.locator('option').allTextContents()).some(label => /general|legacy/i.test(label))).toBe(false);
    expect(teamFilterReads.some(headers => headers['x-team-context'] === 'CHARLIE' && !!headers['x-client-context'])).toBe(true);
    await expectNoHorizontalOverflow(page);
    expect(mutations).toEqual([]);
    expect(blockedReads.every(path => path !== '/api/auth/me' && path !== '/api/user-prefs' && path !== '/api/v1/charlie-clients')).toBe(true);
  });
});
