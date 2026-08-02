import { test, expect, type Page } from '@playwright/test';

async function login(page: Page, username: string, password: string) {
  await page.goto('/');
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
}

async function expectRole(page: Page, role: string) {
  await expect(page.locator('.role-badge')).toHaveText(role.toUpperCase());
  const response = await page.request.get('/api/auth/me');
  expect(response.ok()).toBeTruthy();
  expect(await response.json()).toMatchObject({ role });
}

const admin = { username: process.env.E2E_USERNAME, password: process.env.E2E_PASSWORD };

test.describe('authenticated admin smoke', () => {
  test.skip(!admin.username || !admin.password, 'Set E2E_USERNAME and E2E_PASSWORD.');

  test.beforeEach(async ({ page }) => login(page, admin.username!, admin.password!));

  test('authentication and protected navigation work', async ({ page }) => {
    await expectRole(page, 'admin');
    await expect(page.getByRole('navigation', { name: 'Primary navigation' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    await page.getByRole('button', { name: /IoC Scan/ }).click();
    await expect(page.getByRole('heading', { name: 'IoC Scan' })).toBeVisible();
    await page.getByRole('button', { name: 'Settings' }).click();
    await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Navigation builder', exact: true })).toBeVisible();
  });

  test('navigation preference save survives reload', async ({ page }) => {
    let renamed = false;
    try {
      await page.getByRole('button', { name: 'Settings' }).click();
      await page.getByRole('textbox', { name: /Rename IoC Scan tab/i }).fill('IOC Review');
      await page.getByRole('button', { name: 'Save navigation' }).click();
      await expect(page.getByText('Navigation layout saved.')).toBeVisible();
      renamed = true;
      await page.reload();
      await expect(page.getByRole('button', { name: /IOC Review/ })).toBeVisible();
    } finally {
      if (renamed) {
        await page.getByRole('button', { name: 'Settings' }).click();
        await page.getByRole('textbox', { name: /Rename IoC Scan tab/i }).fill('');
        await page.getByRole('button', { name: 'Save navigation' }).click();
        await expect(page.getByText('Navigation layout saved.')).toBeVisible();
      }
    }
  });

  test('PAC preview skips IPv6 and keeps IPv4 submit available', async ({ page }) => {
    await page.getByRole('button', { name: /PAC Filter/ }).click();
    await expect(page.getByRole('heading', { name: 'PAC Filter' })).toBeVisible();
    await page.locator('.pac-input-panel textarea').first().fill('192.0.2.10\n2001:db8::1');
    await expect(page.getByText('IPv6 detected — will not be saved to DB')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Submit 1 IPs to DB' })).toBeEnabled();
  });

  test('IOC scan submits without provider quota', async ({ page }) => {
    await page.route('**/api/vt?*', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ data: { id: 'mock' }, _meta: { cache: { fromCache: true } } }) }));
    await page.route('**/api/correlate?*', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ confidence: 10, scoring: { confidence: 10 } }) }));
    await page.getByRole('button', { name: /^(IoC Scan|IOC Review)$/ }).click();
    await page.getByLabel(/IOC — one per line/i).fill('192.0.2.10');
    await page.getByRole('button', { name: 'Scan', exact: true }).click();
    await expect(page.getByText(/Scan complete/)).toBeVisible();
    await expect(page.locator('.vt-ioc-val', { hasText: '192.0.2.10' })).toBeVisible();
  });
});

for (const role of ['l1', 'pac'] as const) {
  test(`${role} navigation enforces role access`, async ({ page }) => {
    const username = process.env[`E2E_${role.toUpperCase()}_USERNAME`];
    const password = process.env[`E2E_${role.toUpperCase()}_PASSWORD`];
    test.skip(!username || !password, `Set E2E_${role.toUpperCase()} credentials.`);
    await login(page, username!, password!);
    await expectRole(page, role);
    await expect(page.getByRole('button', { name: /IoC Scan/ })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Dashboard' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /PAC Filter/ })).toHaveCount(role === 'pac' ? 1 : 0);
  });
}

test('unauthenticated user sees login', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByLabel('Username')).toBeVisible();
  await expect(page.getByLabel('Password')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
});

test('health endpoint is live and safe', async ({ request }) => {
  const response = await request.get('/api/health');
  expect(response.ok()).toBeTruthy();
  expect(await response.json()).toEqual({ ok: true });
  expect(response.headers()['cache-control']).toBe('no-store');
});
