import { test, expect, type Page } from '@playwright/test';
import { dismissUpdateToast, installEnvSession, stubTeamFilterReads } from './helpers';

async function login(page: Page, username: string, password: string) {
  await page.goto('/');
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('button', { name: 'Logout' })).toBeVisible();
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

  test.beforeEach(async ({ page, context, baseURL }) => {
    await stubTeamFilterReads(page);
    await installEnvSession(context, baseURL!, 'admin');
    await page.goto('/');
    await dismissUpdateToast(page);
  });

  test('authentication and protected navigation work', async ({ page }) => {
    await page.context().clearCookies();
    await login(page, admin.username!, admin.password!);
    await expectRole(page, 'admin');
    await expect(page.getByRole('navigation', { name: 'Primary navigation' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    await page.getByRole('button', { name: /IoC Scan/ }).click();
    await expect(page.getByRole('heading', { name: 'IoC Scan' })).toBeVisible();
    await page.getByRole('button', { name: 'Settings' }).click();
    await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();
    await page.getByRole('button', { name: /^Navigation/ }).click();
    await expect(page.getByRole('heading', { name: 'Navigation', exact: true })).toBeVisible();
  });

  test('navigation preference save survives reload', async ({ page }) => {
    let renamed = false;
    try {
      await page.getByRole('button', { name: 'Settings' }).click();
      await page.getByRole('button', { name: /^Navigation/ }).click();
      await page.getByRole('textbox', { name: /Rename IoC Scan tab/i }).fill('IOC Review');
      await dismissUpdateToast(page);
      await page.getByRole('button', { name: 'Save navigation' }).click();
      await expect(page.getByText('Navigation layout saved.')).toBeVisible();
      renamed = true;
      await page.reload();
      await expect(page.getByRole('button', { name: /IOC Review/ })).toBeVisible();
    } finally {
      if (renamed) {
        await page.getByRole('button', { name: 'Settings' }).click();
        await page.getByRole('button', { name: /^Navigation/ }).click();
        await page.getByRole('textbox', { name: /Rename IoC Scan tab/i }).fill('');
        await page.getByRole('button', { name: 'Save navigation' }).click();
        await expect(page.getByText('Navigation layout saved.')).toBeVisible();
      }
    }
  });

  test('PAC preview skips IPv6 and keeps IPv4 submit available', async ({ page }) => {
    await page.getByRole('button', { name: 'Team Filter', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'PAC Filter' })).toBeVisible();
    await page.locator('.pac-input-panel textarea').first().fill('192.0.2.10\n2001:db8::1');
    await expect(page.getByText('IPv6 detected — will not be saved to DB')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Submit 1 IPs to DB' })).toBeEnabled();
  });

  test('bulk IOC preview normalizes, dedupes, and selects before scanning', async ({ page }) => {
    await page.getByRole('button', { name: /^(IoC Scan|IOC Review)$/ }).click();
    await page.getByLabel(/IOC — one per line/i).fill('hxxps://evil[.]example/path\nevil.example\nnot an indicator');
    const preview = page.getByLabel('Bulk IOC preview');
    await expect(preview).toBeVisible();
    await expect(preview.getByText('hxxps://evil[.]example/path')).toBeVisible();
    await expect(preview.getByRole('cell', { name: 'Duplicate', exact: true })).toBeVisible();
    await expect(preview.getByText('Unsupported or invalid IOC')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Scan 1' })).toBeEnabled();
  });

  test('IOC scan submits without provider quota', async ({ page }) => {
    await page.route('**/api/vt?*', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ data: { id: 'mock' }, _meta: { cache: { fromCache: true } } }) }));
    await page.route('**/api/correlate?*', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ confidence: 10, scoring: { confidence: 10 } }) }));
    await page.getByRole('button', { name: /^(IoC Scan|IOC Review)$/ }).click();
    await page.getByLabel(/IOC — one per line/i).fill('192.0.2.10');
    await page.getByRole('button', { name: 'Scan 1', exact: true }).click();
    await expect(page.getByText(/Scan complete/)).toBeVisible();
    await expect(page.locator('.vt-ioc-val', { hasText: '192.0.2.10' })).toBeVisible();
  });

  test('strongest valid IOC signal controls card verdict and filters', async ({ page }) => {
    const cleanStats = { harmless: 80, malicious: 0, suspicious: 0, undetected: 10 };
    const maliciousStats = { harmless: 70, malicious: 8, suspicious: 1, undetected: 11 };
    await page.route('**/api/vt?*', route => {
      const url = route.request().url();
      if (url.includes('health=1')) {
        return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ availableKeys: 100 }) });
      }
      const stats = url.includes('192.0.2.22')
        ? {}
        : url.includes('192.0.2.20') ? cleanStats : maliciousStats;
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: { attributes: { last_analysis_stats: stats } } }),
      });
    });
    await page.route('**/api/correlate?*', route => {
      const url = route.request().url();
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(url.includes('192.0.2.22')
          ? { confidence: 0, sources: [] }
          : url.includes('192.0.2.20')
            ? { confidence: 74, sources: [{ source: 'AbuseIPDB', verdict: 'malicious' }] }
            : { confidence: 0, sources: [{ source: 'AbuseIPDB', verdict: 'clean' }] }),
      });
    });
    await page.getByRole('button', { name: /^(IoC Scan|IOC Review)$/ }).click();
    await page.getByLabel(/IOC — one per line/i).fill('192.0.2.20\n192.0.2.21\n192.0.2.22');
    await page.getByRole('button', { name: 'Scan 3', exact: true }).click();
    await expect(page.getByText(/Scan complete/)).toBeVisible();
    await expect(page.locator('.verdict', { hasText: 'MALICIOUS' })).toHaveCount(2);
    await page.getByRole('button', { name: 'Malicious', exact: true }).click();
    await expect(page.locator('.vt-ioc-val', { hasText: /192\.0\.2\.(20|21)/ })).toHaveCount(0);
    await expect(page.locator('.verdict', { hasText: 'UNKNOWN' })).toBeVisible();
    await page.getByRole('button', { name: 'Clean', exact: true }).click();
    await expect(page.locator('.vt-ioc-val', { hasText: '192.0.2.22' })).toBeVisible();
    await page.getByRole('button', { name: 'Unknown', exact: true }).click();
    await expect(page.locator('.vt-ioc-val', { hasText: '192.0.2.22' })).toHaveCount(0);
  });

  test('Deep Analysis recommendations match Malicious, Low Risk, and Unknown', async ({ page }) => {
    await page.route('**/api/ip-cache/by-id?*', route => {
      const url = route.request().url();
      const unknown = url.includes('unknown-case');
      const lowRisk = url.includes('low-risk-case');
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ item: {
          id: unknown ? 'unknown-case' : lowRisk ? 'low-risk-case' : 'disagreement-case',
          ip: unknown ? '192.0.2.41' : lowRisk ? '192.0.2.40' : '192.0.2.30',
          ioc_type: 'ip',
          vt_verdict: unknown ? 'unknown' : 'clean',
          vt_stats: unknown ? {} : { harmless: 80, malicious: 0, suspicious: 0, undetected: 10 },
          vt_payload: {},
          corr_confidence: unknown ? null : lowRisk ? 20 : 0,
          corr_payload: unknown
            ? {}
            : lowRisk
              ? { confidence: 20, sources: [{ source: 'Abuse.ch', verdict: 'clean' }] }
              : { confidence: 0, sources: [
                  { source: 'AbuseIPDB', verdict: 'malicious', score: 100 },
                  { source: 'AlienVault OTX', verdict: 'malicious', score: 80 },
                ] },
          first_scanned_at: '2026-08-25T00:00:00.000Z',
        } }),
      });
    });

    await page.goto('/result/disagreement-case');
    await expect(page.locator('.vt-card-header .verdict')).toHaveText(/MALICIOUS/);
    await expect(page.getByText('This IP is flagged as malicious')).toBeVisible();
    await expect(page.getByText(/High-confidence or corroborated threat intelligence flagged/)).toBeVisible();
    await expect(page.getByText('This IP appears clean')).toHaveCount(0);

    await page.goto('/result/low-risk-case');
    await expect(page.locator('.vt-card-header .verdict')).toHaveText(/LOW RISK/);
    await expect(page.getByText('This IP has low-risk signals')).toBeVisible();
    await expect(page.getByText(/Low risk is not the same as confirmed clean/)).toBeVisible();

    await page.goto('/result/unknown-case');
    await expect(page.locator('.vt-card-header .verdict')).toHaveText(/UNKNOWN/);
    await expect(page.getByText('This IP has no reliable verdict')).toBeVisible();
    await expect(page.getByText(/Do not treat this indicator as clean/)).toBeVisible();
    await expect(page.getByText('This IP appears clean')).toHaveCount(0);
  });
});

for (const role of ['l1', 'pac'] as const) {
  test(`${role} navigation enforces role access`, async ({ page, context, baseURL }) => {
    await installEnvSession(context, baseURL!, role);
    await page.goto('/');
    await expectRole(page, role);
    await expect(page.getByRole('button', { name: /IoC Scan/ })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Dashboard' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Team Filter', exact: true })).toHaveCount(role === 'pac' ? 1 : 0);
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
