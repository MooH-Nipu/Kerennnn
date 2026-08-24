import { expect, type BrowserContext, type Page } from '@playwright/test';

export async function login(page: Page, username: string, password: string) {
  await page.goto('/');
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
}

export async function installSession(context: BrowserContext, baseURL: string, token: string) {
  await context.addCookies([{ name: 'soc_session', value: token, url: baseURL, httpOnly: true, sameSite: 'Lax' }]);
}

export async function installEnvSession(context: BrowserContext, baseURL: string, role: string) {
  await installSession(context, baseURL, requiredEnv(`E2E_AUTO_${role.toUpperCase()}_SESSION_TOKEN`));
}

export async function expectNoHorizontalOverflow(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
}

export async function dismissUpdateToast(page: Page) {
  const button = page.getByRole('button', { name: 'Got it', exact: true });
  if (await button.waitFor({ state: 'visible', timeout: 1500 }).then(() => true).catch(() => false)) await button.click();
}

export async function stubTeamFilterReads(
  page: Page,
  onRequest?: (headers: Record<string, string>) => void,
) {
  await page.route('**/api/v1/team-filter*', async route => {
    const request = route.request();
    if (request.method() !== 'GET') return route.fallback();
    const headers = request.headers();
    onRequest?.(headers);
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        success: true,
        team_context: headers['x-team-context'],
        client_context: headers['x-client-context'] || null,
        items: [],
        total_records: 0,
        request_id: 'e2e-read-stub',
      }),
    });
  });
}

export function requiredEnv(name: string) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required. Run the matching npm E2E script.`);
  return value;
}
