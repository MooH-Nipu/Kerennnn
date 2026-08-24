import { test, expect } from '@playwright/test';
import { expectNoHorizontalOverflow, installEnvSession, login, requiredEnv, stubTeamFilterReads } from './helpers';

const password = () => requiredEnv('E2E_AUTO_PASSWORD');

test('L1 receives global utilities without admin or team access', async ({ page }) => {
  await login(page, requiredEnv('E2E_AUTO_L1_USERNAME'), password());
  for (const name of ['Formatter', 'Merger', 'JSON', 'Daily EOD', 'CVE Lookup', 'ATT&CK']) {
    await expect(page.getByRole('button', { name, exact: true })).toBeVisible();
  }
  await expect(page.getByRole('button', { name: 'Dashboard', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Users', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Team Filter', exact: true })).toHaveCount(0);
});

test('synthetic dual-team L1 can switch PAC and CHARLIE', async ({ page, context, baseURL }) => {
  await stubTeamFilterReads(page);
  await installEnvSession(context, baseURL!, 'dual');
  await page.goto('/');
  await page.getByLabel('Settings').click();
  const team = page.getByLabel('Active Team Filter context');
  await expect(team.locator('option')).toHaveText(['PAC', 'CHARLIE']);
  await team.selectOption('CHARLIE');
  await page.getByRole('button', { name: 'Team Filter', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'CHARLIE Filter' })).toBeVisible();
});

test('Charlie uses named client scope and never GENERAL / Legacy List', async ({ page, context, baseURL }) => {
  const requests: Array<{ team?: string; client?: string }> = [];
  await stubTeamFilterReads(page, headers => requests.push({
    team: headers['x-team-context'],
    client: headers['x-client-context'],
  }));
  await installEnvSession(context, baseURL!, 'admin');
  await page.goto('/');
  await page.getByLabel('Settings').click();
  await page.getByLabel('Active Team Filter context').selectOption('CHARLIE');
  await page.getByRole('button', { name: 'Team Filter', exact: true }).click();
  const clients = page.getByLabel('Charlie client filter');
  await expect(clients).toBeVisible();
  const labels = await clients.locator('option').allTextContents();
  expect(labels.some(label => /general|legacy/i.test(label))).toBe(false);
  const selected = await clients.inputValue();
  expect(selected).not.toBe('');
  await expect.poll(() => requests.some(request => request.team === 'CHARLIE' && request.client === selected)).toBe(true);
  expect(requests.some(request => request.team === 'CHARLIE' && !request.client)).toBe(false);
  await expectNoHorizontalOverflow(page);
});
