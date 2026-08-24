import { test, expect } from '@playwright/test';
import { expectNoHorizontalOverflow, installEnvSession } from './helpers';

test('narrow admin workflows remain usable without overflow', async ({ page, context, baseURL }) => {
  await installEnvSession(context, baseURL!, 'admin');
  await page.goto('/');
  await expectNoHorizontalOverflow(page);
  await page.getByRole('button', { name: 'Users', exact: true }).click();
  await expect(page.locator('.admin-create-form .team-access-select summary')).toBeVisible();
  await expectNoHorizontalOverflow(page);
  await page.getByLabel('Settings').click();
  await expect(page.getByLabel('Active Team Filter context')).toBeVisible();
  await expectNoHorizontalOverflow(page);
});
