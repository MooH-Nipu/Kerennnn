const test = require('node:test');
const assert = require('node:assert/strict');
const { isAllowedWebhookUrl, assertSafeWebhookDestination } = require('./_webhook-security');

test('webhooks accept only supported provider hosts', () => {
  assert.equal(isAllowedWebhookUrl('https://hooks.slack.com/services/T/B/X'), true);
  assert.equal(isAllowedWebhookUrl('https://discord.com/api/webhooks/1/token'), true);
  assert.equal(isAllowedWebhookUrl('https://discordapp.com/api/webhooks/1/token'), true);
  assert.equal(isAllowedWebhookUrl('https://example.com/hook'), false);
  assert.equal(isAllowedWebhookUrl('http://hooks.slack.com/services/T/B/X'), false);
  assert.equal(isAllowedWebhookUrl('https://hooks.slack.com.evil.test/x'), false);
  assert.equal(isAllowedWebhookUrl('https://user@hooks.slack.com/x'), false);
});

test('webhook delivery rejects DNS answers outside public unicast space', async () => {
  const lookup = async host => ({
    'hooks.slack.com': [{ address: '13.107.42.12', family: 4 }],
    'discord.com': [{ address: '162.159.135.232', family: 4 }],
  }[host] || [{ address: '127.0.0.1', family: 4 }]);

  await assert.doesNotReject(() => assertSafeWebhookDestination('https://hooks.slack.com/services/T/B/X', lookup));
  await assert.doesNotReject(() => assertSafeWebhookDestination('https://discord.com/api/webhooks/1/x', lookup));
  await assert.rejects(() => assertSafeWebhookDestination('https://example.com/x', lookup), /Unsupported webhook host/);
  await assert.rejects(
    () => assertSafeWebhookDestination('https://hooks.slack.com/services/T/B/X', async () => [{ address: '169.254.169.254', family: 4 }]),
    /public IP/
  );
  await assert.rejects(
    () => assertSafeWebhookDestination('https://hooks.slack.com/services/T/B/X', async () => [{ address: '::1', family: 6 }]),
    /public IP/
  );
});

test('webhook delivery rejects every IPv6 answer, including embedded private IPv4 forms', async () => {
  for (const address of ['::1', '::127.0.0.1', '::ffff:127.0.0.1', '0:0:0:0:0:ffff:7f00:1', '64:ff9b::7f00:1', '2002:7f00:1::']) {
    await assert.rejects(
      () => assertSafeWebhookDestination('https://hooks.slack.com/services/T/B/X', async () => [{ address, family: 6 }]),
      /public IP/
    );
  }
});
