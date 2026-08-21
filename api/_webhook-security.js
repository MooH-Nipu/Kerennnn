'use strict';
const dns = require('dns').promises;
const net = require('net');

const EXACT_HOSTS = new Set([
  'hooks.slack.com',
  'discord.com',
  'discordapp.com',
  'webhook.office.com',
  'outlook.office.com',
  'outlook.office365.com',
]);
const HOST_SUFFIXES = ['.webhook.office.com', '.logic.azure.com'];

function parseAllowedWebhookUrl(value) {
  let url;
  try { url = new URL(String(value || '')); } catch { return null; }
  const host = url.hostname.toLowerCase();
  if (url.protocol !== 'https:' || url.username || url.password || url.port) return null;
  if (!EXACT_HOSTS.has(host) && !HOST_SUFFIXES.some(suffix => host.endsWith(suffix))) return null;
  return url;
}

function isAllowedWebhookUrl(value) {
  return !!parseAllowedWebhookUrl(value);
}

function isPublicIPv4(address) {
  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b, c] = parts;
  return !(
    a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

function isPublicIp(address) {
  return net.isIP(address) === 4 && isPublicIPv4(address);
}

async function assertSafeWebhookDestination(value, lookup = (host) => dns.lookup(host, { all: true, family: 4, verbatim: true })) {
  const url = parseAllowedWebhookUrl(value);
  if (!url) throw new Error('Unsupported webhook host. Use Slack, Discord, or Microsoft Teams.');
  const answers = await lookup(url.hostname);
  const records = Array.isArray(answers) ? answers : [answers];
  if (!records.length || records.some(record => !isPublicIp(record.address))) {
    throw new Error('Webhook host must resolve only to public IP addresses.');
  }
  const pinned = records[0];
  return {
    url: url.toString(),
    lookup(_hostname, options, callback) {
      if (options?.all) return callback(null, [pinned]);
      callback(null, pinned.address, pinned.family);
    },
  };
}

module.exports = { isAllowedWebhookUrl, isPublicIp, assertSafeWebhookDestination };
