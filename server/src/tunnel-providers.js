'use strict';

const fs = require('node:fs');
const path = require('node:path');

// A tunnel provider publishes this computer's loopback port under a public
// https address. Every entry below is a ready-made configuration: the exact
// command to run, the pattern that reads the published address out of the
// provider output, and what the owner has to set up before it works.
//
// The catalog is the only place a tunnel command comes from. A request may
// name a provider, but it can never carry a command, so nothing that arrives
// from the network is ever handed to a shell.

const TUNNEL_PROVIDERS = [
  {
    id: 'localhost-run',
    label: 'localhost.run — no account, nothing to install',
    operator: 'Disseminate Consulting Limited',
    trust_class: 'network-provider',
    binary: 'ssh',
    account: null,
    command: port => ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'ServerAliveInterval=30',
      '-o', 'ServerAliveCountMax=3', '-R', `80:localhost:${port}`, 'nokey@localhost.run'],
    url_pattern: /https:\/\/[a-z0-9-]+\.lhr\.life/i,
    notes: 'The address changes on every start and the operator publishes no privacy policy. It sees the sealed invitation, the timing and the addresses, not the credential.',
  },
  {
    id: 'cloudflared',
    label: 'cloudflared — no account, no signup',
    operator: 'Cloudflare, Inc.',
    trust_class: 'network-provider',
    binary: 'cloudflared',
    account: null,
    command: port => ['cloudflared', 'tunnel', '--url', `http://127.0.0.1:${port}`, '--no-autoupdate'],
    url_pattern: /https:\/\/[a-z0-9-]+\.trycloudflare\.com/i,
    notes: 'The address is temporary and the tunnel dies with the process. The owner needs the cloudflared client installed.',
  },
  {
    id: 'ngrok',
    label: 'ngrok — needs an ngrok account',
    operator: 'ngrok, Inc.',
    trust_class: 'network-provider',
    binary: 'ngrok',
    account: 'ngrok',
    command: port => ['ngrok', 'http', String(port), '--log', 'stdout'],
    url_pattern: /https:\/\/[a-z0-9-]+\.(?:ngrok-free\.app|ngrok-free\.dev|ngrok-free\.pizza|ngrok\.app|ngrok\.dev|ngrok\.io)/i,
    notes: 'Needs an ngrok account and an authtoken in the ngrok configuration. The free plan allows one development domain.',
  },
];

// The SSH client verifies the tunnel host only when the owner pins its key.
// The nokey mode used here skips that check, so the channel can be
// intercepted by whoever answers for the provider address. Only the sealed
// invitation travels over it, so an interceptor still cannot read the
// credential, but the owner should know the tunnel host is not authenticated.
const SSH_HOST_KEY_NOTE = 'The SSH host key is not verified, so the tunnel channel can be intercepted. Only the sealed invitation travels over it.';

function findTunnelProvider(id, providers = TUNNEL_PROVIDERS) {
  if (typeof id !== 'string') return null;
  return providers.find(provider => provider.id === id) || null;
}

// Look an executable up in PATH the way a shell would, so the catalog can say
// plainly whether a provider can run on this computer.
function findExecutable(name) {
  if (!name) return null;
  if (name.includes('/') || name.includes('\\')) {
    try { fs.accessSync(name, fs.constants.X_OK); return name; } catch { return null; }
  }
  const directories = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const extensions = process.platform === 'win32'
    ? (process.env.PATHEXT || '.EXE;.CMD;.BAT').split(';').filter(Boolean)
    : [''];
  for (const directory of directories) {
    for (const extension of extensions) {
      const candidate = path.join(directory, name + extension);
      try { fs.accessSync(candidate, fs.constants.X_OK); return candidate; }
      catch { /* keep looking */ }
    }
  }
  return null;
}

// Render an argument array as a command line for the owner to read. The
// catalog never executes this string; the array is what runs.
function formatCommand(args) {
  return args.map(argument => (/[\s"']/.test(argument)
    ? `'${argument.replace(/'/g, `'\\''`)}'`
    : argument)).join(' ');
}

function providerRequirements(provider) {
  const requirements = [];
  if (provider.binary) requirements.push(`binary:${provider.binary}`);
  if (provider.account) requirements.push(`account:${provider.account}`);
  return requirements;
}

// Some providers keep their credentials in a file next to the home directory.
// Finding it tells the agent that the owner already set the provider up.
function hasAccountConfig(provider) {
  if (!provider.account) return true;
  const home = require('node:os').homedir();
  const candidates = provider.account === 'ngrok'
    ? [path.join(home, '.config', 'ngrok', 'ngrok.yml'), path.join(home, '.ngrok2', 'ngrok.yml')]
    : [];
  return candidates.some(file => { try { return fs.existsSync(file); } catch { return false; } });
}

// A provider entry carries the command that runs. Only an in-process caller
// may replace the catalog: an entry that came from a file or an environment
// variable would turn a provider name into a remote shell.
function isUsableProvider(provider) {
  return !!provider && typeof provider.id === 'string' && provider.id.length > 0
    && typeof provider.label === 'string' && typeof provider.operator === 'string'
    && typeof provider.command === 'function' && provider.url_pattern instanceof RegExp;
}

// The catalog as it is used, or null when the given list cannot be used.
function usableTunnelProviders(providers) {
  if (!Array.isArray(providers) || !providers.length) return null;
  return providers.every(isUsableProvider) ? providers : null;
}

// The catalog as the agent sees it: what to run, what it costs to run it and
// whether it can run here at all.
function tunnelProviderCatalog(localPort, providers = TUNNEL_PROVIDERS) {
  return providers.map(provider => {
    const binaryPath = findExecutable(provider.binary);
    const missing = [];
    if (!binaryPath) missing.push(`binary:${provider.binary}`);
    if (provider.account && !hasAccountConfig(provider)) missing.push(`account:${provider.account}`);
    const args = provider.command(localPort);
    return {
      id: provider.id,
      label: provider.label,
      operator: provider.operator,
      trust_class: provider.trust_class,
      requires: providerRequirements(provider),
      missing,
      installed: !!binaryPath,
      available: missing.length === 0,
      needs_account: !!provider.account,
      command: formatCommand(args),
      local_url: `http://127.0.0.1:${localPort}`,
      url_pattern: provider.url_pattern.source,
      notes: provider.id === 'localhost-run' ? `${provider.notes} ${SSH_HOST_KEY_NOTE}` : provider.notes,
    };
  });
}

module.exports = { TUNNEL_PROVIDERS, findTunnelProvider, findExecutable, formatCommand,
  providerRequirements, tunnelProviderCatalog, usableTunnelProviders, isUsableProvider };
