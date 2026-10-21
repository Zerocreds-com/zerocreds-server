'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');

// The server owns the tunnel process instead of the agent that raised it. The
// invitation has to stay reachable after the chat window closes, because the
// recipient claims it whenever they get to it.
//
// The child gets a file for stdout and stderr, not a pipe. A pipe would break
// when this process exits and take the tunnel down with it; a file keeps the
// tunnel alive and leaves a log the owner can read.

const READ_LIMIT = 64 * 1024;

// Read the part of the provider log that this run wrote and return the
// published address, or null while the provider is still starting up.
function readPublishedUrl(logFile, urlPattern, fromOffset = 0) {
  let text = '';
  let handle = null;
  try {
    handle = fs.openSync(logFile, 'r');
    const size = fs.fstatSync(handle).size;
    if (size <= fromOffset) return null;
    const start = Math.max(fromOffset, size - READ_LIMIT);
    const length = size - start;
    const buffer = Buffer.alloc(length);
    fs.readSync(handle, buffer, 0, length, start);
    text = buffer.toString('utf8');
  } catch {
    return null;
  } finally {
    if (handle !== null) { try { fs.closeSync(handle); } catch { /* nothing to do */ } }
  }
  const match = text.match(urlPattern);
  return match ? match[0] : null;
}

function isProcessAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (error) { return error.code === 'EPERM'; }
}

// The start time of a running process, so a pid can be checked against the
// process it named. A recycled pid has a different start time.
function processStartTime(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return null;
  try {
    const value = execFileSync('ps', ['-o', 'lstart=', '-p', String(pid)],
      { encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    return value || null;
  } catch {
    return null;
  }
}

// A tunnel that was started here is stopped by process group, so a client that
// forked helpers goes down with it. The child is spawned detached, so it leads
// its own group and the group id equals its pid.
function stopTunnelProcess(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  for (const target of [-pid, pid]) {
    try { process.kill(target, 'SIGTERM'); return true; }
    catch (error) {
      if (error.code === 'ESRCH') return false;
    }
  }
  return false;
}

// Start the provider and wait until it publishes an address. The command comes
// from the catalog, never from the request, so it is run without a shell.
function startTunnelProcess({ command, urlPattern, logFile, label, timeoutMs = 45000 }) {
  return new Promise((resolve, reject) => {
    fs.mkdirSync(path.dirname(logFile), { recursive: true, mode: 0o700 });
    let output = null;
    let offset = 0;
    try {
      output = fs.openSync(logFile, 'a', 0o600);
      // The mode of an existing file is not changed by open, so it is set
      // explicitly: the log holds the published address of the tunnel.
      fs.fchmodSync(output, 0o600);
      offset = fs.fstatSync(output).size;
    } catch (error) {
      if (output !== null) { try { fs.closeSync(output); } catch { /* nothing to do */ } }
      reject(new Error(`cannot write the tunnel log: ${error.message}`));
      return;
    }

    let child;
    try {
      child = spawn(command[0], command.slice(1), {
        detached: true,
        stdio: ['ignore', output, output],
        env: { ...process.env },
      });
    } catch (error) {
      try { fs.closeSync(output); } catch { /* nothing to do */ }
      reject(new Error(`cannot start ${label}: ${error.message}`));
      return;
    }
    try { fs.closeSync(output); } catch { /* the child holds its own copy */ }
    // The tunnel has to outlive this process, and this process has to be able
    // to exit while the tunnel runs. The child leads its own process group
    // because it was spawned detached.
    child.unref();

    let settled = false;
    let poll = null;
    let timer = null;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      if (poll) clearInterval(poll);
      if (timer) clearTimeout(timer);
      if (error) { stopTunnelProcess(child.pid); reject(error); return; }
      resolve(result);
    };
    const published = () => {
      const url = readPublishedUrl(logFile, urlPattern, offset);
      return url ? { url, pid: child.pid, logFile, started_at: processStartTime(child.pid) } : null;
    };

    child.once('error', error => {
      if (error.code === 'ENOENT') {
        finish(new Error(`${label} is not installed on this computer`));
        return;
      }
      finish(new Error(`cannot start ${label}: ${error.message}`));
    });
    child.once('exit', (code, signal) => {
      // A provider can print its address and exit right after, so the log is
      // read once more before the exit is treated as a failure.
      const result = published();
      if (result) { finish(null, result); return; }
      finish(new Error(`${label} stopped before it published an address (${signal || `exit ${code}`})`));
    });

    poll = setInterval(() => {
      const result = published();
      if (result) finish(null, result);
    }, 250);
    timer = setTimeout(() => {
      finish(new Error(`${label} did not publish an address within ${Math.round(timeoutMs / 1000)} seconds`));
    }, timeoutMs);
  });
}

module.exports = { startTunnelProcess, stopTunnelProcess, readPublishedUrl, isProcessAlive, processStartTime };
