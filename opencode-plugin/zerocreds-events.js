const fs = require('node:fs')
const path = require('node:path')

const TOKEN_RE = /^[a-f0-9]{32}$/

function readPrivateToken(file) {
  const tokenPath = file.replace(/^~/, process.env.HOME || '')
  const fd = fs.openSync(tokenPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0))
  try {
    const stat = fs.fstatSync(fd)
    if (!stat.isFile() || (stat.mode & 0o077) || (process.getuid && stat.uid !== process.getuid())) {
      throw new Error('ZeroCreds admin token file must be private and owned by the current user')
    }
    const token = fs.readFileSync(fd, 'utf8').trim()
    if (token.length < 32 || /\s/.test(token)) throw new Error('Invalid ZeroCreds admin token file')
    return token
  } finally {
    fs.closeSync(fd)
  }
}

function sessionTokenFrom(output) {
  const text = output?.output
  if (typeof text !== 'string') return null
  try {
    const parsed = JSON.parse(text)
    return typeof parsed.token === 'string' && TOKEN_RE.test(parsed.token) ? parsed.token : null
  } catch {
    return null
  }
}

const pause = ms => new Promise(resolve => setTimeout(resolve, ms))

function continuation(event) {
  if (event === 'done') return 'The ZeroCreds form is complete. Check form_status using the earlier form token and continue the original task using the saved connection. Never ask for the credential in chat.'
  if (event === 'unknown') return 'The ZeroCreds form write has an unknown outcome. Check form_status using the earlier form token. Do not retry the submission or ask for the credential again automatically; explain that storage needs reconciliation.'
  return 'The ZeroCreds form expired before completion. Check form_status using the earlier form token and explain what remains to finish the original task.'
}

module.exports = async function ZeroCredsEvents(input, options = {}) {
  const baseUrl = (options.baseUrl || 'http://localhost/zerocreds').replace(/\/+$/, '')
  const url = new URL(baseUrl)
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) {
    throw new Error('ZeroCreds event plugin only supports a local loopback server')
  }
  const token = readPrivateToken(options.adminTokenFile || path.join(process.env.HOME || '', '.config/zerocreds/local/admin-token'))
  const active = new Set()

  return {
    'tool.execute.after': async (hook, result) => {
      if (hook.tool !== 'form_create') return
      const formToken = sessionTokenFrom(result)
      if (!formToken || active.has(formToken)) return
      active.add(formToken)
      void (async () => {
        try {
          let backoff = 1000
          while (true) {
            try {
              const response = await fetch(`${baseUrl}/api/session/${formToken}/events`, {
                headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
                signal: AbortSignal.timeout(24 * 60 * 60 * 1000),
              })
              if (!response.ok || !response.body) throw new Error('event stream unavailable')
              backoff = 1000
              const reader = response.body.getReader()
              const decoder = new TextDecoder()
              let buffer = ''
              while (true) {
                const { value, done } = await reader.read()
                if (done) break
                buffer += decoder.decode(value, { stream: true })
                if (buffer.length > 16_384) buffer = buffer.slice(-16_384)
                const blocks = buffer.split('\n\n')
                buffer = blocks.pop() || ''
                for (const block of blocks) {
                  const event = block.match(/^event: (done|expired|unknown)$/m)?.[1]
                  if (!event) continue
                  await input.client.session.promptAsync({
                    path: { id: hook.sessionID },
                    body: { parts: [{ type: 'text', text: continuation(event) }] },
                  })
                  return
                }
              }
            } catch {
              // A new subscription starts with current state, recovering an
              // event missed during a disconnect.
            }
            await pause(backoff)
            backoff = Math.min(backoff * 2, 15_000)
          }
        } finally {
          active.delete(formToken)
        }
      })()
    },
  }
}
