import { lookup as systemLookup } from 'node:dns/promises';
import { Agent, request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
import { Readable } from 'node:stream';
import { checkServerIdentity } from 'node:tls';
import { normalizeTarget, isPublicAddress } from './policy.js';

function abortError() { return new DOMException('The check was aborted.', 'AbortError'); }
async function resolveWithAbort(host, lookup, signal) {
  if (signal?.aborted) throw abortError();
  let stop;
  const aborted = new Promise((_, reject) => { stop = () => reject(abortError()); signal?.addEventListener('abort', stop, {once:true}); });
  try {
    const answers = await Promise.race([lookup(host, {all:true, verbatim:true}), aborted]);
    if (signal?.aborted) throw abortError();
    if (!Array.isArray(answers) || !answers.length || answers.length > 64 ||
      !answers.every(a => a && isPublicAddress(a.address) && isIP(a.address) === a.family)) {
      throw new Error('This hostname does not resolve exclusively to public addresses.');
    }
    return answers.find(a => a.family === 4) ?? answers[0];
  } finally { signal?.removeEventListener('abort', stop); }
}

/** Dependency injection is for trusted code/tests, never URL input. */
export function createSafeFetch({lookup = systemLookup, request = httpsRequest} = {}) {
  return async function pinnedGet(input, {signal} = {}) {
    const url = new URL(normalizeTarget(String(input)));
    const pinned = await resolveWithAbort(url.hostname, lookup, signal);
    if (signal?.aborted) throw abortError();
    return new Promise((resolve, reject) => {
      // A fresh explicit agent avoids global agent/proxy/connection-pool state.
      // proxyEnv:{} opts out even on Node releases supporting env proxies.
      const agent = new Agent({keepAlive:false, maxCachedSessions:0, proxyEnv:{}});
      let req;
      try {
        req = request({
          protocol:'https:', hostname:pinned.address, family:pinned.family,
          port:443, method:'GET', path:url.pathname + url.search,
          agent, autoSelectFamily:false, signal, maxHeaderSize:16384,
          servername:url.hostname, rejectUnauthorized:true, minVersion:'TLSv1.2',
          checkServerIdentity:(_name, cert) => checkServerIdentity(url.hostname, cert),
          // There is deliberately no caller-provided header, auth, socket,
          // proxy or request-option forwarding, and no second DNS lookup.
          headers:{Host:url.hostname, 'User-Agent':'KnockCheck/0.1.1 (website-health-check)',
            Accept:'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1',
            'Accept-Encoding':'identity', Connection:'close'},
        }, res => {
          res.once('close', () => agent.destroy());
          try {
            const headers = new Headers();
            for (const [key, value] of Object.entries(res.headers)) {
              if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(', ') : value);
            }
            const status = res.statusCode;
            if (!Number.isInteger(status) || status < 200 || status > 599) throw new Error('Unsupported HTTP response.');
            const empty = [204, 205, 304].includes(status);
            const body = empty ? null : Readable.toWeb(res);
            if (empty) res.resume();
            resolve(new Response(body, {status, headers}));
          } catch (error) { res.destroy(); agent.destroy(); reject(error); }
        });
        req.once('error', error => { agent.destroy(); reject(error); });
        req.once('upgrade', (_res, socket) => { socket.destroy(); agent.destroy(); reject(new Error('Protocol upgrades are not supported.')); });
        req.end();
      } catch (error) { req?.destroy(); agent.destroy(); reject(error); }
    });
  };
}

// URL callers cannot supply request options or change the pinned transport.
export const safeFetch = createSafeFetch();
