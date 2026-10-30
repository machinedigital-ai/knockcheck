import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import {readFileSync} from 'node:fs';
import {once} from 'node:events';
import {createSafeFetch} from '../src/network.js';
import {checkWebsite} from '../src/check.js';

// Public, test-only self-signed key/certificate. Never use these in production.
const cert=readFileSync(new URL('./fixtures/server-cert.pem',import.meta.url));
const key=readFileSync(new URL('./fixtures/server-key.pem',import.meta.url));
const PUBLIC=[{address:'93.184.216.34',family:4}];

async function fixture(t,handler) {
  const server=https.createServer({key,cert},handler);
  server.listen(0,'127.0.0.1');await once(server,'listening');
  t.after(()=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve);}));
  return server.address().port;
}
function localTransport(port,{lookup=async()=>PUBLIC,trust=true,seen=[]}={}) {
  return createSafeFetch({lookup,request:(options,callback)=>{
    // The production options MUST target the validated public IP. This test
    // adapter alone maps it to an isolated loopback TLS server/ephemeral port.
    assert.equal(options.hostname,'93.184.216.34');assert.equal(options.port,443);
    assert.equal(options.rejectUnauthorized,true);assert.equal(options.autoSelectFamily,false);
    assert.deepEqual(options.agent.options.proxyEnv,{});
    assert.equal(options.agent.options.keepAlive,false);
    seen.push(options);
    return https.request({...options,hostname:'127.0.0.1',family:4,port,...(trust?{ca:cert}:{})},callback);
  }});
}

test('real TLS: pins validated IP, preserves Host/SNI, ignores caller headers and never re-resolves',async t=>{
  let lookups=0;const seen=[],received=[];
  const port=await fixture(t,(req,res)=>{received.push({host:req.headers.host,sni:req.socket.servername,url:req.url,cookie:req.headers.cookie,auth:req.headers.authorization});res.end('ok');});
  const fetcher=localTransport(port,{seen,lookup:async()=>{lookups++;return lookups===1?PUBLIC:[{address:'127.0.0.1',family:4}];}});
  const response=await fetcher('https://agency.com/path?q=one',{headers:{Cookie:'secret',Authorization:'secret'},redirect:'follow',rejectUnauthorized:false});
  assert.equal(await response.text(),'ok');assert.equal(lookups,1);
  assert.deepEqual(received,[{host:'agency.com',sni:'agency.com',url:'/path?q=one',cookie:undefined,auth:undefined}]);
  assert.equal(seen[0].family,4);assert.equal(seen[0].maxHeaderSize,16384);
});

test('real TLS: wrong-host certificate is rejected despite a trusted test CA',async t=>{
  let requests=0;
  const port=await fixture(t,(_req,res)=>{requests++;res.end('should not be read');});
  await assert.rejects(localTransport(port)('https://wrong.agency.com/'),e=>e.code==='ERR_TLS_CERT_ALTNAME_INVALID');
  assert.equal(requests,0);
});

test('real TLS: an untrusted certificate is rejected',async t=>{
  const port=await fixture(t,(_req,res)=>res.end('should not be read'));
  await assert.rejects(localTransport(port,{trust:false})('https://agency.com/'),e=>e.code==='DEPTH_ZERO_SELF_SIGNED_CERT');
});

test('private, mixed, malformed, mapped and missing DNS answers never create a socket',async()=>{
  for(const answers of [[],[{address:'127.0.0.1',family:4}],[...PUBLIC,{address:'10.0.0.1',family:4}],
    [{address:'::ffff:127.0.0.1',family:6}],[{address:'fe80::1',family:6}],
    [{address:'93.184.216.34',family:6}],[{address:'invalid',family:4}]]) {
    let connected=false;
    const fetcher=createSafeFetch({lookup:async()=>answers,request:()=>{connected=true;throw new Error('must not connect');}});
    await assert.rejects(fetcher('https://agency.com/'),/public addresses/);assert.equal(connected,false);
  }
});

test('real TLS: redirect to a privately resolving hostname is blocked without a second connection',async t=>{
  const seen=[];
  const port=await fixture(t,(req,res)=>{if(req.url==='/'){res.writeHead(302,{Location:'https://private.agency.com/admin'});res.end();}else res.end('contact');});
  const lookup=async host=>host==='private.agency.com'?[{address:'192.168.1.1',family:4}]:PUBLIC;
  const result=await checkWebsite('https://agency.com/','https://agency.com/contact',{fetcher:localTransport(port,{lookup,seen})});
  assert.match(result.results[0].detail,/public addresses/);
  assert.equal(seen.length,2);assert.ok(seen.every(o=>o.servername==='agency.com'));
});

test('real TLS: read deadline aborts an unfinished response body',async t=>{
  const port=await fixture(t,(req,res)=>{res.writeHead(200,{'Content-Type':'text/html'});if(req.url==='/')res.write('unfinished');else res.end('contact');});
  const result=await checkWebsite('https://agency.com/','https://agency.com/contact',{fetcher:localTransport(port),timeoutMs:150});
  assert.equal(result.results[0].status,'unknown');assert.match(result.results[0].detail,/timed out/);
});

test('DNS deadline fails closed even if lookup resolves privately after cancellation',async()=>{
  const controller=new AbortController();let finish,connected=false;
  const fetcher=createSafeFetch({lookup:()=>new Promise(resolve=>{finish=resolve;}),request:()=>{connected=true;}});
  const pending=fetcher('https://agency.com/',{signal:controller.signal});controller.abort();
  await assert.rejects(pending,e=>e.name==='AbortError');finish([{address:'127.0.0.1',family:4}]);
  await new Promise(resolve=>setImmediate(resolve));assert.equal(connected,false);
});

test('real TLS: oversized response headers are rejected',async t=>{
  const port=await fixture(t,(_req,res)=>{res.writeHead(200,{'X-Oversized':'x'.repeat(20000)});res.end('large');});
  await assert.rejects(localTransport(port)('https://agency.com/'),e=>e.code==='HPE_HEADER_OVERFLOW');
});

test('real TLS: rejects unexpected compression instead of parsing compressed data as HTML',async t=>{
  const port=await fixture(t,(_req,res)=>{res.writeHead(200,{'Content-Type':'text/html','Content-Encoding':'gzip'});res.end('not processed');});
  const result=await checkWebsite('https://agency.com/','https://agency.com/contact',{fetcher:localTransport(port)});
  assert.equal(result.status,'unknown');assert.match(result.results[0].detail,/compressed/);
});
