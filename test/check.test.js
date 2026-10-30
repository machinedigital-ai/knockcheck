import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {Readable} from 'node:stream';
import {createSafeFetch} from '../src/network.js';
import { normalizeTarget, isPublicAddress, hasEnquiryLink, checkWebsite } from '../src/check.js';

function network(routes, answers=[{address:'93.184.216.34',family:4}]) {
  const calls=[],lookups=[];
  const fetcher=createSafeFetch({lookup:async host=>{lookups.push(host);return typeof answers==='function'?answers(host):answers;},request:(options,callback)=>{
    const url='https://'+options.servername+options.path;calls.push({url,options});
    const req=new EventEmitter();
    req.destroy=()=>{};
    req.end=()=>queueMicrotask(async()=>{
      try {
        let response=routes[url];if(typeof response==='function')response=await response(options);
        if(!response)throw new Error('Unexpected target '+url);
        const res=response.body?Readable.fromWeb(response.body):Readable.from([]);
        res.statusCode=response.status;res.headers=Object.fromEntries(response.headers);
        const abort=()=>res.destroy(new DOMException('aborted','AbortError'));
        options.signal?.addEventListener('abort',abort,{once:true});
        res.once('close',()=>options.signal?.removeEventListener('abort',abort));
        callback(res);
      }catch(error){req.emit('error',error);}
    });
    return req;
  }});
  return {fetcher,calls,lookups};
}
const html=body=>new Response(body,{headers:{'content-type':'text/html'}});

test('only public HTTPS hostnames without credentials or custom ports are accepted',()=>{
  for(const value of ['http://valid.com','https://127.0.0.1','https://[::1]','https://2130706433','https://0x7f000001','https://localhost','https://host.internal','https://name:secret@valid.com','https://valid.com:8080','https://x.local.']) {
    assert.throws(()=>normalizeTarget(value),undefined,value);
  }
  assert.equal(normalizeTarget('https://Example.com/path#section'),'https://example.com/path');
});

test('private, reserved, mapped and malformed IP addresses are rejected',()=>{
  for(const value of ['10.0.0.1','172.16.1.1','192.168.1.1','127.0.0.1','0.0.0.0','100.64.0.1','169.254.169.254','192.0.2.1','198.51.100.1','203.0.113.1','224.1.1.1','999.1.1.1','::1','fe80::1','fc00::1','::ffff:127.0.0.1','2001:db8::1','2001:0000::1','2002:7f00:1::','2001:::123']) assert.equal(isPublicAddress(value),false,value);
  assert.equal(isPublicAddress('1.1.1.1'),true);
  assert.equal(isPublicAddress('2606:4700:4700::1111'),true);
  assert.equal(isPublicAddress('2001:4860:4860::8888'),true);
});

test('static relative enquiry anchors are recognized; script content is not',()=>{
  assert.equal(hasEnquiryLink('<a href="/contact#form">Contact</a>','https://agency.com/', ['https://agency.com/contact']),true);
  assert.equal(hasEnquiryLink('<script>const fake = `<a href="/contact">`</script>','https://agency.com/', ['https://agency.com/contact']),false);
  assert.equal(hasEnquiryLink('<a href="https://agency.com.evil.net/contact">Contact</a>','https://agency.com/', ['https://agency.com/contact']),false);
  assert.equal(hasEnquiryLink('<a data-href="/contact">Contact</a>','https://agency.com/', ['https://agency.com/contact']),false);
  assert.equal(hasEnquiryLink('<a title=" href=\'/contact\' ">Contact</a>','https://agency.com/', ['https://agency.com/contact']),false);
});

test('a passing scan makes credential-free GETs and returns evidence',async()=>{
  const n=network({'https://agency.com/':html('<a href="/contact">Contact</a>'),'https://agency.com/contact':html('<h1>Contact us</h1>')});
  const result=await checkWebsite('https://agency.com/','https://agency.com/contact',{fetcher:n.fetcher});
  assert.equal(result.status,'healthy'); assert.equal(result.results.length,3);
  const target=n.calls.filter(c=>c.url.startsWith('https://agency.com'));
  assert.ok(target.every(c=>c.options.method==='GET' && c.options.hostname==='93.184.216.34' && c.options.servername==='agency.com' && c.options.rejectUnauthorized===true && !c.options.headers.Authorization && !c.options.headers.Cookie));
});

test('redirect to private address is blocked before the target is fetched',async()=>{
  const n=network({'https://agency.com/':new Response('',{status:302,headers:{location:'https://127.0.0.1/admin'}}),'https://agency.com/contact':html('Contact')});
  const result=await checkWebsite('https://agency.com/','https://agency.com/contact',{fetcher:n.fetcher});
  assert.equal(result.results[0].status,'unknown');
  assert.equal(n.calls.some(c=>c.url.includes('127.0.0.1')),false);
});

test('public-looking hostname resolving privately is blocked before connecting',async()=>{
  const n=network({},[{address:'10.0.0.1',family:4}]);
  const result=await checkWebsite('https://private.agency.com/','https://private.agency.com/contact',{fetcher:n.fetcher});
  assert.equal(result.status,'unknown');assert.equal(n.calls.length,0);
});
test('each request resolves only once and never uses global fetch or DoH',async()=>{
  const n=network({'https://agency.com/':html('<a href="/contact">Contact</a>'),'https://agency.com/contact':html('Contact')});
  assert.equal((await checkWebsite('https://agency.com/','https://agency.com/contact',{fetcher:n.fetcher})).status,'healthy');
  assert.deepEqual(n.lookups,['agency.com','agency.com']);assert.equal(n.calls.length,2);
});
test('redirect hostname is resolved and private answers rejected before its connection',async()=>{
  const n=network({'https://agency.com/':new Response('',{status:302,headers:{location:'https://private.agency.com/admin'}}),'https://agency.com/contact':html('Contact')},host=>[{address:host.startsWith('private.')?'127.0.0.1':'93.184.216.34',family:4}]);
  const result=await checkWebsite('https://agency.com/','https://agency.com/contact',{fetcher:n.fetcher});
  assert.equal(result.results[0].status,'unknown');assert.equal(n.calls.some(c=>c.options.servername==='private.agency.com'),false);
});
test('bot-blocked responses are inconclusive, server errors need attention',async()=>{
  const blocked=network({'https://agency.com/':new Response('',{status:403}),'https://agency.com/contact':new Response('',{status:429})});
  const result=await checkWebsite('https://agency.com/','https://agency.com/contact',{fetcher:blocked.fetcher});
  assert.equal(result.status,'unknown'); assert.ok(result.results.every(r=>r.status==='unknown'));
  const failed=network({'https://agency.com/':html('<a href="/contact">Contact</a>'),'https://agency.com/contact':new Response('',{status:500})});
  assert.equal((await checkWebsite('https://agency.com/','https://agency.com/contact',{fetcher:failed.fetcher})).status,'attention');
});

test('redirect loop terminates and timeout becomes an inconclusive result',async()=>{
  const loop=network({'https://agency.com/':new Response('',{status:302,headers:{location:'/'}}),'https://agency.com/contact':html('Contact')});
  const result=await checkWebsite('https://agency.com/','https://agency.com/contact',{fetcher:loop.fetcher});
  assert.match(result.results[0].detail,/redirect loop/);
  const hanging=network({'https://agency.com/':options=>new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new DOMException('aborted','AbortError')))), 'https://agency.com/contact':html('Contact')});
  const timed=await checkWebsite('https://agency.com/','https://agency.com/contact',{fetcher:hanging.fetcher,timeoutMs:10});
  assert.equal(timed.status,'unknown'); assert.match(timed.results[0].detail,/timed out/);
});

test('HTML inspection is bounded and does not claim missing JS links are broken',async()=>{
  const n=network({'https://agency.com/':html('x'.repeat(270000)+'<a href="/contact">Contact</a>'),'https://agency.com/contact':html('Contact')});
  const result=await checkWebsite('https://agency.com/','https://agency.com/contact',{fetcher:n.fetcher});
  assert.equal(result.results[2].status,'unknown'); assert.match(result.results[2].detail,/size limit/);
});

test('additional special-use and ambiguous addresses are rejected',()=>{
  for(const a of ['192.0.0.9','192.0.0.192','168.63.129.16','0127.0.0.1','127.1','64:ff9b::7f00:1','64:ff9b:1::1','2001:20::1','2002:0808:0808::1','3fff:100::1','fe80::1%eth0','::ffff:8.8.8.8']) assert.equal(isPublicAddress(a),false,a);
});
