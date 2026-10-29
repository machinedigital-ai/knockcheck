import test from 'node:test';
import assert from 'node:assert/strict';
import {run,parseArgs,loadSites} from '../src/cli.js';

test('parses URLs and refuses ambiguous or invalid flags',()=>{
  assert.deepEqual(parseArgs(['check','https://x.com','https://x.com/contact','--json','--timeout','15']).timeoutMs,15000);
  for(const args of [['check','https://x.com'],['check','--config'],['check','--timeout','0'],['check','https://x.com','https://x.com/contact','--oops'],['check','--config','x.json','https://x.com']]) assert.throws(()=>parseArgs(args));
});
test('validates config entries and refuses invalid targets before checking',async()=>{
  const options={config:'x',urls:[]};
  const read=async()=>JSON.stringify({sites:[{name:'Example',url:'https://x.com',contactUrl:'https://x.com/contact'}]});
  assert.equal((await loadSites(options,read))[0].url,'https://x.com/');
  await assert.rejects(loadSites(options,async()=>JSON.stringify({sites:[{name:'Bad',url:'https://127.0.0.1',contactUrl:'https://x.com'}]})));
  await assert.rejects(loadSites(options,async()=>'{'));
});
test('JSON output contains evidence and exits according to observed outcomes',async()=>{
  const output=[]; const options={log:x=>output.push(x),error:x=>output.push(x)};
  for (const [status,expected] of [['healthy',0],['attention',1],['unknown',2]]) {
    output.length=0;
    const exit=await run(['check','https://x.com','https://x.com/contact','--json'],{...options,check:async()=>({status,summary:'Result',results:[{label:'Page',status:'pass',detail:'ok'}]})});
    assert.equal(exit,expected);
    const report=JSON.parse(output[0]).reports[0];
    assert.equal(report.status,status);assert.equal(report.results[0].label,'Page');assert.ok(report.checkedAt);
  }
});
test('multiple sites run sequentially and failure takes precedence over unknown',async()=>{
  const output=[];let active=0,max=0,index=0;
  const code=await run(['check','--config','x.json'],{log:x=>output.push(x),error:x=>output.push(x),read:async()=>JSON.stringify({sites:[{name:'One',url:'https://one.com',contactUrl:'https://one.com/contact'},{name:'Two',url:'https://two.com',contactUrl:'https://two.com/contact'}]}),check:async()=>{active++;max=Math.max(max,active);await Promise.resolve();active--;return {status:index++?'attention':'unknown',summary:'Result',results:[]};}});
  assert.equal(code,1);assert.equal(max,1);assert.ok(output.some(s=>s.includes('One: UNKNOWN')));
});
test('invalid input exits 2 without starting a check',async()=>{
  let checked=false;const errors=[];
  assert.equal(await run(['check','http://not-https.com','https://x.com'],{check:async()=>{checked=true;},error:e=>errors.push(e),log:()=>{}}),2);
  assert.equal(checked,false);assert.match(errors[0],/HTTPS/);
});
