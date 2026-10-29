#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { checkWebsite, normalizeTarget } from './check.js';

const usage = `RelayWatch: check a homepage and its contact or booking destination.

Usage:
  node src/cli.js check <homepage> <enquiry-url> [--json] [--timeout <seconds>]
  node src/cli.js check --config <file.json> [--json] [--timeout <seconds>]
  relaywatch check <homepage> <enquiry-url> [--json] [--timeout <seconds>]

Options:
  --config <file>     JSON file containing {"sites":[{"name","url","contactUrl"}]}
  --json              Output machine-readable JSON instead of text
  --timeout <seconds> Per-page timeout, 1-60 seconds (default: 12)
  --help              Show this help

Exit codes: 0 all checks pass; 1 at least one HTTP failure; 2 inconclusive or invalid input.
Only test public websites you own or have permission to monitor.
`;

export function parseArgs(args) {
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) return {help:true};
  if (args.shift() !== 'check') throw new Error('Expected the check command. Use --help for usage.');
  const options = {json:false, timeoutMs:12000, urls:[], config:null};
  while (args.length) {
    const value=args.shift();
    if (value==='--json') options.json=true;
    else if (value==='--timeout') {
      const n=Number(args.shift());
      if (!Number.isInteger(n)||n<1||n>60) throw new Error('Timeout must be a whole number from 1 to 60 seconds.');
      options.timeoutMs=n*1000;
    } else if (value==='--config') {
      options.config=args.shift();
      if (!options.config || options.config.startsWith('--')) throw new Error('--config needs a filename.');
    } else if (value.startsWith('-')) throw new Error(`Unknown option: ${value}`);
    else options.urls.push(value);
  }
  if (options.config && options.urls.length) throw new Error('Choose a config file or two URLs, not both.');
  if (!options.config && options.urls.length!==2) throw new Error('Provide a homepage and an enquiry URL.');
  return options;
}

export async function loadSites(options, read=readFile) {
  let sites;
  if (options.config) {
    let config;
    try { config=JSON.parse(await read(options.config,'utf8')); }
    catch { throw new Error('Could not read a valid JSON config file.'); }
    sites=config?.sites;
    if (!Array.isArray(sites)||sites.length===0||sites.length>100) throw new Error('Config must contain 1-100 sites.');
  } else sites=[{name:'Website',url:options.urls[0],contactUrl:options.urls[1]}];
  return sites.map((site,i)=>{
    if (!site || typeof site!=='object' || typeof site.name!=='string'||!site.name.trim()||site.name.length>100) throw new Error(`Site ${i+1} needs a name of 1-100 characters.`);
    try {return {name:site.name.trim(),url:normalizeTarget(site.url),contactUrl:normalizeTarget(site.contactUrl)};}
    catch (e) {throw new Error(`Site ${i+1}: ${e.message}`);}
  });
}

export async function run(args,{check=checkWebsite,read=readFile,log=console.log,error=console.error}={}) {
  try {
    const options=parseArgs([...args]);
    if (options.help) {log(usage);return 0;}
    const sites=await loadSites(options,read);
    const reports=[];
    // Sequential execution keeps load on monitored servers predictable.
    for (const site of sites) {
      const result=await check(site.url,site.contactUrl,{timeoutMs:options.timeoutMs});
      reports.push({...site,checkedAt:new Date().toISOString(),...result});
    }
    if (options.json) log(JSON.stringify({version:1,reports},null,2));
    else for(const r of reports) {
      log(`\n${r.name}: ${r.status.toUpperCase()}\n${r.url}\n${r.summary}`);
      for(const c of r.results) log(`  ${c.status.toUpperCase().padEnd(7)} ${c.label}: ${c.detail}${c.url ? ` (${c.url})` : ''}`);
      log(`  Checked ${r.checkedAt}`);
    }
    return reports.some(r=>r.status==='attention') ? 1 : reports.some(r=>r.status!=='healthy') ? 2 : 0;
  } catch(e) {error(`RelayWatch: ${e instanceof Error ? e.message : 'Unable to run check.'}`);return 2;}
}

if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) process.exitCode=await run(process.argv.slice(2));
