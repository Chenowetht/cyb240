'use strict';
// Dependency-free integration checks using Chromium's DevTools Protocol.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{spawn}=require('node:child_process');
const createServer=require('./serve.cjs');
const output=path.resolve(__dirname,'../test-output');fs.mkdirSync(output,{recursive:true});
let downloadDir=output;
let captureExport=null;
const chrome=[process.env.CHROME_PATH,'C:/Program Files/Google/Chrome/Application/chrome.exe','C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe','/usr/bin/chromium','/usr/bin/google-chrome'].filter(Boolean).find(p=>fs.existsSync(p));
if(!chrome)throw Error('Set CHROME_PATH to a Chromium browser executable.');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function downloaded(name){if(captureExport){fs.writeFileSync(path.join(output,name),await captureExport(name));return;}const target=path.join(downloadDir,name);for(let i=0;i<100;i++){if(fs.existsSync(target)){fs.copyFileSync(target,path.join(output,name));return;}await sleep(100);}throw Error('Download did not arrive: '+name);}
(async()=>{
  const server=createServer();await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const url=`http://127.0.0.1:${server.address().port}/`,profile=fs.mkdtempSync(path.join(os.tmpdir(),'quiet-callback-test-'));
  downloadDir=path.join(profile,'downloads');fs.mkdirSync(downloadDir);
  let browser,ws;const errors=[],requests=[];
  try{
    const compatibility=process.env.CHROME_TEST_COMPAT==='1'?['--disable-crash-reporter','--disable-features=RendererCodeIntegrity','--no-sandbox']:[];
    browser=spawn(chrome,['--headless=new','--disable-gpu',...compatibility,'--no-first-run','--no-default-browser-check','--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'],{windowsHide:true,stdio:['ignore','ignore','pipe']});
    let stderr='';browser.stderr.on('data',d=>stderr+=d);
    const portFile=path.join(profile,'DevToolsActivePort');for(let i=0;i<100&&!fs.existsSync(portFile);i++)await sleep(100);
    if(!fs.existsSync(portFile))throw Error('Chromium did not start: '+stderr);
    const port=fs.readFileSync(portFile,'utf8').split('\n')[0];
    const targets=await(await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    ws=new WebSocket(targets.find(t=>t.type==='page').webSocketDebuggerUrl);await new Promise((r,j)=>{ws.onopen=r;ws.onerror=j;});
    let seq=0;const pending=new Map();
    ws.onmessage=message=>{const m=JSON.parse(message.data);if(m.id){const job=pending.get(m.id);if(job){pending.delete(m.id);m.error?job.reject(Error(JSON.stringify(m.error))):job.resolve(m.result);}}if(m.method==='Runtime.exceptionThrown'){errors.push(m.params.exceptionDetails.text+JSON.stringify(m.params.exceptionDetails.exception));console.error(errors.at(-1));}if(m.method==='Network.requestWillBeSent')requests.push(m.params.request.url);if(m.method==='Page.downloadProgress')console.log('Download',m.params.state);};
    const call=(method,params={})=>new Promise((resolve,reject)=>{const id=++seq;const timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP timeout: '+method+' '+JSON.stringify(params).slice(0,180)));},12000);pending.set(id,{resolve:v=>{clearTimeout(timer);resolve(v);},reject:e=>{clearTimeout(timer);reject(e);}});ws.send(JSON.stringify({id,method,params}));});
    const evaluate=async expression=>{const r=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true,userGesture:true});if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value;};
    if(process.env.CAPTURE_EXPORTS==='1')captureExport=name=>evaluate(`window.__exportBodies[${JSON.stringify(name)}]`);
    const click=id=>evaluate(`document.getElementById(${JSON.stringify(id)}).click()`);
    const set=(id,value)=>evaluate(`(()=>{const e=document.getElementById(${JSON.stringify(id)});e.value=${JSON.stringify(value)};e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));})()`);
    const text=id=>evaluate(`document.getElementById(${JSON.stringify(id)}).textContent`);
    const ready=async()=>{for(let i=0;i<100;i++){if(await evaluate('document.readyState==="complete" && !!document.getElementById("tab-Live")'))return;await sleep(50);}throw Error('Page load timed out');};
    const reload=async()=>{await call('Page.reload');await sleep(150);await ready();};
    const seedTime=async t=>{const script=await call('Page.addScriptToEvaluateOnNewDocument',{source:`(()=>{const s=JSON.parse(localStorage.getItem('quiet-callback-v1'));if(s){s.t=${t};localStorage.setItem('quiet-callback-v1',JSON.stringify(s));}})()`});await reload();await call('Page.removeScriptToEvaluateOnNewDocument',{identifier:script.identifier});};
    await call('Page.enable');await call('Runtime.enable');await call('Network.enable');
    await call('Page.addScriptToEvaluateOnNewDocument',{source:`window.__testOffset=0;const originalNow=performance.now.bind(performance);performance.now=()=>originalNow()+window.__testOffset;`});
    if(captureExport)await call('Page.addScriptToEvaluateOnNewDocument',{source:`window.__exportBodies={};const bodies=new Map(),make=URL.createObjectURL.bind(URL);URL.createObjectURL=blob=>{const url=make(blob);bodies.set(url,blob);return url;};const originalClick=HTMLAnchorElement.prototype.click;HTMLAnchorElement.prototype.click=function(){if(this.download&&bodies.has(this.href)){window.__exportBodies[this.download]=bodies.get(this.href).text();return;}return originalClick.call(this);};`});
    await call('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
    await call('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:downloadDir});
    await call('Page.navigate',{url});await ready();console.log('Loaded browser app.');
    assert.equal(await evaluate('document.getElementById("workspace").hidden'),true);
    await set('student-id','invalid');assert.equal(await evaluate('document.getElementById("student-id").checkValidity()'),false);
    await set('student-id','chenowetht2026');await evaluate('document.getElementById("start-form").requestSubmit()');await sleep(400);await click('toggle');
    assert.equal(await evaluate('document.getElementById("workspace").hidden'),false);
    const paused=await text('clock');await sleep(500);assert.equal(await text('clock'),paused);
    // Exercise actual timer and all playback speed settings without waiting 12 real minutes.
    for(const speed of [1,2,4]){await set('speed',String(speed));const before=await evaluate('JSON.parse(localStorage.getItem("quiet-callback-v1")).t');await click('toggle');await evaluate('window.__testOffset+=10000');await sleep(250);await click('toggle');const after=await evaluate('JSON.parse(localStorage.getItem("quiet-callback-v1")).t');assert.ok(after-before>=10*speed&&after-before<12*speed,`speed ${speed}`);}
    console.log('Playback controls verified.');
    await seedTime(119);assert.equal(await evaluate('document.querySelector("#cp-0 .cp-content").hidden'),true);assert.equal(await evaluate('document.getElementById("request-evidence").disabled'),true);
    await seedTime(240);assert.equal(await evaluate('document.querySelector("#cp-0 .cp-content").hidden'),false);await click('tab-IDS');assert.match(await text('evidence-table'),/No released evidence/);
    await set('request-reason','Does the approved service register explain the HR polling interval?');await click('request-evidence');assert.match(await text('requests'),/Pending/);
    await seedTime(261);assert.match(await text('requests'),/configured to poll/);
    await seedTime(500);await click('tab-IDS');assert.match(await text('evidence-table'),/BEH-204/);
    for(const name of ['Live','DNS','NetFlow','Firewall','IDS','TLS','Assets']){await click('tab-'+name);assert.equal(await evaluate(`document.getElementById('tab-${name}').getAttribute('aria-selected')`),'true');assert.ok((await text('evidence-table')).length>80);}
    await click('tab-NetFlow');await set('host-filter','FIN-WS34');await set('dest-filter','203.0.113.117');assert.match(await text('evidence-table'),/FIN-WS34/);assert.doesNotMatch(await text('evidence-table'),/HR-WS18/);assert.doesNotMatch(await text('evidence-table'),/203\.0\.113\.84/);
    await set('type-filter','DNS');assert.match(await text('evidence-table'),/No released evidence/);await set('type-filter','');await set('dest-filter','');await set('from-filter','10:14:00');await set('to-filter','10:15:05');assert.equal(await evaluate('document.querySelectorAll("#evidence-table tbody tr").length'),3);
    await click('use-flows');await click('calculate');assert.match(await text('calc-result'),/Mean 30.00 s/);
    await set('timestamps','10:99:00, 10:14:03, 10:14:32');await click('calculate');assert.match(await text('calc-result'),/outside/);
    await set('timestamps','10:14:03, 32, 63');await click('calculate');assert.match(await text('calc-result'),/one input format/);
    await click('clear-filters');await set('host-filter','FIN-WS34');await click('use-flows');await click('calculate');
    await evaluate('document.querySelector("#evidence-table [data-cite]").click()');await set('observation','Observed recurring TLS sessions. <img src=x onerror=alert(1)>');await set('interpretation','An automated process is plausible; process ownership remains unknown.');await evaluate('document.getElementById("note-form").requestSubmit()');assert.match(await text('notes'),/automated process/);assert.equal(await evaluate('document.querySelectorAll("#notes img").length'),0);
    await evaluate('document.querySelector("[data-edit]").click()');await set('interpretation','Updated interpretation: compare service records before deciding.');await evaluate('document.getElementById("note-form").requestSubmit()');assert.match(await text('notes'),/Updated interpretation/);
    await set('checkpoint-0','Compare the FIN and HR event series before assigning meaning to repetition.');await reload();assert.match(await text('notes'),/Updated interpretation/);assert.equal(await evaluate('document.getElementById("checkpoint-0").value'),'Compare the FIN and HR event series before assigning meaning to repetition.');assert.match(await text('run-status'),/PAUSED/);
    await click('export-json');await downloaded('quiet-callback-chenowetht2026-draft.json');await click('export-html');await downloaded('quiet-callback-chenowetht2026-draft.html');
    const draft=JSON.parse(fs.readFileSync(path.join(output,'quiet-callback-chenowetht2026-draft.json'),'utf8'));assert.equal(draft.status,'Draft');assert.ok(draft.releasedEvidence.every(e=>e.t<=500));assert.equal(draft.additionalEvidence[0].status,'Released');
    await seedTime(720);assert.match(await text('run-status'),/SHIFT COMPLETE/);assert.equal(await evaluate('document.getElementById("toggle").disabled'),true);assert.equal(await evaluate('document.querySelector("#cp-3 .cp-content").hidden'),false);
    await set('decision','Escalate for Endpoint Investigation');
    for(let i=0;i<4;i++)await set('checkpoint-'+i,'Checkpoint reasoning recorded for integration testing.');
    // Deliberate filler checks word-count mechanics, not assessment quality.
    for(let i=0;i<7;i++)await set('assessment-'+i,Array(45).fill('analysis').join(' '));
    await click('review-report');assert.match(await text('report-status'),/fields are complete/);assert.match(await text('word-count'),/315/);
    await click('export-json');await downloaded('quiet-callback-chenowetht2026-complete.json');await click('export-html');await downloaded('quiet-callback-chenowetht2026-complete.html');
    const json=JSON.parse(fs.readFileSync(path.join(output,'quiet-callback-chenowetht2026-complete.json'),'utf8')),html=fs.readFileSync(path.join(output,'quiet-callback-chenowetht2026-complete.html'),'utf8');
    assert.equal(json.releasedEvidence.length,171);assert.equal(json.assessmentWordCount,315);assert.equal(json.status,'Complete');assert.match(html,/&lt;img src=x onerror=alert\(1\)&gt;/);assert.doesNotMatch(html,/<img src=x/);assert.match(html,/Released evidence appendix/);
    await click('tab-Live');await click('clear-filters');
    fs.writeFileSync(path.join(output,'desktop.png'),Buffer.from((await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:false})).data,'base64'));
    await call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
    assert.equal(await evaluate('document.documentElement.scrollWidth<=window.innerWidth'),true);
    fs.writeFileSync(path.join(output,'mobile.png'),Buffer.from((await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:false})).data,'base64'));
    await evaluate('window.confirm=()=>true');await click('restart');assert.match(await text('clock'),/10:14:00/);assert.match(await text('notes'),/Updated interpretation/);assert.match(await text('requests'),/Pending/);
    assert.deepEqual(errors,[]);assert.deepEqual(requests.filter(u=>/^https?:/.test(u)&&!u.startsWith(url)),[],'No external application request');
    await click('new-case');await sleep(200);await ready();assert.equal(await evaluate('document.getElementById("workspace").hidden'),true);
    // Verify direct file opening, which is the simplest offline launch route.
    await call('Page.navigate',{url:require('node:url').pathToFileURL(path.resolve(__dirname,'../index.html')).href});await ready();assert.equal(await evaluate('window.QuietScenario.events.length'),171);
    assert.deepEqual(errors,[]);
    console.log('PASS: HTTP + file launch, ID validation, pause/resume, 1x/2x/4x, staging, all tabs and filters, requests, calculator validation, notes/edit/citations, autosave/reload, completion, JSON/HTML '+(captureExport?'export Blob generation (download interception enabled)':'downloads')+' and escaping, restart/clear, mobile overflow, no JS errors or external app requests.');
  }finally{if(ws)ws.close();if(browser)browser.kill();await new Promise(r=>server.close(r));/* Preserve temporary browser profile for OS-safe cleanup by the temp manager. */}
})().catch(e=>{console.error(e);process.exitCode=1;});
