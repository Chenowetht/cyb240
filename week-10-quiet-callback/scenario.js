/* Deterministic synthetic data. No DNS lookup, fetch, socket, or external resource. */
(function (root) {
  'use strict';
  const duration = 720;
  const assets = [
    ['FIN-WS34','10.24.10.34','Finance workstation','Finance','Windows 11; business hours 08:00–17:00; outbound HTTPS allowed; software baseline not supplied.'],
    ['HR-WS18','10.24.20.18','HR workstation','Human Resources','Windows 11; managed endpoint; routine agent check-ins expected.'],
    ['BACKUP-02','10.24.30.2','Backup server','Infrastructure','Approved cloud backup window 10:00–11:00 UTC; ticket CHG-1042; vault.cloud.example / 192.0.2.200.'],
    ['ENG-WS22','10.24.40.22','Engineering workstation','Engineering','Interactive documentation and code browsing expected.'],
    ['DNS-01','10.24.0.53','Recursive resolver','Infrastructure','Logs queries and answers; cached queries may not appear for every connection.'],
    ['FW-01','10.24.0.1','Perimeter firewall','Network Operations','Permits policy-compliant outbound HTTPS; ALLOW is not an application trust decision.'],
    ['IDS-01','10.24.0.10','Passive network sensor','Security Operations','Behavioral detections require an observation window; does not decrypt TLS.']
  ].map(([host,ip,role,owner,context]) => ({id:'A-'+host,host,ip,role,owner,context}));
  const events = [];
  function add(t,type,host,destination,details,extra={}) { events.push({t,type,host,destination,details,...extra}); }
  function session(t,host,ip,domain,bytes,duration,packets,profile) {
    add(t,'NetFlow',host,ip,`TCP/443 · ${duration.toFixed(1)} s · ${packets} packets · ${bytes.toLocaleString('en-US')} total bytes`,{port:443,bytes,duration,packets,domain,sensor:'FW-01'});
    add(t+0.1,'Firewall',host,ip,'ALLOW · outbound-https · TCP/443',{domain,sensor:'FW-01',action:'ALLOW'});
    add(t+0.2,'TLS',host,ip,`TLS 1.3 · SNI ${domain} · ${profile} · payload unavailable`,{domain,sensor:'IDS-01'});
  }
  const domain = 'sync.edge-metrics.example';
  add(1,'DNS','FIN-WS34','203.0.113.84',`${domain} → 203.0.113.84 · A · TTL 120`,{domain,sensor:'DNS-01'});
  let t=3, n=0; const intervals=[29,31,28,33,30,27,32,30,29,31];
  while(t<=duration-6) {
    const ip=t<450?'203.0.113.84':'203.0.113.117';
    session(t,'FIN-WS34',ip,domain,3817+(n%5)*73,4.7+(n%4)*0.2,11+n%3,'certificate issuer Example Public CA; fingerprint LAB-A71');
    t+=intervals[n%intervals.length]; n++;
  }
  [121,241,361].forEach(t=>add(t,'DNS','FIN-WS34','203.0.113.84',`${domain} → 203.0.113.84 · A · TTL 120`,{domain,sensor:'DNS-01'}));
  [450,570,690].forEach(t=>add(t,'DNS','FIN-WS34','203.0.113.117',`${domain} → 203.0.113.117 · A · TTL 120`,{domain,sensor:'DNS-01'}));
  for(let t=40;t<duration;t+=60) {
    if(t===40||t===340||t===640) add(t-2,'DNS','HR-WS18','198.51.100.45','agent.manage.example → 198.51.100.45 · A · TTL 300',{domain:'agent.manage.example',sensor:'DNS-01'});
    session(t,'HR-WS18','198.51.100.45','agent.manage.example',6200,2.4,16,'certificate issuer Example Enterprise CA; fingerprint LAB-H18');
  }
  add(8,'DNS','BACKUP-02','192.0.2.200','vault.cloud.example → 192.0.2.200 · A · TTL 600',{domain:'vault.cloud.example',sensor:'DNS-01'});
  [15,135,255,375,495,615].forEach((t,i)=>session(t,'BACKUP-02','192.0.2.200','vault.cloud.example',82000000+i*1250000,110.0,57000+i*800,'certificate issuer Example Cloud CA; fingerprint LAB-B02'));
  [8,55,117,209,287,402,521,677].forEach((t,i)=>{
    const ip=i%2?'192.0.2.81':'198.51.100.22', domain=i%2?'docs.build.example':'repo.build.example';
    add(t,'DNS','ENG-WS22',ip,`${domain} → ${ip} · A · TTL 60`,{domain,sensor:'DNS-01'});
    session(t+2,'ENG-WS22',ip,domain,18000+i*9281,1.2+i%3,28+i*12,'certificate issuer Example Public CA; fingerprint LAB-E22');
  });
  add(300,'IDS','FIN-WS34','203.0.113.84','BEH-204 · medium · recurring low-byte encrypted outbound sessions across a 5-minute window; analyst review requested. Behavioral signal, not payload confirmation.',{domain,sensor:'IDS-01'});
  add(610,'IDS','FIN-WS34','203.0.113.117','BEH-204 update · recurring session profile continues at a different destination address; correlate host, DNS, and TLS metadata.',{domain,sensor:'IDS-01'});
  events.sort((a,b)=>a.t-b.t);
  events.forEach((e,i)=>e.id='E'+String(i+1).padStart(4,'0'));
  const checkpoints=[
    {at:120,title:'Establish a baseline',prompt:'Compare at least two hosts. What is directly observable? Which explanations remain plausible?'},
    {at:300,title:'Correlate independent sources',prompt:'How does the newly available sensor context affect your hypothesis? What does it fail to establish?'},
    {at:480,title:'Revisit your hypothesis',prompt:'Compare early and later activity. What changed, what persisted, and what evidence would distinguish competing explanations?'},
    {at:720,title:'Decide and communicate',prompt:'Choose a proportionate next step. Document confidence, uncertainty, and the evidence needed to resolve it.'}
  ];
  const responses={
    change:'Service register SR-18: HR-WS18 runs an approved management agent configured to poll agent.manage.example every 60 seconds. CHG-1042 approves BACKUP-02 transfers to vault.cloud.example from 10:00–11:00 UTC. No matching FIN-WS34 software change was found in the supplied register; the register may be incomplete.',
    dns:'DNS-01 historical summary: sync.edge-metrics.example was first observed in the supplied seven-day resolver window today. HR management and backup domains appeared on each of the previous seven days. This is local visibility, not domain registration age or a reputation verdict.',
    endpoint:'Endpoint collection is not available to the network desk during this shift. A separate endpoint investigation can collect process-to-connection mapping, executable paths and hashes, persistence artifacts, and relevant user activity. No endpoint compromise confirmation is supplied.',
    owner:'Finance owner reports no intentionally launched synchronization task during this shift, but cannot identify every installed background service. Engineering confirms interactive documentation use. Owner recollection is incomplete and must be corroborated.'
  };
  function statistics(values) {
    if(values.length<3||values.some(v=>!Number.isFinite(v)||v<0)) throw new Error('Enter at least three valid timestamps or nonnegative seconds.');
    const sorted=[...values].sort((a,b)=>a-b), gaps=sorted.slice(1).map((v,i)=>v-sorted[i]);
    const mean=gaps.reduce((a,b)=>a+b,0)/gaps.length, ordered=[...gaps].sort((a,b)=>a-b), mid=Math.floor(ordered.length/2);
    const median=ordered.length%2?ordered[mid]:(ordered[mid-1]+ordered[mid])/2;
    const sd=Math.sqrt(gaps.reduce((s,v)=>s+(v-mean)**2,0)/gaps.length);
    return {samples:sorted.length,intervals:gaps,mean,median,min:ordered[0],max:ordered.at(-1),populationSD:sd,cv:mean?sd/mean:null,duplicates:sorted.filter((v,i)=>i&&v===sorted[i-1]).length};
  }
  const api={duration,assets,events,checkpoints,responses,statistics};
  if(typeof module!=='undefined') module.exports=api;
  root.QuietScenario=api;
})(typeof window==='undefined'?globalThis:window);
