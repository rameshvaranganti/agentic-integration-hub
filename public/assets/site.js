document.querySelector('#menuBtn')?.addEventListener('click',()=>{const n=document.querySelector('#navLinks'); const o=n.classList.toggle('open');document.querySelector('#menuBtn').setAttribute('aria-expanded',String(o));});
const search=document.querySelector('#catalogSearch');const cards=[...document.querySelectorAll('[data-catalog]')];let category='all';function applyFilters(){const q=(search?.value||'').toLowerCase().trim();let count=0;cards.forEach(el=>{let ok=(category==='all'||el.dataset.category===category)&&el.textContent.toLowerCase().includes(q);el.classList.toggle('hide',!ok);if(ok)count++});const s=document.querySelector('#resultsCount');if(s)s.textContent=count+' resources found';}search?.addEventListener('input',applyFilters);document.querySelectorAll('[data-filter]').forEach(b=>b.addEventListener('click',()=>{category=b.dataset.filter;document.querySelectorAll('[data-filter]').forEach(x=>x.classList.toggle('active',x===b));applyFilters()}));
function toolRun(kind){const inp=document.querySelector('#toolInput')?.value||'';const out=document.querySelector('#toolOutput');if(!out)return;try{let result='';if(kind==='json'){result=JSON.stringify(JSON.parse(inp),null,2)}else if(kind==='xml'){const d=new DOMParser().parseFromString(inp,'application/xml');if(d.querySelector('parsererror'))throw Error('Invalid XML: '+d.querySelector('parsererror').textContent.slice(0,180));const ser=new XMLSerializer();const normalized=ser.serializeToString(d);result=normalized.replace(/></g,'>\n<')}else if(kind==='base64-encode'){result=btoa(Array.from(new TextEncoder().encode(inp),x=>String.fromCharCode(x)).join(''))}else if(kind==='base64-decode'){result=new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(atob(inp.trim()),c=>c.charCodeAt(0)))}else if(kind==='url-encode'){result=encodeURIComponent(inp)}else if(kind==='url-decode'){result=decodeURIComponent(inp)}else if(kind==='xpath'){const [xml,xpath]=inp.split(/\n---XPATH---\n/);if(!xpath)throw Error('Use XML, then a line containing ---XPATH---, then your XPath expression.');const d=new DOMParser().parseFromString(xml,'application/xml');if(d.querySelector('parsererror'))throw Error('Invalid XML');const nodes=d.evaluate(xpath.trim(),d,null,XPathResult.ANY_TYPE,null);if(nodes.resultType===XPathResult.STRING_TYPE)result=nodes.stringValue;else if(nodes.resultType===XPathResult.NUMBER_TYPE)result=String(nodes.numberValue);else if(nodes.resultType===XPathResult.BOOLEAN_TYPE)result=String(nodes.booleanValue);else{let node;let lines=[];while((node=nodes.iterateNext()))lines.push(node.textContent.trim());result=lines.join('\n')||'No matching nodes.'}}out.textContent=result||'(empty result)';out.style.color='#cce5ed'}catch(e){out.textContent=e.message;out.style.color='#ffab98'}}document.querySelectorAll('[data-tool]').forEach(b=>b.addEventListener('click',()=>toolRun(b.dataset.tool)));document.querySelector('#clearTool')?.addEventListener('click',()=>{document.querySelector('#toolInput').value='';document.querySelector('#toolOutput').textContent='Output appears here.'});document.querySelector('#copyOutput')?.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(document.querySelector('#toolOutput').textContent);document.querySelector('#copyOutput').textContent='Copied'}catch(e){document.querySelector('#copyOutput').textContent='Copy unavailable'}});

/* ---- MCP tool definition linter ---- */
(function(){const inp=document.querySelector('#lintInput'),out=document.querySelector('#lintOutput');if(!inp||!out)return;
const RISKY='{\n  "name": "call erp api",\n  "description": "Calls ERP",\n  "inputSchema": {\n    "type": "object",\n    "properties": {\n      "endpoint": { "type": "string" },\n      "body": { "type": "string" },\n      "userId": { "type": "string" }\n    }\n  }\n}';
const WRITE=/^(create|update|delete|post|cancel|release|approve|set|change|remove|submit|pay|transfer|book|send|write|modify|patch|put)/i;
function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function lintOne(t,i){const f=[];const add=(lvl,msg)=>f.push([lvl,msg]);const label=t&&t.name?t.name:'tool #'+(i+1);
 if(!t||typeof t!=='object'||Array.isArray(t)){add('error','Not a tool object.');return [label,f]}
 if(!t.name)add('error','Missing "name".');else{if(!/^[A-Za-z0-9_.-]{1,128}$/.test(t.name))add('error','Name should use only letters, digits, "_", "-" or "." (1 to 128 chars), no spaces.');
  if(/^(call|execute|run|invoke|do)_?(api|erp|sql|query|request|anything)?$/i.test(t.name.replace(/[ _-]/g,'_'))||/(_|^)(api|sql|query)(_|$)/i.test(t.name))add('warn','Generic name. Model business tasks (get_order_status), not transport endpoints (call_erp_api).');}
 const d=t.description||'';if(!d)add('error','Missing "description". The model chooses tools from descriptions.');else{if(d.length<40)add('warn','Description is very short ('+d.length+' chars). Say what it does, when to use it and what it will not do.');if(d.length>1200)add('warn','Description is long ('+d.length+' chars); it costs context on every request.');}
 const s=t.inputSchema;if(!s)add('error','Missing "inputSchema".');else{
  if(s.type!=='object')add('error','inputSchema.type must be "object".');
  const props=s.properties||{};const keys=Object.keys(props);
  if(s.additionalProperties!==false)add('warn','Set "additionalProperties": false so unexpected arguments are rejected.');
  if(keys.length&&!(Array.isArray(s.required)&&s.required.length))add('warn','No "required" fields. State which arguments are mandatory.');
  keys.forEach(k=>{const p=props[k]||{};
   if(p.type==='string'&&!p.pattern&&!p.enum&&!p.format&&!p.maxLength)add('info','"'+k+'": unconstrained string. Add pattern, enum, format or maxLength. Free text is where prompt injection travels.');
   if(!p.description&&!p.pattern&&!p.enum)add('info','"'+k+'": add a description so the model fills it correctly.');
   if(/^(user|employee|person|customer)_?id$/i.test(k))add('warn','"'+k+'": identity as a model-supplied argument. Derive the user from the access token instead, or the agent can be talked into acting for someone else.');
   if(/(password|secret|token|apikey|api_key|credential)/i.test(k))add('error','"'+k+'": never accept credentials as tool arguments.');
   if(/^(sql|query|script|code|command|expression)$/i.test(k))add('error','"'+k+'": tool appears to execute model-written code or queries (OWASP ASI05).');
   if(/^(endpoint|url|path|uri)$/i.test(k)&&p.type==='string'&&!p.enum)add('warn','"'+k+'": caller-chosen endpoint turns this into a generic proxy. Fix the target, or restrict with enum.');});
  if(s.$schema&&!/2020-12/.test(s.$schema))add('info','MCP 2026-07-28 allows JSON Schema 2020-12 keywords; $schema points elsewhere.');}
 const a=t.annotations||{};const isWrite=WRITE.test(t.name||'');
 if(!t.annotations)add('info','No annotations. Add readOnlyHint, destructiveHint, idempotentHint where true (hints for clients, never security controls).');
 if(isWrite&&a.readOnlyHint===true)add('error','Name suggests a write but readOnlyHint is true.');
 if(isWrite){const props=(s&&s.properties)||{};if(!Object.keys(props).some(k=>/idempot|request_?id|external_?ref|client_?ref/i.test(k)))add('warn','Write-style tool without an idempotency key. MCP 2026-07-28 makes retries routine; require a key and check it downstream.');
  if(a.destructiveHint===undefined)add('info','Write-style tool: declare destructiveHint so clients can ask for confirmation.');}
 if(t.outputSchema&&t.outputSchema.type&&t.outputSchema.type!=='object')add('info','outputSchema is usually an object so structuredContent stays extensible.');
 if(!f.length)add('ok','No issues found. Remember: authorization happens in the gateway and downstream APIs, not in the schema.');
 return [label,f]}
function run(){let data;try{data=JSON.parse(inp.value)}catch(e){out.innerHTML='<p class="lint-error">Invalid JSON: '+esc(e.message)+'</p>';return}
 let tools=Array.isArray(data)?data:(data&&Array.isArray(data.tools)?data.tools:(data&&data.result&&Array.isArray(data.result.tools)?data.result.tools:[data]));
 const names={};tools.forEach(t=>{if(t&&t.name)names[t.name]=(names[t.name]||0)+1});
 let html='';let counts={error:0,warn:0,info:0};tools.forEach((t,i)=>{const [label,f]=lintOne(t,i);if(t&&t.name&&names[t.name]>1)f.unshift(['error','Duplicate tool name.']);
  html+='<h4>'+esc(label)+'</h4><ul>'+f.map(([l,m])=>{if(counts[l]!==undefined)counts[l]++;return '<li class="lint-'+l+'"><b>'+l.toUpperCase()+'</b> '+esc(m)+'</li>'}).join('')+'</ul>'});
 out.innerHTML='<p class="small">'+tools.length+' tool(s): '+counts.error+' error, '+counts.warn+' warning, '+counts.info+' suggestion</p>'+html}
document.querySelector('#lintRun').addEventListener('click',run);document.querySelector('#lintWrite').addEventListener('click',()=>{inp.value=RISKY;run()});})();

/* ---- A2A Agent Card builder ---- */
(function(){const b=document.querySelector('#acBuild');if(!b)return;const v=id=>document.querySelector(id).value.trim();const out=document.querySelector('#acOutput');
const SEC={oauth:{oauth2:{oauth2SecurityScheme:{description:'OAuth 2.0 authorization code with PKCE',flows:{authorizationCode:{authorizationUrl:'https://login.example.com/authorize',tokenUrl:'https://login.example.com/token',scopes:{'agent.invoke':'Invoke this agent'},pkceRequired:true}}}}},
 cc:{oauth2:{oauth2SecurityScheme:{description:'OAuth 2.0 client credentials',flows:{clientCredentials:{tokenUrl:'https://login.example.com/token',scopes:{'agent.invoke':'Invoke this agent'}}}}}},
 mtls:{mtls:{mtlsSecurityScheme:{description:'Mutual TLS with partner certificates'}}},
 oidc:{oidc:{openIdConnectSecurityScheme:{description:'OpenID Connect',openIdConnectUrl:'https://login.example.com/.well-known/openid-configuration'}}}};
function build(){const skills=v('#acSkills').split('\n').map(l=>l.trim()).filter(Boolean).map(l=>{const [id,name,description,tags]=l.split('|').map(x=>(x||'').trim());return {id:id||'skill',name:name||id||'Skill',description:description||'',tags:(tags||'').split(',').map(x=>x.trim()).filter(Boolean)}});
 const sec=document.querySelector('#acSec').value;const card={name:v('#acName'),description:v('#acDesc'),version:v('#acVersion'),provider:{organization:v('#acOrg'),url:v('#acOrgUrl')},
  supportedInterfaces:[{url:v('#acUrl'),protocolBinding:document.querySelector('#acBinding').value,protocolVersion:'1.0'}],
  capabilities:{streaming:document.querySelector('#acStream').checked,pushNotifications:document.querySelector('#acPush').checked,extendedAgentCard:document.querySelector('#acExt').checked},
  securitySchemes:SEC[sec],
  defaultInputModes:['application/json','text/plain'],defaultOutputModes:['application/json'],skills};
 const warn=[];if(!/^https:\/\//.test(card.supportedInterfaces[0].url))warn.push('Endpoint should use https://');if(!card.description)warn.push('Add a description.');if(!skills.length)warn.push('Add at least one skill.');
 out.textContent=JSON.stringify(card,null,2)+'\n\n// Draft only. Replace example URLs, declare which schemes are required, add "signatures" (detached JWS over the RFC 8785 canonical card)\n// and validate against the official A2A v1.0 schema before publishing.'+(warn.length?'\n// Check: '+warn.join(' '):'');}
b.addEventListener('click',build);document.querySelector('#acCopy').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(out.textContent.split('\n\n// Draft')[0]);document.querySelector('#acCopy').textContent='Copied'}catch(e){document.querySelector('#acCopy').textContent='Copy unavailable'}});build();})();

/* ---- Live process-flow animation for diagrams ---- */
(function(){
const reduce=window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const NS='http://www.w3.org/2000/svg';
function pauseBtn(host,onToggle){const b=document.createElement('button');b.type='button';b.className='flowtoggle';b.setAttribute('aria-pressed','false');b.textContent='❚❚ Pause flow';
 b.addEventListener('click',()=>{const p=b.getAttribute('aria-pressed')!=='true';b.setAttribute('aria-pressed',String(p));b.textContent=p?'▶ Play flow':'❚❚ Pause flow';onToggle(p)});host.appendChild(b);return b}
/* Article SVG diagrams: dots travel each connector in top-to-bottom order, then the cycle repeats */
document.querySelectorAll('figure.diagram svg').forEach((svg,si)=>{
 const paths=[...svg.querySelectorAll('path.l')];if(!paths.length)return;
 svg.classList.add('flowing');if(reduce)return;
 const info=paths.map((p,i)=>{if(!p.id)p.id='flow'+si+'-'+i;const a=p.getPointAtLength(0);return {p,y:Math.round(a.y/12)}});
 const rows=[...new Set(info.map(x=>x.y))].sort((a,b)=>a-b);
 const step=0.9, travel=0.85, cycle=rows.length*step+1.2;
 info.forEach(({p,y})=>{const k=rows.indexOf(y), t0=k*step/cycle, t1=Math.min((k*step+travel)/cycle,0.99);
  const c=document.createElementNS(NS,'circle');c.setAttribute('r','5.5');c.setAttribute('class','flowdot');
  const m=document.createElementNS(NS,'animateMotion');m.setAttribute('dur',cycle+'s');m.setAttribute('repeatCount','indefinite');m.setAttribute('calcMode','linear');
  m.setAttribute('keyPoints','0;0;1;1');m.setAttribute('keyTimes','0;'+t0.toFixed(3)+';'+t1.toFixed(3)+';1');
  const mp=document.createElementNS(NS,'mpath');mp.setAttribute('href','#'+p.id);mp.setAttributeNS('http://www.w3.org/1999/xlink','xlink:href','#'+p.id);m.appendChild(mp);
  const o=document.createElementNS(NS,'animate');o.setAttribute('attributeName','opacity');o.setAttribute('dur',cycle+'s');o.setAttribute('repeatCount','indefinite');
  o.setAttribute('values','0;0;1;1;0;0');o.setAttribute('keyTimes','0;'+Math.max(t0-0.001,0).toFixed(3)+';'+t0.toFixed(3)+';'+t1.toFixed(3)+';'+Math.min(t1+0.02,0.995).toFixed(3)+';1');
  c.appendChild(m);c.appendChild(o);svg.appendChild(c);
  const g=document.createElementNS(NS,'animate');g.setAttribute('attributeName','stroke');g.setAttribute('dur',cycle+'s');g.setAttribute('repeatCount','indefinite');
  g.setAttribute('values','#53e0b6;#53e0b6;#eafff9;#53e0b6;#53e0b6');g.setAttribute('keyTimes','0;'+t0.toFixed(3)+';'+((t0+t1)/2).toFixed(3)+';'+t1.toFixed(3)+';1');p.appendChild(g);});
 pauseBtn(svg.closest('figure'),p=>{p?svg.pauseAnimations():svg.unpauseAnimations();svg.classList.toggle('paused',p)});
});
/* Homepage architecture: steps light up in order as a request flows through */
const arch=document.querySelector('.visual .vstack');
if(arch){arch.classList.add('live');if(reduce)arch.classList.add('still');
 const steps=[...arch.children];let n=0;steps.forEach(el=>{el.style.setProperty('--i',n);n++});arch.style.setProperty('--n',n);
 if(!reduce)pauseBtn(arch.closest('.visual'),p=>arch.classList.toggle('paused',p));}
})();
