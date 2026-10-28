const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const state={dashboard:{},scans:[],findings:[],flows:[],campaigns:[],users:[],tenants:[],tickets:[],ticketConfig:null,sso:null,steps:[],recordPoll:null,lang:'zh'};

const I18N={
en:{
brand_sub:'Security Console',nav_dashboard:'Dashboard',nav_scans:'Scans',nav_findings:'Vulnerabilities',nav_login:'Login recorder',nav_campaigns:'Campaigns',nav_team:'Team / tickets',
scope_title:'Authorized use only',scope_body:'Scan only systems you own or have explicit permission to assess.',
page_dashboard_title:'Security overview',page_dashboard_sub:'Continuous visibility across authorized web assets',
page_scans_title:'Scan activity',page_scans_sub:'Track assessment coverage and progress',
page_findings_title:'Vulnerabilities',page_findings_sub:'Review evidence and remediation guidance',
page_login_title:'Login recorder',page_login_sub:'Click-to-record in the browser or edit steps manually',
page_campaigns_title:'Campaigns',page_campaigns_sub:'Orchestrate multi-target authorized assessments',
page_team_title:'Team, SSO & tickets',page_team_sub:'Tenants, OIDC login, and Jira/ServiceNow sync',
btn_new_scan:'＋ New scan',auth_banner:'API auth is enabled. Paste a Bearer token below to continue.',ph_api_token:'API token',
metric_scans:'Total scans',metric_scans_sub:'assessment jobs',metric_findings:'Vulnerabilities',metric_findings_sub:'all severities',
metric_high:'High risk',metric_high_sub:'critical + high',metric_running:'Running',metric_running_sub:'active scans',
recent_scans:'Recent scans',view_all:'View all',risk_dist:'Risk distribution',scan_activity:'Scan activity',refresh:'Refresh',all_severities:'All severities',filter_severity:'Severity',
login_record_title:'Interactive browser recording',login_record_help:'Launch a visible browser, complete login, then press <b>Done</b>. The draft lands in the editor only—click <b>Save flow</b> to store it. Passwords become <code>${APOCALYPSE_PASSWORD}</code> (set that env before replaying a saved flow). Prefer Cookie headers if you skip saved flows.',
flow_name:'Flow name',start_url:'Start URL',btn_start_record:'Start browser recording',
step_editor:'Step editor',btn_add_step:'＋ Add step',step_editor_help:'Edit a recorded flow or compose steps manually. Secrets use <code>${ENV}</code> placeholders.',
success_url:'Success URL contains',btn_load_template:'Load template',btn_export_json:'Export JSON',btn_save_flow:'Save flow',
campaign_title:'Campaign orchestration',campaign_form_help:'Set name, profile, and targets, then launch batch assessments.',campaign_list:'Campaign list',
name:'Name',targets_lines:'Targets (one URL per line)',profile:'Profile',concurrency:'Concurrency',
opt_graphql:'GraphQL introspection',opt_browser:'Browser crawl',opt_blind:'Blind injection (deep only)',opt_private_targets:'Allow private targets',
campaign_ack:'I confirm authorization for all listed targets',btn_create_campaign:'Create campaign',
preview_json:'Flow JSON',saved_flows_title:'Saved flows',
team_users:'Team users',team_users_help:'Create analyst accounts and bind them to a tenant.',team_user_list:'Directory',
team_users_rail:'Accounts & roles',tenants_sso_rail:'Isolation & login',ticket_sync_rail:'Issue trackers',
tenant_section:'Tenants',tenant_help:'Isolate assessment data by customer or business line.',
sso_section:'OIDC SSO',sso_help:'Connect an enterprise IdP. Secrets stay in environment variables.',
ticket_help:'Push findings to GitHub, Jira, or ServiceNow.',ticket_list:'Synced tickets',ticket_list_help:'Tickets created from findings appear here.',
provider_github_desc:'Issues tracker',provider_jira_desc:'Cloud / Server',provider_snow_desc:'Incident table',
role:'Role',tenant_id:'Tenant ID',btn_create_user:'Create user',
tenants_sso:'Tenants & SSO',tenant_name:'New tenant name',btn_create_tenant:'Create tenant',
oidc_issuer:'OIDC issuer',client_id:'Client ID',redirect_uri:'Redirect URI',client_secret_env:'Client secret env',
btn_save_sso:'Save SSO',btn_sso_login:'Start SSO login',ticket_sync:'Ticket sync',provider:'Provider',provider_webhook:'Generic webhook',
github_repo:'GitHub repo',base_url:'Base URL',jira_project:'Jira project key',snow_table:'ServiceNow table',
webhook_url:'Webhook URL',token_env:'Token env var',jira_email_env:'Jira email env',btn_save_ticket:'Save config',
modal_scan_title:'New website scan',modal_scan_sub:'Configure a scoped, non-destructive assessment.',
target_url:'Target URL',scan_profile:'Scan profile',profile_safe:'Safe — passive checks, ~30 request budget',
profile_balanced:'Balanced — harmless probes, ~100 request budget',profile_deep:'Deep — broader crawl, ~250 request budget',
saved_login:'Saved login flow',none:'None',login_password:'Login password (this scan)',
login_password_help:'Used once to expand ${APOCALYPSE_PASSWORD} when replaying a saved flow. Not stored. Leave empty if you use Cookie headers.',
custom_headers:'Authentication / custom headers',
custom_headers_help:'One per line. Values are used only for this scan and are not saved.',
openapi_url:'OpenAPI / Swagger JSON URL',graphql_url:'GraphQL URL',
opt_submit_forms:'POST form / JSON body canaries (Deep only)',opt_blind_scan:'Blind boolean/time SQLi heuristics (Deep only)',
opt_api_probe:'API probing (OpenAPI / GraphQL args)',opt_browser_verify:'Browser XSS verification (dialog)',
oast_url:'OAST collaborator base URL',oast_listen:'OAST listen (lab)',secondary_headers:'Secondary session headers (IDOR)',
policy_json:'Policy JSON (optional)',opt_private:'Allow private/local target',
scan_ack:'I confirm I own this target or have explicit authorization to test it.',cancel:'Cancel',btn_start_scan:'Start scan',
col_target:'Target',col_status:'Status',col_profile:'Profile',col_findings:'Findings',col_created:'Created',
empty_scans:'No scans yet.',empty_findings:'No vulnerabilities recorded.',empty_steps:'No steps yet.',empty_flows:'No saved flows.',
empty_campaigns:'No campaigns.',empty_users:'Local open mode (no users).',empty_tenants:'Default tenant only.',empty_tickets:'No tickets synced.',
btn_edit:'Edit',btn_delete:'Delete',btn_run:'Run',btn_ticket:'Ticket',btn_sync:'Sync',btn_open:'open',verified:'Verified',
toast_scan_queued:'Scan {id} queued',toast_scan_deleted:'Scan deleted',toast_flow_copied:'Flow JSON copied',toast_flow_saved:'Login flow saved',toast_flow_deleted:'Login flow deleted',confirm_delete_flow:'Delete login flow {name}?',
toast_record_done:'Recording loaded into the editor — click Save flow to store it',toast_campaign_created:'Campaign {id} created',toast_campaign_started:'Campaign started',
toast_user_created:'User created',toast_tenant_created:'Tenant created',toast_sso_saved:'SSO config saved',
toast_ticket_saved:'Ticket config saved',toast_ticket_created:'Ticket created',toast_ticket_synced:'Ticket synced',
record_status:'Recording {id}… complete login in the browser, then click Done',record_saved:'Draft ready in editor — not saved until you click Save flow',
sso_configured:'SSO configured · {issuer}',sso_complete:'Complete login in the IdP window, then paste the returned token above',
token_save:'Save this token now: {token}',err_headers:'Headers must use Name: value format',err_auth:'Authentication required',err_request:'Request failed',
coverage:'coverage: {c}; baseline new {n} / fixed {f} / recurring {r}'
},
zh:{
brand_sub:'安全控制台',nav_dashboard:'仪表盘',nav_scans:'扫描',nav_findings:'漏洞',nav_login:'登录录制',nav_campaigns:'批量任务',nav_team:'团队 / 工单',
scope_title:'仅限授权使用',scope_body:'只扫描你拥有或已获明确授权评估的系统。',
page_dashboard_title:'安全总览',page_dashboard_sub:'授权 Web 资产的持续可见性',
page_scans_title:'扫描活动',page_scans_sub:'跟踪评估覆盖与进度',
page_findings_title:'漏洞',page_findings_sub:'查看证据与修复建议',
page_login_title:'登录录制',page_login_sub:'在浏览器中点选录制，或手动编辑步骤',
page_campaigns_title:'批量任务',page_campaigns_sub:'编排多目标授权评估',
page_team_title:'团队、SSO 与工单',page_team_sub:'租户、OIDC 登录与 Jira/ServiceNow 同步',
btn_new_scan:'＋ 新建扫描',auth_banner:'已启用 API 认证。请粘贴 Bearer Token 后继续。',ph_api_token:'API Token',
metric_scans:'扫描总数',metric_scans_sub:'评估任务',metric_findings:'漏洞',metric_findings_sub:'全部严重级别',
metric_high:'高风险',metric_high_sub:'严重 + 高危',metric_running:'运行中',metric_running_sub:'进行中的扫描',
recent_scans:'最近扫描',view_all:'查看全部',risk_dist:'风险分布',scan_activity:'扫描活动',refresh:'刷新',all_severities:'全部严重级别',filter_severity:'严重级别',
login_record_title:'交互式浏览器录制',login_record_help:'启动可视浏览器，完成登录后点 <b>Done</b>。结果只填入编辑器，需点 <b>保存流程</b> 才入库。密码会红化为 <code>${APOCALYPSE_PASSWORD}</code>（重放已保存流程前请 export）。用 Cookie 扫描则不必保存流程。',
flow_name:'流程名称',start_url:'起始 URL',btn_start_record:'开始浏览器录制',
step_editor:'步骤编辑器',btn_add_step:'＋ 添加步骤',step_editor_help:'编辑已录制流程或手动编排步骤。密钥使用 <code>${ENV}</code> 占位符。',
success_url:'成功 URL 包含',btn_load_template:'加载模板',btn_export_json:'导出 JSON',btn_save_flow:'保存流程',
campaign_title:'批量任务编排',campaign_form_help:'设定名称、配置档与目标清单，再启动批量评估。',campaign_list:'任务列表',
name:'名称',targets_lines:'目标（每行一个 URL）',profile:'配置档',concurrency:'并发',
opt_graphql:'GraphQL introspection',opt_browser:'浏览器爬取',opt_blind:'盲注（仅 deep）',opt_private_targets:'允许私有目标',
campaign_ack:'我确认已获全部所列目标的授权',btn_create_campaign:'创建批量任务',
preview_json:'流程 JSON',saved_flows_title:'已保存流程',
team_users:'团队用户',team_users_help:'创建分析员账号并绑定租户。',team_user_list:'用户目录',
team_users_rail:'账号与角色',tenants_sso_rail:'隔离与登录',ticket_sync_rail:'缺陷跟踪对接',
tenant_section:'租户',tenant_help:'隔离不同客户或业务线的评估数据。',
sso_section:'OIDC SSO',sso_help:'对接企业身份提供方，密钥只引用环境变量。',
ticket_help:'把漏洞推送到 GitHub、Jira 或 ServiceNow。',ticket_list:'已同步工单',ticket_list_help:'从漏洞页推送后会出现在这里。',
provider_github_desc:'Issues 工单',provider_jira_desc:'Cloud / Server',provider_snow_desc:'Incident 表',
role:'角色',tenant_id:'租户 ID',btn_create_user:'创建用户',
tenants_sso:'租户与 SSO',tenant_name:'新租户名称',btn_create_tenant:'创建租户',
oidc_issuer:'OIDC Issuer',client_id:'Client ID',redirect_uri:'Redirect URI',client_secret_env:'Client Secret 环境变量',
btn_save_sso:'保存 SSO',btn_sso_login:'开始 SSO 登录',ticket_sync:'工单同步',provider:'提供方',provider_webhook:'通用 Webhook',
github_repo:'GitHub 仓库',base_url:'Base URL',jira_project:'Jira 项目 Key',snow_table:'ServiceNow 表',
webhook_url:'Webhook URL',token_env:'Token 环境变量',jira_email_env:'Jira 邮箱环境变量',btn_save_ticket:'保存配置',
modal_scan_title:'新建网站扫描',modal_scan_sub:'配置一次限定范围、非破坏性的评估。',
target_url:'目标 URL',scan_profile:'扫描配置档',profile_safe:'Safe — 被动检查，约 30 请求',
profile_balanced:'Balanced — 无害探针，约 100 请求',profile_deep:'Deep — 更广爬取，约 250 请求',
saved_login:'已保存登录流程',none:'无',login_password:'登录密码（本次扫描）',
login_password_help:'仅用于展开 ${APOCALYPSE_PASSWORD} 以重放已保存流程，不会入库。用 Cookie 时可留空。',
custom_headers:'认证 / 自定义请求头',
custom_headers_help:'每行一条。仅用于本次扫描，不会持久保存。',
openapi_url:'OpenAPI / Swagger JSON URL',graphql_url:'GraphQL URL',
opt_submit_forms:'POST 表单 / JSON 体探针（仅 Deep）',opt_blind_scan:'盲注布尔/时间型启发式（仅 Deep）',
opt_api_probe:'API 探测（OpenAPI / GraphQL 参数）',opt_browser_verify:'浏览器 XSS 验证（弹窗）',
oast_url:'OAST Collaborator Base URL',oast_listen:'OAST 监听（实验室）',secondary_headers:'第二会话请求头（IDOR）',
policy_json:'策略 JSON（可选）',opt_private:'允许私有/本地目标',
scan_ack:'我确认拥有该目标或已获明确授权进行测试。',cancel:'取消',btn_start_scan:'开始扫描',
col_target:'目标',col_status:'状态',col_profile:'配置档',col_findings:'发现',col_created:'创建时间',
empty_scans:'暂无扫描。',empty_findings:'暂无漏洞记录。',empty_steps:'暂无步骤。',empty_flows:'暂无已保存流程。',
empty_campaigns:'暂无批量任务。',empty_users:'本地开放模式（无用户）。',empty_tenants:'仅默认租户。',empty_tickets:'暂无同步工单。',
btn_edit:'编辑',btn_delete:'删除',btn_run:'运行',btn_ticket:'工单',btn_sync:'同步',btn_open:'打开',verified:'已验证',
toast_scan_queued:'扫描 {id} 已入队',toast_scan_deleted:'扫描已删除',toast_flow_copied:'流程 JSON 已复制',toast_flow_saved:'登录流程已保存',toast_flow_deleted:'登录流程已删除',confirm_delete_flow:'确定删除登录流程 {name}？',
toast_record_done:'录制已填入编辑器 — 点「保存流程」才会入库',toast_campaign_created:'批量任务 {id} 已创建',toast_campaign_started:'批量任务已启动',
toast_user_created:'用户已创建',toast_tenant_created:'租户已创建',toast_sso_saved:'SSO 配置已保存',
toast_ticket_saved:'工单配置已保存',toast_ticket_created:'工单已创建',toast_ticket_synced:'工单已同步',
record_status:'正在录制 {id}… 请在浏览器中完成登录并点击 Done',record_saved:'已填入编辑器（尚未入库，请点「保存流程」）',
sso_configured:'SSO 已配置 · {issuer}',sso_complete:'请在 IdP 窗口完成登录，然后将返回的 Token 粘贴到上方',
token_save:'请立即保存此 Token：{token}',err_headers:'请求头须使用 Name: value 格式',err_auth:'需要认证',err_request:'请求失败',
coverage:'覆盖: {c}; 基线 新增 {n} / 已修复 {f} / 复发 {r}'
}
};

function t(key,vars){let s=(I18N[state.lang]&&I18N[state.lang][key])||(I18N.en[key])||key;if(vars)Object.keys(vars).forEach(k=>{s=s.replaceAll(`{${k}}`,String(vars[k]))});return s}
function applyI18n(){
  document.documentElement.lang=state.lang==='zh'?'zh-CN':'en';
  $$('[data-i18n]').forEach(el=>{const k=el.getAttribute('data-i18n');if(k)el.textContent=t(k)});
  $$('[data-i18n-html]').forEach(el=>{const k=el.getAttribute('data-i18n-html');if(k)el.innerHTML=t(k)});
  $$('[data-i18n-placeholder]').forEach(el=>{const k=el.getAttribute('data-i18n-placeholder');if(k)el.setAttribute('placeholder',t(k))});
  $('#lang-zh')?.classList.toggle('active',state.lang==='zh');
  $('#lang-en')?.classList.toggle('active',state.lang==='en');
  const active=$$('.nav-item.active')[0]?.dataset.view||'dashboard';
  showView(active,true);
  enhanceSelects();
}
function closeAllCSelects(except){
  $$('.cselect.open').forEach(el=>{
    if(el===except)return;
    el.classList.remove('open');
    el.querySelector('.cselect-trigger')?.setAttribute('aria-expanded','false');
  });
}
function syncCSelect(wrap){
  const sel=wrap.querySelector('select');
  const trigger=wrap.querySelector('.cselect-trigger');
  const menu=wrap.querySelector('.cselect-menu');
  if(!sel||!trigger||!menu)return;
  const opt=sel.selectedOptions[0];
  trigger.innerHTML=`<span>${esc(opt?opt.textContent.trim():'')}</span><i class="cselect-caret" aria-hidden="true"></i>`;
  menu.innerHTML=[...sel.options].map((o,i)=>`<button type="button" class="cselect-option${o.selected?' selected':''}" data-index="${i}" role="option" aria-selected="${o.selected?'true':'false'}">${esc(o.textContent.trim())}</button>`).join('');
}
function enhanceSelect(sel){
  if(!sel||sel.dataset.enhanced==='1'||sel.hidden||sel.hasAttribute('hidden'))return;
  if(sel.id==='ticket-provider')return;
  sel.dataset.enhanced='1';
  sel.classList.add('cselect-native');
  const wrap=document.createElement('div');
  wrap.className='cselect';
  sel.parentNode.insertBefore(wrap,sel);
  wrap.appendChild(sel);
  const trigger=document.createElement('button');
  trigger.type='button';
  trigger.className='cselect-trigger';
  trigger.setAttribute('aria-haspopup','listbox');
  trigger.setAttribute('aria-expanded','false');
  const menu=document.createElement('div');
  menu.className='cselect-menu';
  menu.setAttribute('role','listbox');
  wrap.appendChild(trigger);
  wrap.appendChild(menu);
  syncCSelect(wrap);
  trigger.addEventListener('click',e=>{
    e.preventDefault();
    e.stopPropagation();
    const willOpen=!wrap.classList.contains('open');
    closeAllCSelects();
    wrap.classList.toggle('open',willOpen);
    trigger.setAttribute('aria-expanded',willOpen?'true':'false');
  });
  menu.addEventListener('click',e=>{
    const btn=e.target.closest('.cselect-option');
    if(!btn)return;
    e.preventDefault();
    e.stopPropagation();
    sel.selectedIndex=+btn.dataset.index;
    sel.dispatchEvent(new Event('change',{bubbles:true}));
    syncCSelect(wrap);
    wrap.classList.remove('open');
    trigger.setAttribute('aria-expanded','false');
  });
  sel.addEventListener('change',()=>syncCSelect(wrap));
}
function enhanceSelects(){
  $$('select').forEach(enhanceSelect);
  $$('.cselect').forEach(syncCSelect);
}
function setLang(lang){state.lang=lang==='en'?'en':'zh';localStorage.setItem('apocalypse_lang',state.lang);applyI18n();render()}

const esc=v=>String(v??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
function authHeaders(){const token=$('#api-token')?.value||localStorage.getItem('apocalypse_token')||'';return token?{'Authorization':`Bearer ${token}`}:{}}
async function api(path,options={}){const headers={...(options.headers||{}),...authHeaders()};if(options.body&&!headers['Content-Type'])headers['Content-Type']='application/json';const r=await fetch(path,{...options,headers});const j=await r.json().catch(()=>({}));if(r.status===401||r.status===403){$('#auth-banner').style.display='block';throw new Error(j.error||t('err_auth'))}if(!r.ok)throw new Error(j.error||t('err_request'));return j}
function toast(message){const el=$('#toast');el.textContent=message;el.classList.add('show');setTimeout(()=>el.classList.remove('show'),2600)}
function status(value){return `<span class="status status-${esc(value)}">${esc(value)}</span>`}
function severity(value){return `<span class="severity sev-${esc(value)}">${esc(value)}</span>`}
function coverage(x){return `http ${x.discovered_http||0} / browser ${x.discovered_browser||0}`}
function baselineTip(x){const s=(x.baseline&&x.baseline.summary)||{};return t('coverage',{c:coverage(x),n:s.new||0,f:s.fixed||0,r:s.recurring||0})}
function reportHref(id){return `/reports/${esc(id)}.html?lang=${esc(state.lang)}`}
function scanRows(items){if(!items.length)return `<p class="empty">${esc(t('empty_scans'))}</p>`;return `<div class="data-row header"><span>${esc(t('col_target'))}</span><span>${esc(t('col_status'))}</span><span>${esc(t('col_profile'))}</span><span>${esc(t('col_findings'))}</span><span>${esc(t('col_created'))}</span><span></span></div>`+items.map(x=>`<div class="data-row scan-row"><a class="target" href="${reportHref(x.id)}" target="_blank">${esc(x.target)}</a>${status(x.status)}<span title="${esc(baselineTip(x))}">${esc(x.profile)}</span><b title="${esc(baselineTip(x))}">${x.findings}</b><span>${new Date(x.created_at).toLocaleString(state.lang==='zh'?'zh-CN':'en')}</span><button class="text-button" data-del-scan="${esc(x.id)}" title="${esc(t('btn_delete'))}">${esc(t('btn_delete'))}</button></div>`).join('')}
function findingRows(items){if(!items.length)return `<p class="empty">${esc(t('empty_findings'))}</p>`;return items.map(x=>`<div class="finding-row">${severity(x.severity)}<b>${esc(x.title)}${x.verified?`<em class="verified">${esc(t('verified'))}</em>`:''}</b><span class="target">${esc(x.url)}</span><span>${esc(x.category)}</span><button class="text-button" data-ticket-scan="${esc(x.scan_id)}" data-ticket-finding="${esc(x.id)}">${esc(t('btn_ticket'))}</button></div>`).join('')}
function currentFlow(){return{start_url:$('#login-start').value.trim(),success_url_contains:$('#login-success').value.trim()||null,steps:state.steps.map(s=>({action:s.action,url:s.url||undefined,selector:s.selector||undefined,value:s.value||undefined,contains:s.contains||undefined,secret:!!s.secret}))}}
function renderSteps(){$('#login-steps').innerHTML=state.steps.map((s,i)=>`<div class="step-row"><select data-k="action" data-i="${i}"><option ${s.action==='goto'?'selected':''}>goto</option><option ${s.action==='fill'?'selected':''}>fill</option><option ${s.action==='click'?'selected':''}>click</option><option ${s.action==='wait_for_url'?'selected':''}>wait_for_url</option><option ${s.action==='wait_for_selector'?'selected':''}>wait_for_selector</option><option ${s.action==='wait'?'selected':''}>wait</option></select><input data-k="selector" data-i="${i}" placeholder="selector / url / contains" value="${esc(s.selector||s.url||s.contains||'')}"><input data-k="value" data-i="${i}" placeholder="value / ${'{ENV}'}" value="${esc(s.value||'')}"><button class="text-button" data-del="${i}">✕</button></div>`).join('')||`<p class="empty">${esc(t('empty_steps'))}</p>`;$('#login-preview').textContent=JSON.stringify(currentFlow(),null,2);enhanceSelects()}
function flowLabel(f){return `${f.name} · ${f.id}`}
function renderFlows(){$('#saved-flows').innerHTML=!state.flows.length?`<p class="empty">${esc(t('empty_flows'))}</p>`:state.flows.map(f=>`<div class="data-row"><span title="${esc(f.id)}">${esc(f.name)}</span><span class="muted">${esc(f.id)}</span><button class="text-button" data-edit-flow="${esc(f.id)}">${esc(t('btn_edit'))}</button><button class="text-button danger" data-del-flow="${esc(f.id)}">${esc(t('btn_delete'))}</button></div>`).join('');const sel=$('#login-flow-id');const current=sel.value;sel.innerHTML=`<option value="">${esc(t('none'))}</option>`+state.flows.map(f=>`<option value="${esc(f.id)}">${esc(flowLabel(f))}</option>`).join('');sel.value=current;const wrap=sel.closest('.cselect');if(wrap)syncCSelect(wrap);else enhanceSelects();syncLoginPasswordField()}
function renderCampaigns(){$('#campaign-list').innerHTML=!state.campaigns.length?`<p class="empty">${esc(t('empty_campaigns'))}</p>`:state.campaigns.map(c=>{const done=c.targets.filter(x=>x.status==='completed').length;return `<div class="data-row"><span>${esc(c.name)}</span>${status(c.status)}<span>${done}/${c.targets.length}</span><button class="text-button" data-run-campaign="${esc(c.id)}">${esc(t('btn_run'))}</button></div>`}).join('')}
function syncTicketProvider(provider,opts={}){
  const p=provider||'github';
  $('#ticket-provider').value=p;
  $$('input[name="ticket-provider-ui"]').forEach(x=>{x.checked=x.value===p});
  $$('#ticket-fields [data-providers]').forEach(row=>{
    const list=(row.getAttribute('data-providers')||'').trim().split(/\s+/).filter(Boolean);
    const show=list.includes(p);
    row.hidden=!show;
    row.classList.toggle('is-hidden',!show);
  });
  if(opts.setDefaultToken){
    const defaults={github:'GITHUB_TOKEN',jira:'JIRA_TOKEN',servicenow:'SERVICENOW_TOKEN',webhook:'WEBHOOK_TOKEN'};
    if(defaults[p])$('#ticket-token-env').value=defaults[p];
  }
}
function renderTeam(){
  $('#user-list').innerHTML=!state.users.length
    ?`<p class="empty">${esc(t('empty_users'))}</p>`
    :state.users.map(u=>`<div class="entity-row"><span class="entity-name">${esc(u.name)}</span><span class="role-pill ${esc(u.role)}">${esc(u.role)}</span><span class="entity-meta">${esc(u.tenant_id||'default')}</span></div>`).join('');
  $('#tenant-list').innerHTML=!state.tenants.length
    ?`<p class="empty">${esc(t('empty_tenants'))}</p>`
    :state.tenants.map(x=>`<div class="entity-row"><span class="entity-name">${esc(x.name)}</span><span class="entity-meta">${esc(x.slug)}</span><span class="entity-meta">${esc(x.id)}</span></div>`).join('');
  $('#ticket-list').innerHTML=!state.tickets.length
    ?`<p class="empty">${esc(t('empty_tickets'))}</p>`
    :state.tickets.map(x=>`<div class="entity-row"><span class="entity-name">${esc(x.title)}</span>${status(x.status)}<a class="target" href="${esc(x.external_url)}" target="_blank">${esc(t('btn_open'))}</a><button class="text-button" data-sync-ticket="${esc(x.id)}">${esc(t('btn_sync'))}</button></div>`).join('');
  if(state.ticketConfig){
    const c=state.ticketConfig.config||{};
    syncTicketProvider(state.ticketConfig.provider);
    if(c.repo)$('#ticket-repo').value=c.repo;
    if(c.url)$('#ticket-url').value=c.url;
    if(c.base_url)$('#ticket-base-url').value=c.base_url;
    if(c.project_key)$('#ticket-project').value=c.project_key;
    if(c.table)$('#ticket-table').value=c.table;
    if(c.token_env)$('#ticket-token-env').value=c.token_env;
    if(c.email_env)$('#ticket-email-env').value=c.email_env;
  }else{
    syncTicketProvider($('#ticket-provider').value||'github');
  }
  if(state.sso?.config){
    $('#sso-issuer').value=state.sso.config.issuer||'';
    $('#sso-client-id').value=state.sso.config.client_id||'';
    $('#sso-redirect').value=state.sso.config.redirect_uri||'';
    $('#sso-secret-env').value=state.sso.config.client_secret_env||'OIDC_CLIENT_SECRET';
    $('#sso-status').textContent=t('sso_configured',{issuer:state.sso.config.issuer});
  }
}
function render(){const d=state.dashboard,s=d.findings_by_severity||{};$('#metric-scans').textContent=d.total_scans||0;$('#metric-findings').textContent=d.total_findings||0;$('#metric-high').textContent=(s.critical||0)+(s.high||0);$('#metric-running').textContent=(d.scans_by_status?.running||0)+(d.scans_by_status?.queued||0);$('#recent-scans').innerHTML=scanRows(state.scans.slice(0,7));$('#all-scans').innerHTML=scanRows(state.scans);const filter=$('#severity-filter').value;$('#all-findings').innerHTML=findingRows(state.findings.filter(x=>!filter||x.severity===filter));const max=Math.max(1,...Object.values(s));$('#severity-chart').innerHTML=['critical','high','medium','low','info'].map(k=>`<div class="bar-row"><span>${k}</span><div class="bar"><i style="width:${((s[k]||0)/max)*100}%"></i></div><b>${s[k]||0}</b></div>`).join('');renderSteps();renderFlows();renderCampaigns();renderTeam();enhanceSelects()}
async function refresh(){try{const [d,s,f,lf,c,u,tk]=await Promise.all([api('/api/dashboard'),api('/api/scans'),api('/api/findings'),api('/api/login-flows'),api('/api/campaigns'),api('/api/users').catch(()=>({users:[],tenants:[],sso:null})),api('/api/tickets').catch(()=>({tickets:[],config:null}))]);state.dashboard=d;state.scans=s.scans;state.findings=f.findings;state.flows=lf.flows||[];state.campaigns=c.campaigns||[];state.users=u.users||[];state.tenants=u.tenants||[];state.sso=u.sso;state.tickets=tk.tickets||[];state.ticketConfig=tk.config;if(u.auth_required)$('#auth-banner').style.display='block';render()}catch(e){toast(e.message)}}
function showView(name,skipNav){$$('.view').forEach(x=>x.classList.remove('active'));$(`#${name}-view`)?.classList.add('active');if(!skipNav)$$('.nav-item').forEach(x=>x.classList.toggle('active',x.dataset.view===name));const map={dashboard:['page_dashboard_title','page_dashboard_sub'],scans:['page_scans_title','page_scans_sub'],findings:['page_findings_title','page_findings_sub'],login:['page_login_title','page_login_sub'],campaigns:['page_campaigns_title','page_campaigns_sub'],team:['page_team_title','page_team_sub']};const keys=map[name]||map.dashboard;$('#page-title').textContent=t(keys[0]);$('#page-subtitle').textContent=t(keys[1])}

function showTeamTab(name){
  $$('.rail-item').forEach(x=>x.classList.toggle('active',x.dataset.teamTab===name));
  $$('.team-tab').forEach(x=>x.classList.toggle('active',x.dataset.teamPanel===name));
}
$$('.nav-item').forEach(x=>x.onclick=()=>showView(x.dataset.view));$$('[data-jump]').forEach(x=>x.onclick=()=>showView(x.dataset.jump));
$$('.rail-item').forEach(x=>x.onclick=()=>showTeamTab(x.dataset.teamTab));
$$('input[name="ticket-provider-ui"]').forEach(x=>x.onchange=()=>syncTicketProvider(x.value,{setDefaultToken:true}));
syncTicketProvider('github');
$('#lang-zh').onclick=()=>setLang('zh');$('#lang-en').onclick=()=>setLang('en');
function syncLoginPasswordField(){
  const wrap=$('#login-password-wrap');
  const sel=$('#login-flow-id');
  const on=!!(sel&&sel.value);
  if(wrap){
    wrap.hidden=!on;
    wrap.setAttribute('aria-hidden',on?'false':'true');
  }
  if(!on){const pw=$('#login-password');if(pw)pw.value=''}
}
$('#new-scan').onclick=()=>{$('#scan-dialog').showModal();renderFlows();syncLoginPasswordField()};$('#close-dialog').onclick=$('#cancel-dialog').onclick=()=>{$('#scan-dialog').close();syncLoginPasswordField()};$('#severity-filter').onchange=render;$('#refresh-scans').onclick=refresh;
$('#login-flow-id').addEventListener('change',syncLoginPasswordField);
$('#recent-scans').onclick=$('#all-scans').onclick=async e=>{if(!e.target.dataset.delScan)return;try{await api(`/api/scans/${e.target.dataset.delScan}`,{method:'DELETE'});toast(t('toast_scan_deleted'));await refresh()}catch(err){toast(err.message)}};
$('#api-token')?.addEventListener('change',e=>{localStorage.setItem('apocalypse_token',e.target.value);refresh()});
function headerObject(value){const headers={};for(const raw of value.split(/\r?\n/)){const line=raw.trim();if(!line)continue;const i=line.indexOf(':');if(i<1)throw new Error(t('err_headers'));headers[line.slice(0,i).trim()]=line.slice(i+1).trim()}return headers}
$('#scan-form').onsubmit=async e=>{e.preventDefault();$('#form-error').textContent='';try{let policy=null;const rawPolicy=$('#policy-json').value.trim();if(rawPolicy)policy=JSON.parse(rawPolicy);const body={target:$('#target').value,profile:$('#profile').value,custom_headers:headerObject($('#custom-headers').value),secondary_headers:headerObject($('#secondary-headers').value),openapi_url:$('#openapi-url').value,browser_crawl:$('#browser-crawl').checked,browser_verify:$('#browser-verify').checked,graphql:$('#graphql').checked,graphql_url:$('#graphql-url').value,webhook_url:$('#webhook-url').value,submit_forms:$('#submit-forms').checked,blind_inject:$('#blind-inject').checked,api_probe:$('#api-probe').checked,oast_url:$('#oast-url').value,oast_listen:$('#oast-listen').value,policy,allow_private:$('#allow-private').checked,login_flow_id:$('#login-flow-id').value||null,login_password:$('#login-password')?.value||'',acknowledged:$('#ack').checked};const r=await api('/api/scans',{method:'POST',body:JSON.stringify(body)});$('#scan-dialog').close();e.target.reset();syncLoginPasswordField();toast(t('toast_scan_queued',{id:r.scan_id}));showView('scans');await refresh()}catch(err){$('#form-error').textContent=err.message}};
$('#add-step').onclick=()=>{state.steps.push({action:'fill',selector:'',value:''});renderSteps()};
$('#login-steps').onclick=e=>{if(e.target.dataset.del!=null){state.steps.splice(+e.target.dataset.del,1);renderSteps()}};
$('#login-steps').onchange=e=>{const i=+e.target.dataset.i,k=e.target.dataset.k;if(Number.isNaN(i)||!k)return;if(k==='action')state.steps[i].action=e.target.value;else if(['goto','wait_for_url'].includes(state.steps[i].action)){state.steps[i].url=state.steps[i].action==='goto'?e.target.value:'';state.steps[i].contains=state.steps[i].action==='wait_for_url'?e.target.value:'';state.steps[i].selector=''}else if(k==='selector')state.steps[i].selector=e.target.value;else if(k==='value'){state.steps[i].value=e.target.value;state.steps[i].secret=e.target.value.includes('${')}renderSteps()};
$('#login-load-template').onclick=async()=>{const r=await api('/api/login-flows');const tpl=r.template;$('#login-start').value=tpl.start_url;$('#login-success').value=tpl.success_url_contains||'';state.steps=(tpl.steps||[]).map(s=>({...s}));renderSteps()};
$('#login-export').onclick=()=>{navigator.clipboard?.writeText(JSON.stringify(currentFlow(),null,2));toast(t('toast_flow_copied'))};
$('#login-save').onclick=async()=>{try{await api('/api/login-flows',{method:'POST',body:JSON.stringify({name:$('#login-name').value,flow:currentFlow()})});toast(t('toast_flow_saved'));await refresh()}catch(e){toast(e.message)}};
$('#login-record').onclick=async()=>{try{const r=await api('/api/login-record',{method:'POST',body:JSON.stringify({name:$('#login-name').value,start_url:$('#login-start').value,timeout_seconds:300})});$('#login-record-status').textContent=t('record_status',{id:r.session_id});if(state.recordPoll)clearInterval(state.recordPoll);state.recordPoll=setInterval(async()=>{try{const s=await api(`/api/login-record/${r.session_id}`);if(s.status==='completed'){clearInterval(state.recordPoll);state.recordPoll=null;$('#login-record-status').textContent=t('record_saved');if(s.flow){$('#login-start').value=s.flow.start_url||'';$('#login-success').value=s.flow.success_url_contains||'';state.steps=(s.flow.steps||[]).map(step=>({...step}));renderSteps()}toast(t('toast_record_done'))}else if(s.status==='failed'){clearInterval(state.recordPoll);state.recordPoll=null;$('#login-record-status').textContent=s.error||'failed';toast(s.error||'failed')}}catch(err){clearInterval(state.recordPoll);state.recordPoll=null;toast(err.message)}},2000)}catch(e){toast(e.message)}};
$('#saved-flows').onclick=async e=>{if(e.target.dataset.editFlow){const f=state.flows.find(x=>x.id===e.target.dataset.editFlow);if(!f)return;$('#login-name').value=f.name;$('#login-start').value=f.flow.start_url||'';$('#login-success').value=f.flow.success_url_contains||'';state.steps=(f.flow.steps||[]).map(s=>({...s}));renderSteps()}if(e.target.dataset.delFlow){const id=e.target.dataset.delFlow;const f=state.flows.find(x=>x.id===id);if(!confirm(t('confirm_delete_flow',{name:f?flowLabel(f):id})))return;await api(`/api/login-flows/${id}`,{method:'DELETE'});toast(t('toast_flow_deleted'));await refresh()}};
$('#campaign-create').onclick=async()=>{try{const r=await api('/api/campaigns',{method:'POST',body:JSON.stringify({name:$('#campaign-name').value,targets:$('#campaign-targets').value,profile:$('#campaign-profile').value,concurrency:+$('#campaign-concurrency').value,graphql:$('#campaign-graphql').checked,browser_crawl:$('#campaign-browser').checked,blind_inject:$('#campaign-blind').checked,allow_private:$('#campaign-private').checked,acknowledged:$('#campaign-ack').checked})});toast(t('toast_campaign_created',{id:r.id}));await refresh()}catch(e){toast(e.message)}};
$('#campaign-list').onclick=async e=>{if(e.target.dataset.runCampaign){await api(`/api/campaigns/${e.target.dataset.runCampaign}/run`,{method:'POST'});toast(t('toast_campaign_started'));await refresh()}};
$('#user-create').onclick=async()=>{try{const r=await api('/api/users',{method:'POST',body:JSON.stringify({name:$('#user-name').value,role:$('#user-role').value,tenant_id:$('#user-tenant').value||'default'})});$('#user-token').hidden=false;$('#user-token').textContent=t('token_save',{token:r.token});toast(t('toast_user_created'));await refresh()}catch(e){toast(e.message)}};
$('#tenant-create').onclick=async()=>{try{await api('/api/tenants',{method:'POST',body:JSON.stringify({name:$('#tenant-name').value})});toast(t('toast_tenant_created'));await refresh()}catch(e){toast(e.message)}};
$('#sso-save').onclick=async()=>{try{await api('/api/sso/config',{method:'POST',body:JSON.stringify({config:{issuer:$('#sso-issuer').value,client_id:$('#sso-client-id').value,redirect_uri:$('#sso-redirect').value,client_secret_env:$('#sso-secret-env').value}})});toast(t('toast_sso_saved'));await refresh()}catch(e){toast(e.message)}};
$('#sso-login').onclick=async()=>{try{const r=await api('/api/sso/login',{method:'POST',body:JSON.stringify({tenant_id:$('#user-tenant').value||'default'})});window.open(r.authorize_url,'_blank','noopener');$('#sso-status').textContent=t('sso_complete')}catch(e){toast(e.message)}};
$('#ticket-save').onclick=async()=>{try{const provider=$('#ticket-provider').value;const config={token_env:$('#ticket-token-env').value};if(provider==='github')config.repo=$('#ticket-repo').value;else if(provider==='jira'){config.base_url=$('#ticket-base-url').value;config.project_key=$('#ticket-project').value;config.email_env=$('#ticket-email-env').value;config.issue_type='Bug'}else if(provider==='servicenow'){config.base_url=$('#ticket-base-url').value;config.table=$('#ticket-table').value}else config.url=$('#ticket-url').value;await api('/api/tickets/config',{method:'POST',body:JSON.stringify({provider,config})});toast(t('toast_ticket_saved'));await refresh()}catch(e){toast(e.message)}};
$('#all-findings').onclick=async e=>{const scanId=e.target.dataset.ticketScan,findingId=e.target.dataset.ticketFinding;if(!scanId)return;try{await api('/api/tickets',{method:'POST',body:JSON.stringify({scan_id:scanId,finding_id:Number(findingId)})});toast(t('toast_ticket_created'));showView('team');showTeamTab('tickets');await refresh()}catch(err){toast(err.message)}};
$('#ticket-list').onclick=async e=>{if(e.target.dataset.syncTicket){await api(`/api/tickets/${e.target.dataset.syncTicket}/sync`,{method:'POST'});toast(t('toast_ticket_synced'));await refresh()}};

const saved=localStorage.getItem('apocalypse_lang');
state.lang=saved||((navigator.language||'').toLowerCase().startsWith('zh')?'zh':'en');
if(localStorage.getItem('apocalypse_token'))$('#api-token').value=localStorage.getItem('apocalypse_token');
document.addEventListener('click',()=>closeAllCSelects());
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeAllCSelects()});
applyI18n();
enhanceSelects();
refresh();setInterval(refresh,5000);
