/** Offline behavioral smoke tests, no network, credentials, or real database required. */
const fs=require('fs'), vm=require('vm'), assert=require('node:assert/strict');
const ts=require('typescript');
const crypto=require('node:crypto');
const invitations=[]; const clients=[];
const database={
  async query(sql,p=[]) {
    const q=sql.replace(/\s+/g,' ').trim();
    const ret=(rows)=>({rows});
    if(q.startsWith('SELECT id, provider, auth_type FROM clients')) return ret(clients.filter(x=>x.email.toLowerCase()===p[0]));
    if(q.startsWith('INSERT INTO client_authorization_invites')) {
      invitations.push({id:p[0],token_hash:p[1],client_name:p[2],assigned_email:p[3],provider:p[4],existing_client_id:p[5],created_by:p[6],status:'pending',created_at:new Date(),expires_at:p[7],attempts:0});return ret([]);
    }
    if(q.includes('WHERE assigned_email = $1 AND provider = $2') && q.startsWith('UPDATE')) {
      for(const i of invitations) if(i.assigned_email===p[0]&&i.provider===p[1]&&i.status==='pending'&&i.id!==p[2]) i.status='revoked'; return ret([]);
    }
    if(q.startsWith('SELECT * FROM client_authorization_invites WHERE token_hash')) return ret(invitations.filter(x=>x.token_hash===p[0]));
    if(q.includes('SET oauth_state_hash = $1') && q.includes('attempts = attempts + 1')) {
      const i=invitations.find(i=>i.id===p[3]&&i.status==='pending'&&i.attempts<p[4]);
      if(!i)return ret([]);
      Object.assign(i,{oauth_state_hash:p[0],code_verifier:p[1],attempt_expires_at:p[2],attempts:i.attempts+1,consented_at:new Date()}); return ret([{id:i.id}]);
    }
    if(q.startsWith('SELECT id, client_name, assigned_email, provider, existing_client_id, code_verifier')){
      return ret(invitations.filter(i=>i.oauth_state_hash===p[0]&&i.provider===p[1]&&i.status==='pending'&&i.attempt_expires_at >new Date()).map(i=>({...i})));
    }
    if(q.startsWith('UPDATE client_authorization_invites')&&q.includes('WHERE id = $1')&&q.includes('attempt_expires_at = NULL')&&!q.includes('status =')) {
      const i=invitations.find(i=>i.id===p[0]);if(i){i.oauth_state_hash=null;i.code_verifier=null;i.attempt_expires_at=null;}return ret([]);
    }
    if(q.startsWith('SELECT id, status, expires_at, existing_client_id FROM client_authorization_invites')) return ret(invitations.filter(i=>i.id===p[0]).map(i=>({...i})));
    if(q.startsWith('SELECT id, provider, auth_type, email FROM clients')) return ret(clients.filter(c=>c.email===p[0]));
    if(q.startsWith('INSERT INTO clients')) {
      clients.push({id:p[0],client_name:p[1],email:p[2],provider:p[3],auth_type:'oauth',oauth_access_token:p[4],oauth_refresh_token:p[5],status:'connected'});return ret([]);
    }
    if(q.startsWith('UPDATE clients SET provider =')) {
      const c=clients.find(c=>c.id===p[4]);Object.assign(c,{provider:p[0],auth_type:'oauth',oauth_access_token:p[1],oauth_refresh_token:p[2],status:'connected'});return ret([]);
    }
    if(q.startsWith('UPDATE client_authorization_invites') && q.includes("SET status = 'connected'")) {
      const i=invitations.find(i=>i.id===p[0]);Object.assign(i,{status:'connected',existing_client_id:p[1],completed_at:new Date()});return ret([]);
    }
    if(q.startsWith('SELECT i.id, i.client_name')) return ret(invitations);
    if(q.startsWith('UPDATE client_authorization_invites') && q.includes("status = 'revoked'")) {
      const i=invitations.find(i=>i.id===p[0]&&i.status==='pending');if(!i)return ret([]);i.status='revoked';return ret([{id:i.id}]);
    }
    throw Error('Mock did not expect SQL: '+q.slice(0,220));
  }, async withTransaction(work){return work({query:(...args)=>database.query(...args)});}
};
const src=fs.readFileSync(require('node:path').join(__dirname,'../server/clientAuthorization.ts'),'utf8');
const code=ts.transpileModule(src,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022,esModuleInterop:true}}).outputText;
const moduleObj={exports:{}};
const context={module:moduleObj,exports:moduleObj.exports,process:{env:{NODE_ENV:'production',CLIENT_AUTH_ENABLED:'true',RENDER_EXTERNAL_URL:'https://weapplying4u-mail-manager.onrender.com',GOOGLE_CLIENT_ID:'test-client',GOOGLE_CLIENT_SECRET:'test-secret',MICROSOFT_CLIENT_ID:'test-ms',MICROSOFT_CLIENT_SECRET:'test-ms-secret'}},
  require:(n)=>n==='node:crypto'?crypto:n==='./db.js'?database:require(n),
  Buffer,URL,URLSearchParams,Date,Map,console,AbortSignal,
  fetch:async (url)=>{
    if(url.includes('login.microsoftonline.com/consumers/oauth2/v2.0/token')) return {ok:true,json:async()=>({access_token:'ms-access',refresh_token:'ms-refresh',expires_in:3600})};
    if(url.includes('graph.microsoft.com/v1.0/me?$select')) return {ok:true,json:async()=>({mail:context.mockEmail,displayName:'Sample User'})};
    if(url.includes('graph.microsoft.com/v1.0/me/mailFolders/inbox/messages')) return {ok:true,json:async()=>({value:[]})};
    if(url.includes('oauth2.googleapis.com/token'))return {ok:true,json:async()=>({access_token:'mock-access',refresh_token:'mock-refresh',expires_in:3600})};
    if(url.includes('gmail/v1/users/me/messages')) return {ok:true,json:async()=>({messages:[]})};
    if(url.includes('gmail/v1/users/me/profile'))return {ok:true,json:async()=>({emailAddress:context.mockEmail})};
    throw Error('Unexpected provider request '+url);
  },mockEmail:'jane.test@gmail.com'};
vm.runInNewContext(code,context);
const routes=new Map();
const router={get(path,...handlers){routes.set(`GET ${path}`,handlers);},post(path,...handlers){routes.set(`POST ${path}`,handlers);}};
const pass=(_req,_res,next)=>next();
moduleObj.exports.registerClientAuthorizationRoutes(router,pass,pass);
async function call(method,path,req={}) {
  let handlers=routes.get(`${method} ${path}`),params={};
  if(!handlers)for(const [route,hs] of routes){const [m,pt]=route.split(' ');const parts=pt.split('/'),actual=path.split('/');if(m!==method||parts.length!==actual.length)continue;
    const p={};if(parts.every((s,i)=>s.startsWith(':')?(p[s.slice(1)]=actual[i],true):s===actual[i])){handlers=hs;params=p;break;}}
  assert.ok(handlers,`${method} ${path}`);
  const request={ip:'127.0.0.1',get:()=>undefined,params,body:{},query:{},user:{id:'admin_1',role:'ADMIN',email:'admin@example.com'},...req};
  let status=200,result=null,redirect=null,ended=false;
  const res={status(s){status=s;return res;},json(j){result=j;ended=true;return res;},setHeader(){},redirect(s,url){redirect=url||s;status=typeof s==='number'?s:302;ended=true;return res;}};
  for(const fn of handlers){if(ended)break;let nextCalled=false;await fn(request,res,()=>{nextCalled=true;});if(!nextCalled && !ended) throw Error('Handler did not end response or call next');}
  return {status,result,redirect};
}
async function run(){
  let r=await call('POST','/client-authorization/invitations',{body:{client_name:'Jane',email:'  Jane.Test@GMAIL.COM ',provider:'google'}});
  assert.equal(r.status,201); const token=r.result.link.split('/connect/')[1]; assert.ok(token.length>32);
  assert.equal(invitations.length,1);assert.equal(invitations[0].assigned_email,'jane.test@gmail.com');
  assert.equal(invitations[0].token_hash,crypto.createHash('sha256').update(token).digest('hex'));assert.ok(!JSON.stringify(invitations).includes(token));
  const fake=await call('GET','/client-authorization/invitation/invalid');assert.equal(fake.status,404);
  let start=await call('POST',`/client-authorization/invitation/${token}/start`,{body:{consent:false}});assert.equal(start.status,400);
  start=await call('POST',`/client-authorization/invitation/${token}/start`,{body:{consent:true}});assert.equal(start.status,200);
  let url=new URL(start.result.url);assert.equal(url.searchParams.get('login_hint'),'jane.test@gmail.com');
  const state=url.searchParams.get('state'); assert.ok(state); assert.equal(url.searchParams.get('code_challenge_method'),'S256');
  context.mockEmail='wrong.account@gmail.com';
  r=await call('GET','/client-connect/google/callback',{query:{state,code:'mock-code'}});
  assert.equal(r.status,303);assert.ok(r.redirect.includes('failed'));assert.equal(clients.length,0);assert.equal(invitations[0].status,'pending');
  r=await call('GET','/client-connect/google/callback',{query:{state,code:'replay'}});assert.ok(r.redirect.includes('failed'));
  start=await call('POST',`/client-authorization/invitation/${token}/start`,{body:{consent:true}});
  url=new URL(start.result.url);context.mockEmail='jane.test@gmail.com';
  r=await call('GET','/client-connect/google/callback',{query:{state:url.searchParams.get('state'),code:'mock-code'}});
  assert.equal(r.status,303);assert.ok(r.redirect.includes('success'));assert.equal(clients.length,1);assert.equal(invitations[0].status,'connected');
  assert.equal(clients[0].email,'jane.test@gmail.com');
  r=await call('POST',`/client-authorization/invitation/${token}/start`,{body:{consent:true}});assert.equal(r.status,410);
  const other=await call('POST','/client-authorization/invitations',{body:{client_name:'Bob',email:'bob@gmail.com',provider:'google'}});
  const otherToken=other.result.link.split('/connect/')[1];
  const revoke=await call('POST',`/client-authorization/invitations/${other.result.invitation.id}/revoke`);assert.equal(revoke.status,200);
  r=await call('POST',`/client-authorization/invitation/${otherToken}/start`,{body:{consent:true}});assert.equal(r.status,410);
  const microsoft=await call('POST','/client-authorization/invitations',{body:{client_name:'Mary',email:'mary@example.com',provider:'microsoft'}});
  const msToken=microsoft.result.link.split('/connect/')[1];
  const msStart=await call('POST',`/client-authorization/invitation/${msToken}/start`,{body:{consent:true}});
  const msUrl=new URL(msStart.result.url);
  assert.ok(msUrl.hostname==='login.microsoftonline.com');
  assert.equal(msUrl.searchParams.get('scope'),'offline_access User.Read Mail.Read');
  context.mockEmail='mary@example.com';
  const msResult=await call('GET','/client-connect/microsoft/callback',{query:{state:msUrl.searchParams.get('state'),code:'mock-ms-code'}});
  assert.ok(msResult.redirect.includes('success'));assert.equal(clients.length,2);
  assert.equal(clients[1].provider,'microsoft');
  const expiry=await call('POST','/client-authorization/invitations',{body:{client_name:'Late',email:'late@gmail.com',provider:'google'}});
  const exToken=expiry.result.link.split('/connect/')[1];
  invitations.find(i=>i.id===expiry.result.invitation.id).expires_at=new Date(Date.now()-1);
  const expiredResponse=await call('POST',`/client-authorization/invitation/${exToken}/start`,{body:{consent:true}});
  assert.equal(expiredResponse.status,410);
  console.log('PASS: Google and Microsoft flows, unique hashed links, binding, consent, PKCE, replay defense, wrong-account rejection, successful connection, one-use, expiry and revocation');
}
run().catch(e=>{console.error(e);process.exitCode=1});
