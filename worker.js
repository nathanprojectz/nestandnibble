const cors={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"GET,POST,PUT,PATCH,DELETE,OPTIONS","Access-Control-Allow-Headers":"Content-Type,Authorization"};
const json=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...cors}});
const allowed=new Set(["orders","att","exp","stock","day","cfg","lv","slog","lock"]),enc=new TextEncoder();
const OWNER_EMAIL_DEFAULT="lyongaming738@gmail.com";
const legacyUsers={jonathan01:{name:"Jonathan",role:"staff",emp:"e2",h:"wv09dvk7vi"},ryan02:{name:"Ryan",role:"staff",emp:"e1",h:"3y2b1oc33n"},garin03:{name:"Garin",role:"staff",emp:"e3",h:"1s9uq9h7rar"},zikri04:{name:"Zikri",role:"owner",emp:null,h:"1yhecb3x5du"}};
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join(""),unhex=s=>Uint8Array.from(s.match(/.{2}/g)||[],x=>parseInt(x,16));
async function sha(v){return hex(await crypto.subtle.digest("SHA-256",typeof v==="string"?enc.encode(v):v))}
function legacy(s,seed=7){let h1=0xdeadbeef^seed,h2=0x41c6ce57^seed;for(let i=0,c;i<s.length;i++){c=s.charCodeAt(i);h1=Math.imul(h1^c,2654435761);h2=Math.imul(h2^c,1597334677)}h1=Math.imul(h1^(h1>>>16),2246822507)^Math.imul(h2^(h2>>>13),3266489909);h2=Math.imul(h2^(h2>>>16),2246822507)^Math.imul(h1^(h1>>>13),3266489909);return(4294967296*(2097151&h2)+(h1>>>0)).toString(36)}
function eq(a,b){if(typeof a!=="string"||typeof b!=="string"||a.length!==b.length)return false;let n=0;for(let i=0;i<a.length;i++)n|=a.charCodeAt(i)^b.charCodeAt(i);return n===0}
async function derive(pin,salt,n=50000){const k=await crypto.subtle.importKey("raw",enc.encode(pin),"PBKDF2",false,["deriveBits"]);return hex(await crypto.subtle.deriveBits({name:"PBKDF2",salt:unhex(salt),iterations:n,hash:"SHA-256"},k,256))}
const bearer=r=>(r.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"").trim();
async function who(r,env){const t=bearer(r);if(!t||t.length>200)return null;return env.DB.prepare("SELECT u.id,u.name,u.role,u.emp,s.expires_at FROM auth_sessions s JOIN app_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1").bind(await sha(t),Date.now()).first()}
const pub=u=>({id:u.id,name:u.name,role:u.role,emp:u.emp});
async function auth(r,url,env){
 if(url.pathname==="/api/auth/login"&&r.method==="POST"){
  let b;try{b=await r.json()}catch{return json({error:"Permintaan tidak valid"},400)}
  const id=String(b?.id||"").trim().toLowerCase(),pin=String(b?.pin||"");
  if(!/^[a-z0-9_-]{3,24}$/.test(id)||!/^[0-9]{4}$/.test(pin))return json({error:"ID atau PIN tidak valid"},400);
  const now=Date.now(),a=await env.DB.prepare("SELECT failures,locked_until FROM auth_attempts WHERE user_id=?").bind(id).first();
  if(a?.locked_until>now)return json({error:"Terlalu banyak percobaan. Tunggu sebentar."},429);
  let u=await env.DB.prepare("SELECT id,name,role,emp,pin_hash,active FROM app_users WHERE id=?").bind(id).first();
  if(u&&!u.active)return json({error:"Akun ini dinonaktifkan"},401);
  const old=legacyUsers[id];if(!u&&!old)return json({error:"ID atau PIN salah"},401);
  let ok=false,upgrade=false;
  if(u){if(u.pin_hash.startsWith("pbkdf2$")){const[,n,s,d]=u.pin_hash.split("$");ok=eq(await derive(pin,s,Number(n)),d)}else{ok=eq(legacy("nn|"+id+"|"+pin),u.pin_hash);upgrade=ok}}
  else{ok=eq(legacy("nn|"+id+"|"+pin),old.h);upgrade=ok}
  if(!ok){const failures=(a?.failures||0)+1,locked=failures>=5?now+60000:0;await env.DB.prepare("INSERT INTO auth_attempts(user_id,failures,locked_until,updated_at) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until,updated_at=excluded.updated_at").bind(id,failures,locked,now).run();return json({error:"ID atau PIN salah"},401)}
  if(upgrade){const p=u||{id,...old},salt=hex(crypto.getRandomValues(new Uint8Array(16))),d=await derive(pin,salt),hash="pbkdf2$50000$"+salt+"$"+d;
   if(u)await env.DB.prepare("UPDATE app_users SET pin_hash=? WHERE id=?").bind(hash,id).run();
   else await env.DB.prepare("INSERT INTO app_users(id,name,role,emp,pin_hash,active) VALUES(?,?,?,?,?,1)").bind(id,p.name,p.role,p.emp,hash).run();
  }
  await env.DB.prepare("DELETE FROM auth_attempts WHERE user_id=?").bind(id).run();
  u=await env.DB.prepare("SELECT id,name,role,emp FROM app_users WHERE id=?").bind(id).first();
  const token=hex(crypto.getRandomValues(new Uint8Array(32))),expires=now+43200000;
  await env.DB.prepare("INSERT INTO auth_sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)").bind(await sha(token),id,expires,now).run();
  return json({token,user:pub(u),expiresAt:expires});
 }
 if(url.pathname==="/api/auth/session"&&r.method==="GET"){const u=await who(r,env);return u?json({user:pub(u),expiresAt:u.expires_at}):json({error:"Sesi tidak berlaku"},401)}
 if(url.pathname==="/api/auth/logout"&&r.method==="POST"){const t=bearer(r);if(t)await env.DB.prepare("DELETE FROM auth_sessions WHERE token_hash=?").bind(await sha(t)).run();return json({ok:true})}
 return null;
}

/* ===== Kunci: kode verifikasi 4 angka dikirim ke email owner (Resend) ===== */
const LOCK_SQL="CREATE TABLE IF NOT EXISTS lock_codes(id TEXT PRIMARY KEY,h TEXT NOT NULL,tries INTEGER NOT NULL DEFAULT 0,exp INTEGER NOT NULL,created INTEGER NOT NULL,who TEXT,kind TEXT)";
const LKEY=/^[co]:\d{4}-\d{2}(-\d{2})?$/,wibDay=t=>new Date(t+7*3600e3).toISOString().slice(0,10);
const clean=(s,n)=>String(s||"").replace(/[\r\n<>]/g," ").slice(0,n);
async function lockSend(request,env,user){
 let b;try{b=await request.json()}catch{return json({ok:false,msg:"Permintaan tidak valid"},400)}
 if(!env.RESEND_KEY)return json({ok:false,msg:"Layanan email belum diatur: tambahkan secret RESEND_KEY di Cloudflare."},500);
 if(!LKEY.test(String(b.k||"")))return json({ok:false,msg:"Kunci tidak dikenal"},400);
 await env.DB.prepare(LOCK_SQL).run();
 const now=Date.now(),st=await env.DB.prepare("SELECT MAX(created) AS t,SUM(CASE WHEN created>? THEN 1 ELSE 0 END) AS n FROM lock_codes").bind(now-3600000).first();
 if(st?.t&&now-st.t<30000)return json({ok:false,msg:"Tunggu 30 detik sebelum meminta kode lagi"},429);
 if((st?.n||0)>=10)return json({ok:false,msg:"Terlalu banyak permintaan kode. Coba lagi sekitar 1 jam lagi."},429);
 const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%10000).padStart(4,"0"),id=hex(crypto.getRandomValues(new Uint8Array(16)));
 await env.DB.prepare("DELETE FROM lock_codes WHERE exp<?").bind(now-3600000).run();
 await env.DB.prepare("INSERT INTO lock_codes(id,h,tries,exp,created,who,kind) VALUES(?,?,0,?,?,?,?)").bind(id,await sha(code+":"+id+":"+env.RESEND_KEY),now+600000,now,user.id,b.k).run();
 const wib=new Date(now+7*3600e3).toISOString().replace("T"," ").slice(0,16);
 let res=null;try{res=await fetch("https://api.resend.com/emails",{method:"POST",headers:{Authorization:"Bearer "+env.RESEND_KEY,"Content-Type":"application/json"},body:JSON.stringify({from:env.MAIL_FROM||"Nest & Nibble <onboarding@resend.dev>",to:[env.OWNER_EMAIL||OWNER_EMAIL_DEFAULT],subject:"Kode buka kunci "+code+" · "+clean(b.f,40),text:"Kode buka kunci: "+code+"\n\nFitur  : "+clean(b.f,40)+"\nPeriode: "+clean(b.k,24)+"\nDiminta oleh: "+user.name+"\nWaktu  : "+wib+" WIB\n\nKode berlaku 10 menit dan hanya bisa dipakai sekali. Jangan berikan kode ini jika Anda tidak yakin permintaannya sah."})})}catch(e){console.error("resend_error",e)}
 if(!res||!res.ok){let d="";try{d=(await res.json()).message||""}catch{}console.error("resend_fail",res&&res.status,d);await env.DB.prepare("DELETE FROM lock_codes WHERE id=?").bind(id).run();return json({ok:false,msg:"Email gagal dikirim"+(d?": "+String(d).slice(0,140):". Periksa pengaturan Resend.")},502)}
 return json({ok:true,id});
}
async function lockVerify(request,env,user){
 let b;try{b=await request.json()}catch{return json({ok:false,msg:"Permintaan tidak valid"},400)}
 if(!env.RESEND_KEY)return json({ok:false,msg:"Layanan email belum diatur."},500);
 await env.DB.prepare(LOCK_SQL).run();
 const id=clean(b.id,40),code=String(b.code||""),k=String(b.k||""),now=Date.now(),row=id?await env.DB.prepare("SELECT id,h,tries,exp,kind FROM lock_codes WHERE id=?").bind(id).first():null;
 if(!row||row.kind!==k)return json({ok:false,msg:"Kode sudah tidak berlaku. Kirim ulang kode."});
 if(now>row.exp){await env.DB.prepare("DELETE FROM lock_codes WHERE id=?").bind(id).run();return json({ok:false,msg:"Kode kedaluwarsa. Kirim ulang kode."})}
 if(/^\d{4}$/.test(code)&&eq(await sha(code+":"+id+":"+env.RESEND_KEY),row.h)){await env.DB.prepare("DELETE FROM lock_codes WHERE id=?").bind(id).run();const rec={on:0,ts:now,exp:now+900000,by:user.name,d:wibDay(now),u:now};
  await env.DB.batch([env.DB.prepare("INSERT INTO records(collection,id,data,updated_at) VALUES('lock',?,?,?) ON CONFLICT(collection,id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at").bind(k,JSON.stringify(rec),now),env.DB.prepare("INSERT OR REPLACE INTO records(collection,id,data,updated_at) VALUES('lock',?,?,?)").bind("h:"+now,JSON.stringify({k,ts:now,by:user.name,d:wibDay(now),u:now}),now)]);
  return json({ok:true,rec})}
 const t=row.tries+1;
 if(t>=5){await env.DB.prepare("DELETE FROM lock_codes WHERE id=?").bind(id).run();return json({ok:false,msg:"Salah 5 kali. Kode dibatalkan, kirim ulang kode."})}
 await env.DB.prepare("UPDATE lock_codes SET tries=? WHERE id=?").bind(t,id).run();
 return json({ok:false,msg:"Kode salah. Sisa percobaan "+(5-t)+"."});
}

/* ===== Akun karyawan (owner saja): tambah, nonaktifkan, aktifkan, hapus ===== */
async function usersApi(request,url,env,user){
 if(user.role!=="owner")return json({error:"Hanya owner yang boleh mengelola akun"},403);
 const m=url.pathname.match(/^\/api\/users(?:\/([a-z0-9_-]{3,24}))?$/);if(!m)return json({error:"Not found"},404);const id=m[1];
 let b={};if(request.method!=="DELETE"){try{b=await request.json()}catch{return json({error:"Permintaan tidak valid"},400)}}
 if(request.method==="POST"&&!id){
  const uid=String(b.id||"").trim().toLowerCase(),name=String(b.name||"").trim(),pin=String(b.pin||""),emp=b.emp?String(b.emp).slice(0,24):null;
  if(!/^[a-z0-9]{3,16}$/.test(uid))return json({error:"ID login 3 sampai 16 huruf kecil atau angka"},400);
  if(name.length<2||name.length>20)return json({error:"Nama 2 sampai 20 huruf"},400);
  if(!/^\d{4}$/.test(pin))return json({error:"PIN harus 4 angka"},400);
  if(legacyUsers[uid]||await env.DB.prepare("SELECT 1 AS x FROM app_users WHERE id=?").bind(uid).first())return json({error:"ID login itu sudah dipakai"},409);
  const salt=hex(crypto.getRandomValues(new Uint8Array(16))),hash="pbkdf2$50000$"+salt+"$"+await derive(pin,salt);
  await env.DB.prepare("INSERT INTO app_users(id,name,role,emp,pin_hash,active) VALUES(?,?,?,?,?,1)").bind(uid,name,"staff",emp,hash).run();return json({ok:true});
 }
 if(!id)return json({error:"Not found"},404);
 const row=await env.DB.prepare("SELECT id,role FROM app_users WHERE id=?").bind(id).first(),old=legacyUsers[id];
 if((row&&row.role==="owner")||(!row&&old&&old.role==="owner"))return json({error:"Akun owner tidak bisa diubah"},403);
 if(!row&&!old)return json({error:"Akun tidak ditemukan"},404);
 const setActive=async act=>{
  if(!row)await env.DB.prepare("INSERT INTO app_users(id,name,role,emp,pin_hash,active) VALUES(?,?,?,?,?,?)").bind(id,old.name,old.role,old.emp,old.h,act).run();
  else await env.DB.prepare("UPDATE app_users SET active=? WHERE id=?").bind(act,id).run();
  if(!act)await env.DB.prepare("DELETE FROM auth_sessions WHERE user_id=?").bind(id).run();
 };
 if(request.method==="PATCH"){await setActive(b.active?1:0);return json({ok:true})}
 if(request.method==="DELETE"){
  if(old||!row){await setActive(0);return json({ok:true})}
  await env.DB.prepare("DELETE FROM auth_sessions WHERE user_id=?").bind(id).run();await env.DB.prepare("DELETE FROM auth_attempts WHERE user_id=?").bind(id).run();await env.DB.prepare("DELETE FROM app_users WHERE id=?").bind(id).run();return json({ok:true});
 }
 return json({error:"Not found"},404);
}

const adapter=`(()=>{const API="/api",KEY="nn_auth_token_v2",listeners=new Set(),base={"content-type":"application/json"};
const token=()=>{try{return localStorage.getItem(KEY)||""}catch{return""}},saveToken=v=>{try{v?localStorage.setItem(KEY,v):localStorage.removeItem(KEY)}catch{}};
async function req(path,opts={}){const h={...base,...opts.headers},t=token();if(t)h.Authorization="Bearer "+t;const r=await fetch(API+path,{...opts,headers:h});if(r.status===401&&path!=="/auth/login"){saveToken("");window.dispatchEvent(new Event("nn-auth-expired"));throw Error("Sesi login berakhir")}if(!r.ok){let msg="";try{msg=(await r.json()).error||""}catch{}throw Error(msg||"HTTP "+r.status)}return r.status===204?null:r.json()}
const auth={async login(id,pin){const x=await req("/auth/login",{method:"POST",body:JSON.stringify({id,pin})});saveToken(x.token);return x},async session(){if(!token())return null;try{return(await req("/auth/session")).user}catch{return null}},async logout(){try{await req("/auth/logout",{method:"POST",body:"{}"})}catch{}saveToken("")}};
const snap=rows=>({docs:rows.map(x=>({id:x.id,data:()=>x.data})),metadata:{fromCache:false}});
function notify(c,rows){const s=snap(rows);for(const x of listeners)if(x.collection===c){try{x.callback(s)}catch(e){console.error(e)}}}
async function refresh(c,f,v){const q=new URLSearchParams({collection:c});if(f){q.set("field",f);q.set("gte",v)}const rows=await req("/records?"+q);notify(c,rows);return rows}
function subscribe(c,f,v,cb){const x={collection:c,callback:cb};listeners.add(x);refresh(c,f,v).catch(()=>{});const timer=setInterval(()=>refresh(c,f,v).catch(()=>{}),5000);return()=>{listeners.delete(x);clearInterval(timer)}}
const db={doc(path){const[c,...p]=path.split("/"),id=p.join("/");return{async set(data){await req("/records/"+encodeURIComponent(c)+"/"+encodeURIComponent(id),{method:"PUT",body:JSON.stringify(data)});await refresh(c)},async delete(){await req("/records/"+encodeURIComponent(c)+"/"+encodeURIComponent(id),{method:"DELETE"});await refresh(c)},onSnapshot(cb,err){let active=true;const run=()=>refresh(c).then(rows=>{if(active){const x=rows.find(y=>y.id===id);cb({exists:!!x,data:()=>x?.data,metadata:{fromCache:false}})}}).catch(e=>{if(active&&err)err(e)});run();const timer=setInterval(run,5000);return()=>{active=false;clearInterval(timer)}}}},collection(c){return{where(f,op,v){if(op!==">=")throw Error("Operator not supported");return{onSnapshot(cb,err){return subscribe(c,f,v,cb)}}}}}};
window.nnAuth=auth;window.addEventListener("online",()=>document.dispatchEvent(new Event("nn-cloud-online")));window.claude=window.claude||{};window.claude.use=async n=>{if(n==="db")return db;if(n==="user"){const u=await auth.session();return u?{...u,can:async()=>true}:null}return null};
window.addEventListener("nn-auth-expired",()=>{try{localStorage.removeItem("nn_sess_v1")}catch{}const el=document.querySelector("#login");if(el){document.body.classList.add("locked");el.hidden=false;el.innerHTML='<div class="lgw"><h1>Sesi berakhir</h1><p>Silakan muat ulang halaman untuk masuk kembali.</p><button class="btn" onclick="location.reload()">Muat ulang</button></div>'}});
})();`;
function patch(html){
 if(html.includes('window.nnAuth.login'))return html;
 const a=html.indexOf("const cy="),u=html.indexOf("const USERS=",a),e=html.indexOf(";",u);
 if(a<0||u<0||e<0)throw Error("Cannot locate old login block");
 html=html.slice(0,a)+"const USERS={jonathan01:{name:'Jonathan',role:'staff',emp:'e2'},ryan02:{name:'Ryan',role:'staff',emp:'e1'},garin03:{name:'Garin',role:'staff',emp:'e3'},zikri04:{name:'Zikri',role:'owner',emp:null}};"+html.slice(e+1);
 const old="function tryLogin(){const el=$('#lid');if(!el)return;const id=(el.value||'').trim().toLowerCase(),u=USERS[id];\n if(!id){pin='';lgDots();lgMsg('Isi ID pengguna dulu',1);return}\n if(u&&cy('nn|'+id+'|'+pin)===u.h){tries=0;sessSet(id);enter(id);return}\n tries++;pin='';lgDots();try{navigator.vibrate(60)}catch(e){}\n if(tries>=5){lockUntil=Date.now()+30000;tries=0;lockTick()}else lgMsg('ID atau PIN salah ('+tries+'/5)',1)}";
 const next="async function tryLogin(){const el=$('#lid');if(!el)return;const id=(el.value||'').trim().toLowerCase();if(!id){pin='';lgDots();lgMsg('Isi ID pengguna dulu',1);return}try{const result=await window.nnAuth.login(id,pin);tries=0;sessSet(id);enter(id,false,result.user);await initSync()}catch(e){tries++;pin='';lgDots();try{navigator.vibrate(60)}catch(e){}if(tries>=5){lockUntil=Date.now()+30000;tries=0;lockTick()}else lgMsg(e.message||'ID atau PIN salah',1)}}";
 if(!html.includes(old))throw Error("Cannot locate login function");
 html=html.replace(old,next).replace("function enter(id,quiet){U=Object.assign({id},USERS[id]);","function enter(id,quiet,profile){U=Object.assign({id},USERS[id],profile||{});").replace("logout:()=>{sessSet(null);U=null;closeM();ui.unl=false;lgShow()}","logout:()=>{window.nnAuth.logout();sessSet(null);U=null;closeM();ui.unl=false;lgShow()}");
 const i=html.indexOf("async function initSync()"),j=html.indexOf(" if(!DB){",i);if(i<0||j<0)throw Error("Cannot locate sync initialization");
 const init="async function initSync(){\n let authUser=null;try{authUser=await claude.use('user')}catch(e){}\n if(!authUser){RO=false;U=null;sessSet(null);document.body.classList.remove('ro');lgShow();setSync('off');return}\n U=Object.assign({id:authUser.id},USERS[authUser.id]||{},authUser);RO=false;document.body.classList.remove('ro');if(U){applyRole();if(!tabOK(ui.tab))ui.tab=firstTab();render()}\n try{DB=await claude.use('db')}catch(e){DB=null}";
 html=html.slice(0,i)+init+html.slice(j);
 return html;
}
export default{async fetch(request,env,ctx){
 const url=new URL(request.url);
 if(url.pathname==="/nn-cloudflare.js")return new Response(adapter,{headers:{"content-type":"application/javascript; charset=utf-8","cache-control":"no-store"}});
 if(url.pathname==="/"||url.pathname==="/index.html"){
  try{const origin=await fetch("https://raw.githubusercontent.com/nathanprojectz/nestandnibble/main/public/index.html");if(!origin.ok)return new Response("Gagal memuat aplikasi.",{status:502});const html=patch(await origin.text());return new Response(html,{headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff"}})}catch(e){console.error("html_error",e);return new Response("Aplikasi sementara tidak tersedia.",{status:503})}
 }
 if(url.pathname.startsWith("/api/")){
  if(request.method==="OPTIONS")return new Response(null,{status:204,headers:cors});
  if(!env.DB)return json({error:"D1 binding DB belum dikonfigurasi"},500);
  try{
   if(url.pathname.startsWith("/api/auth/")){const out=await auth(request,url,env);if(out)return out}
   const user=await who(request,env);if(!user)return json({error:"Sesi login tidak berlaku. Silakan masuk kembali."},401);
   if(url.pathname==="/api/lock/send"&&request.method==="POST")return lockSend(request,env,user);
   if(url.pathname==="/api/lock/verify"&&request.method==="POST")return lockVerify(request,env,user);
   if(url.pathname==="/api/users"||url.pathname.startsWith("/api/users/"))return usersApi(request,url,env,user);
   if(url.pathname==="/api/records"&&request.method==="GET"){
    const c=url.searchParams.get("collection"),field=url.searchParams.get("field"),gte=url.searchParams.get("gte");if(!allowed.has(c))return json({error:"Collection tidak diizinkan"},400);
    const rows=field&&gte?await env.DB.prepare("SELECT id,data FROM records WHERE collection=? AND json_extract(data, '$.' || ?) >= ? ORDER BY updated_at").bind(c,field,gte).all():await env.DB.prepare("SELECT id,data FROM records WHERE collection=? ORDER BY updated_at").bind(c).all();
    return json((rows.results||[]).map(x=>({id:x.id,data:JSON.parse(x.data)})));
   }
   const m=url.pathname.match(/^\/api\/records\/([^/]+)\/([^/]+)$/);
   if(m){const c=decodeURIComponent(m[1]),id=decodeURIComponent(m[2]);if(!allowed.has(c)||!id||id.length>200)return json({error:"Invalid record path"},400);
    if(c==="lock"){if(request.method==="DELETE"||id.startsWith("h:"))return json({error:"Catatan kunci hanya bisa diubah oleh server"},403);if(request.method==="PUT"){const x=await request.clone().json().catch(()=>null);if(!x||x.on!==1||!LKEY.test(id))return json({error:"Kunci hanya bisa dibuka lewat kode verifikasi"},403)}}
    if(c==="cfg"&&user.role!=="owner"&&["PUT","DELETE"].includes(request.method))return json({error:"Hanya owner yang boleh mengubah pengaturan"},403);
    if(request.method==="PUT"){const data=await request.json();if(!data||typeof data!=="object"||Array.isArray(data))return json({error:"Record harus berupa object"},400);const v=JSON.stringify(data);if(v.length>900000)return json({error:"Record terlalu besar"},413);await env.DB.prepare("INSERT INTO records(collection,id,data,updated_at) VALUES(?,?,?,?) ON CONFLICT(collection,id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at").bind(c,id,v,Date.now()).run();return json({ok:true})}
    if(request.method==="DELETE"){await env.DB.prepare("DELETE FROM records WHERE collection=? AND id=?").bind(c,id).run();return new Response(null,{status:204,headers:cors})}
   }
   return json({error:"Not found"},404);
  }catch(e){console.error("api_error",e);return json({error:"Internal server error"},500)}
 }
 return new Response("Not found",{status:404});
}};
