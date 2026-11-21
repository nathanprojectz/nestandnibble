const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
const json = (data,status=200)=>new Response(JSON.stringify(data),{
  status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...cors}
});
function b64url(s){return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));}
async function verifyAccess(request,env){
  const token=request.headers.get("Cf-Access-Jwt-Assertion");
  if(!token) return false;
  const [h,p,s]=token.split(".");
  if(!h||!p||!s) return false;
  let header,claims;
  try{header=JSON.parse(new TextDecoder().decode(b64url(h)));claims=JSON.parse(new TextDecoder().decode(b64url(p)));}catch{return false;}
  if(header.alg!=="RS256"||!claims.exp||claims.exp<Date.now()/1000) return false;
  const issuer=`https://${env.ACCESS_TEAM_DOMAIN}`;
  if(claims.iss!==issuer||!Array.isArray(claims.aud)||!claims.aud.includes(env.ACCESS_AUD)) return false;
  const jwks=await fetch(`${issuer}/cdn-cgi/access/certs`).then(r=>r.json()).catch(()=>null);
  const jwk=jwks?.keys?.find(k=>k.kid===header.kid);
  if(!jwk)return false;
  try{
    const key=await crypto.subtle.importKey("jwk",jwk,{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]);
    return await crypto.subtle.verify("RSASSA-PKCS1-v1_5",key,b64url(s),new TextEncoder().encode(`${h}.${p}`));
  }catch{return false;}
}
const allowed = new Set(["orders","att","exp","stock","day","cfg","lv","slog"]);
export default {
 async fetch(request,env,ctx){
  const url=new URL(request.url);
  if(url.pathname.startsWith("/api/")){
   if(request.method==="OPTIONS")return new Response(null,{status:204,headers:cors});
   if(!await verifyAccess(request,env))return json({error:"Unauthorized — akses harus melalui Cloudflare Access"},401);
   if(!env.DB)return json({error:"D1 binding DB belum dikonfigurasi"},500);
   try{
    if(url.pathname==="/api/records"&&request.method==="GET"){
     const c=url.searchParams.get("collection"),field=url.searchParams.get("field"),gte=url.searchParams.get("gte");
     if(!allowed.has(c))return json({error:"Collection tidak diizinkan"},400);
     let rows;
     if(field&&gte) rows=await env.DB.prepare("SELECT id,data FROM records WHERE collection=? AND json_extract(data, '$.' || ?) >= ? ORDER BY updated_at").bind(c,field,gte).all();
     else rows=await env.DB.prepare("SELECT id,data FROM records WHERE collection=? ORDER BY updated_at").bind(c).all();
     return json((rows.results||[]).map(r=>({id:r.id,data:JSON.parse(r.data)})));
    }
    const m=url.pathname.match(/^\/api\/records\/([^/]+)\/([^/]+)$/);
    if(m){
     const c=decodeURIComponent(m[1]),id=decodeURIComponent(m[2]);
     if(!allowed.has(c)||!id||id.length>200)return json({error:"Invalid record path"},400);
     if(request.method==="PUT"){
      const data=await request.json();
      if(!data||typeof data!=="object"||Array.isArray(data))return json({error:"Record harus berupa object"},400);
      const serialized=JSON.stringify(data);
      if(serialized.length>900000)return json({error:"Record terlalu besar"},413);
      await env.DB.prepare("INSERT INTO records(collection,id,data,updated_at) VALUES(?,?,?,?) ON CONFLICT(collection,id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at").bind(c,id,serialized,Date.now()).run();
      return json({ok:true});
     }
     if(request.method==="DELETE"){
      await env.DB.prepare("DELETE FROM records WHERE collection=? AND id=?").bind(c,id).run();
      return new Response(null,{status:204,headers:cors});
     }
    }
    return json({error:"Not found"},404);
   }catch(e){console.error("api_error",e);return json({error:"Internal server error"},500);}
  }
  return env.ASSETS.fetch(request);
 }
};