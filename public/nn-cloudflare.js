/* Nest & Nibble — Cloudflare D1 bridge. Uses the Firestore-shaped interface expected by index.html. */
(() => {
  const API = '/api';
  const listeners = new Set();
  const cache = new Map();
  const headers = {'content-type':'application/json'};
  async function request(path, options={}) {
    const res = await fetch(API + path, {...options, headers:{...headers,...options.headers}});
    if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
    return res.status === 204 ? null : res.json();
  }
  const snap = rows => ({docs: rows.map(row => ({id:row.id,data:()=>row.data})), metadata:{fromCache:false}});
  function notify(collection, rows) {
    const value=snap(rows);
    for (const item of listeners) if(item.collection===collection) {
      try { item.callback(value); } catch(e) { console.error(e); }
    }
  }
  async function refresh(collection, field, value) {
    const qs=new URLSearchParams({collection});
    if(field){qs.set('field',field);qs.set('gte',value);}
    const rows=await request('/records?'+qs.toString());
    cache.set(collection,rows); notify(collection,rows);
  }
  function subscribe(collection, field, value, callback) {
    const item={collection,field,value,callback}; listeners.add(item);
    refresh(collection,field,value).catch(()=>{});
    const timer=setInterval(()=>refresh(collection,field,value).catch(()=>{}),5000);
    return ()=>{listeners.delete(item);clearInterval(timer);};
  }
  const db={
    doc(path) {
      const [collection,...parts]=path.split('/'); const id=parts.join('/');
      return {
        async set(data) {
          await request('/records/'+encodeURIComponent(collection)+'/'+encodeURIComponent(id),{
            method:'PUT',body:JSON.stringify(data)
          });
          const rows=await request('/records?collection='+encodeURIComponent(collection));
          cache.set(collection,rows); notify(collection,rows);
        },
        async delete() {
          await request('/records/'+encodeURIComponent(collection)+'/'+encodeURIComponent(id),{method:'DELETE'});
          const rows=await request('/records?collection='+encodeURIComponent(collection));
          cache.set(collection,rows); notify(collection,rows);
        },
        onSnapshot(callback,error) {
          let active=true;
          const run=()=>refresh(collection,null,null).then(rows=>{
            if(active) callback({exists:rows.length>0,data:()=>rows.find(x=>x.id===id)?.data, metadata:{fromCache:false}});
          }).catch(e=>{if(active&&error)error(e);});
          run();const timer=setInterval(run,5000);
          return ()=>{active=false;clearInterval(timer);};
        }
      };
    },
    collection(name) {
      return {where(field,op,value) {
        if(op!=='>=') throw new Error('Operator not supported');
        return {onSnapshot(callback,error){return subscribe(name,field,value,callback,error);}};
      }};
    }
  };
  window.claude = window.claude || {};
  window.claude.use = async name => name==='db' ? db : name==='user' ? null : null;
  window.addEventListener('online',()=>document.dispatchEvent(new Event('nn-cloud-online')));
})();