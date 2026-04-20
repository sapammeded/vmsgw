export default {
async fetch(request, env) {

const url = new URL(request.url);
const m = request.method;

const G="VMS_GLOBAL_DATA_V11";
const U="VMS_USERS_V11";
const L="VMS_LICENSES_V11";

const H={
 'Access-Control-Allow-Origin':'*',
 'Access-Control-Allow-Methods':'GET,POST,OPTIONS',
 'Access-Control-Allow-Headers':'Content-Type,x-api-key,x-token',
 'Content-Type':'application/json'
};

if(m==='OPTIONS') return new Response(null,{headers:H});

const res=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:H});
const err=(m,s=500)=>res({error:m},s);

const kv=async()=>{
 if(!env.CORP_QR_STORAGE) throw "KV_NOT_BOUND";
 return env.CORP_QR_STORAGE;
};

const sha256 = async (str)=>{
 const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
 return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
};

const verify=async()=>{
 const t=request.headers.get("x-token");
 if(!t) return null;
 try{
  const k=await kv();
  const raw=await k.get("TOKEN_"+t);
  if(!raw) return null;
  const d=JSON.parse(raw);
  if(Date.now()>d.exp){
   await k.delete("TOKEN_"+t);
   return null;
  }
  return d;
 }catch{return null}
};

// ================= ROOT =================
if(url.pathname==='/' && m==='GET'){
 return res({status:'ok',version:'v11.5'});
}

// ================= FORCE INIT =================
if(url.pathname==='/force-init' && m==='POST'){
 try{
  const k=await kv();

  let raw = await k.get(U);
  let users = [];

  if(raw){
   try{ users = JSON.parse(raw); }
   catch{ users = []; }
  }

  if(users.length===0){
   users.push({
    username:"admin",
    password:await sha256("123456"),
    role:"SUPER_ADMIN",
    created_at:Date.now()
   });

   await k.put(U,JSON.stringify(users));
   return res({ok:true,msg:"INIT_OK"});
  }

  return res({ok:false,msg:"EXIST"});
 }catch(e){
  return res({error:"FORCE_INIT_ERROR",message:e.toString()},500);
 }
}

// ================= LOGIN =================
if(url.pathname==='/login' && m==='POST'){
 try{
  const {username,password}=await request.json();
  if(!username||!password) return err("INVALID_INPUT",400);

  const k=await kv();
  const users=JSON.parse(await k.get(U)||"[]");

  const hash=await sha256(password);
  const u=users.find(x=>x.username===username && x.password===hash);

  if(!u) return err("INVALID_CREDENTIAL",401);

  const token=await sha256(username+Date.now()+Math.random());
  const exp=Date.now()+86400000;

  await k.put("TOKEN_"+token,JSON.stringify({
   username:u.username,
   role:u.role,
   exp
  }));

  return res({ok:true,token,role:u.role,expires:exp});
 }catch(e){ return err(e); }
}

// ================= CREATE LICENSE =================
if(url.pathname==='/create-license' && m==='POST'){
 const a=await verify();
 if(!a||a.role!=="SUPER_ADMIN") return err("FORBIDDEN",403);

 const {company,price}=await request.json();
 if(!company) return err("COMPANY_REQUIRED",400);

 const k=await kv();
 let lic=JSON.parse(await k.get(L)||"{}");

 const key="LIC-"+company.replace(/\s/g,'').toUpperCase().slice(0,5)+"-"+Math.random().toString(36).slice(2,7).toUpperCase();

 lic[key]={
  key,
  company,
  status:"ACTIVE",
  devices:[],
  totalDevices:0,
  pricePerDevice:price||50000,
  createdAt:Date.now(),
  billing:null
 };

 await k.put(L,JSON.stringify(lic));
 return res({ok:true,license:lic[key]});
}

// ================= GET LICENSE =================
if(url.pathname==='/licenses'){
 const a=await verify();
 if(!a) return err("UNAUTHORIZED",401);

 const k=await kv();
 return res(JSON.parse(await k.get(L)||"{}"));
}

// ================= APPROVE DEVICE =================
if(url.pathname==='/approve-device' && m==='POST'){
 const a=await verify();
 if(!a||a.role!=="SUPER_ADMIN") return err("FORBIDDEN",403);

 const {deviceId}=await request.json();
 const k=await kv();
 let f=JSON.parse(await k.get(G)||'{"devices":{}}');

 if(!f.devices[deviceId]) return err("NOT_FOUND",404);

 f.devices[deviceId].status="ACTIVE";
 f.devices[deviceId].approvedAt=Date.now();

 await k.put(G,JSON.stringify(f));
 return res({ok:true});
}

// ================= BILLING INIT =================
if(url.pathname==='/init-billing' && m==='POST'){
 const a=await verify();
 if(!a) return err("FORBIDDEN",403);

 const {licenseKey,days}=await request.json();

 const k=await kv();
 let lic=JSON.parse(await k.get(L)||"{}");

 if(!lic[licenseKey]) return err("NOT_FOUND",404);

 lic[licenseKey].billing={
  start:Date.now(),
  end:Date.now()+(days||30)*86400000,
  status:"ACTIVE",
  lastInvoice:null
 };

 await k.put(L,JSON.stringify(lic));
 return res({ok:true});
}

// ================= GENERATE INVOICE =================
if(url.pathname==='/generate-invoice' && m==='POST'){
 const a=await verify();
 if(!a) return err("UNAUTHORIZED",401);

 const {licenseKey}=await request.json();

 const k=await kv();
 let all=JSON.parse(await k.get(L)||"{}");
 const lic=all[licenseKey];

 if(!lic) return err("NOT_FOUND",404);

 const total=lic.devices.length*(lic.pricePerDevice||50000);

 const invoice={
  id:"INV-"+Date.now(),
  company:lic.company,
  devices:lic.devices.length,
  price:lic.pricePerDevice,
  total,
  status:"UNPAID",
  createdAt:Date.now()
 };

 lic.billing.lastInvoice=invoice;

 await k.put(L,JSON.stringify(all));
 return res({ok:true,invoice});
}

// ================= PAY =================
if(url.pathname==='/pay-invoice' && m==='POST'){
 const a=await verify();
 if(!a) return err("UNAUTHORIZED",401);

 const {licenseKey}=await request.json();

 const k=await kv();
 let all=JSON.parse(await k.get(L)||"{}");

 const lic=all[licenseKey];
 if(!lic||!lic.billing) return err("NOT_READY",400);

 lic.billing.start=Date.now();
 lic.billing.end=Date.now()+30*86400000;
 lic.billing.status="ACTIVE";

 await k.put(L,JSON.stringify(all));
 return res({ok:true});
}

// ================= ADMIN =================
if(url.pathname==='/admin'){
 const a=await verify();
 if(!a) return err("UNAUTHORIZED",401);

 const k=await kv();

 return res({
  ...(JSON.parse(await k.get(G)||'{"devices":{}}')),
  licenses:JSON.parse(await k.get(L)||"{}"),
  ts:Date.now()
 });
}

// ================= SAVE =================
if(url.pathname==='/save' && m==='POST'){
 try{
  const data=await request.json();
  const k=await kv();

  let f=JSON.parse(await k.get(G)||'{"devices":{}}');
  let lic=JSON.parse(await k.get(L)||"{}");

  const key=data.anti?.license;
  if(!key||!lic[key]) return err("INVALID_LICENSE",403);

  if(data.anti && data.deviceId){

   let d=f.devices[data.deviceId]||{
    deviceId:data.deviceId,
    license:key,
    status:"PENDING",
    flags:[],
    lastLocation:null,
    lastUpdate:0,
    meta:{}
   };

   if(data.meta) d.meta=data.meta;

   if(!lic[key].devices.includes(data.deviceId)){
    lic[key].devices.push(data.deviceId);
    lic[key].totalDevices=lic[key].devices.length;
   }

   if(data.anti.lat && data.anti.lng){
    if(d.lastLocation){
     const dx=data.anti.lat-d.lastLocation.lat;
     const dy=data.anti.lng-d.lastLocation.lng;
     const dist=Math.sqrt(dx*dx+dy*dy)*111000;
     const dt=(Date.now()-d.lastLocation.ts)/1000;
     if(dist/(dt||1)>80){
      d.flags.push({type:"SPEED_HACK",time:Date.now()});
     }
    }
    d.lastLocation={lat:data.anti.lat,lng:data.anti.lng,ts:Date.now()};
   }

   if(Array.isArray(data.anti.flags)){
    d.flags=[...d.flags,...data.anti.flags].slice(-50);
   }

   if(d.status!=="BANNED"){
    d.status=d.flags.length>5?"SUSPICIOUS":d.flags.length?"WARNING":d.status;
   }

   d.lastUpdate=Date.now();
   f.devices[data.deviceId]=d;
  }

  // AUTO BILLING
  Object.values(lic).forEach(l=>{
   if(!l.billing) return;
   const r=l.billing.end-Date.now();

   if(r<3*86400000 && r>0) l.billing.status="WARNING";

   if(r<=0){
    l.billing.status="EXPIRED";
    l.devices.forEach(id=>{
     if(f.devices[id]) f.devices[id].status="SUSPENDED";
    });
   }
  });

  f.version=(f.version||0)+1;
  f.lastSync=Date.now();

  await k.put(G,JSON.stringify(f));
  await k.put(L,JSON.stringify(lic));

  return res({ok:true,version:f.version});

 }catch(e){ return err(e); }
}

// ================= BAN / UNBAN / RESET =================
if(['/ban','/unban','/reset-device'].includes(url.pathname)){
 const a=await verify();
 if(!a) return err("UNAUTHORIZED",401);

 const body=await request.json();
 const k=await kv();
 let f=JSON.parse(await k.get(G)||'{"devices":{}}');

 Object.keys(f.devices).forEach(id=>{
  const d=f.devices[id];

  if(url.pathname==='/ban' && d.license===body.license){
   d.status="BANNED";
   d.bannedAt=Date.now();
  }

  if(url.pathname==='/unban' && d.license===body.license){
   d.status="ACTIVE";
   delete d.bannedAt;
  }

  if(url.pathname==='/reset-device' && id===body.deviceId){
   f.devices[id]={
    deviceId:id,
    license:d.license,
    status:"ACTIVE",
    flags:[],
    lastLocation:null,
    lastUpdate:Date.now(),
    meta:d.meta||{}
   };
  }
 });

 await k.put(G,JSON.stringify(f));
 return res({ok:true});
}

// ================= FALLBACK =================
return err("NOT_FOUND",404);

}
};