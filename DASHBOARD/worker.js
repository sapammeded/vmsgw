// ============================================================
// VMS WORKER v10 — FINAL FULL AUTH UI SYSTEM (BOSS LEVEL)
// ============================================================

export default {
async fetch(request, env){

const url = new URL(request.url);
const method = request.method;

const GLOBAL_KEY = "VMS_GLOBAL_DATA_V10";
const USER_KEY   = "VMS_USERS_V10";

const API_KEY = "VMS_MASTER_SECURE_2026";

// ================= CORS =================
const cors = {
'Access-Control-Allow-Origin': '*',
'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
'Access-Control-Allow-Headers': 'Content-Type,x-api-key,x-token',
'Content-Type': 'application/json'
};

if(method === 'OPTIONS') return new Response(null,{headers:cors});

// ================= UTILS =================
async function sha256(str){
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function generateToken(user){
    return await sha256(user + Date.now() + Math.random());
}

// ================= AUTH =================
async function checkToken(req){
    const token = req.headers.get("x-token");
    if(!token) return null;

    const raw = await env.CORP_QR_STORAGE.get("TOKEN_" + token);
    if(!raw) return null;

    const data = JSON.parse(raw);

    if(Date.now() > data.exp){
        await env.CORP_QR_STORAGE.delete("TOKEN_" + token);
        return null;
    }

    return data;
}

function isMaster(req){
    return req.headers.get("x-api-key") === API_KEY;
}

// ============================================================
// ROOT
// ============================================================
if(url.pathname === '/' && method === 'GET'){
return new Response(JSON.stringify({
status:'ok',
version:'v10',
mode:'FULL_AUTH_UI'
}),{headers:cors});
}

// ============================================================
// 🔥 ADMIN DASHBOARD (WAJIB)
// ============================================================
if(url.pathname === '/admin' && method === 'GET'){

const auth = await checkToken(request);
if(!auth) return new Response("UNAUTHORIZED",{status:401});

const raw = await env.CORP_QR_STORAGE.get(GLOBAL_KEY);
let fresh = raw ? JSON.parse(raw) : {
    visitors:{}, logs:[], version:0, devices:{}, licenses:{}
};

return new Response(JSON.stringify({
    devices: fresh.devices,
    licenses: fresh.licenses,
    visitors: fresh.visitors,
    logs: fresh.logs,
    version: fresh.version,
    ts: Date.now()
}),{headers:cors});
}

// ============================================================
// INIT (FIRST ONLY)
// ============================================================
if(url.pathname === '/init' && method === 'POST'){

if(!isMaster(request)){
    return new Response("UNAUTHORIZED",{status:401});
}

const exist = await env.CORP_QR_STORAGE.get(USER_KEY);
if(exist) return new Response("ALREADY_INIT",{status:400});

const body = await request.json();

const users = [{
    username: body.username,
    password: await sha256(body.password),
    role: "SUPER_ADMIN"
}];

await env.CORP_QR_STORAGE.put(USER_KEY, JSON.stringify(users));

return new Response(JSON.stringify({ok:true}),{headers:cors});
}

// ============================================================
// LOGIN
// ============================================================
if(url.pathname === '/login' && method === 'POST'){
try{

const body = await request.json();

const raw = await env.CORP_QR_STORAGE.get(USER_KEY);
const users = raw ? JSON.parse(raw) : [];

const hash = await sha256(body.password);

const user = users.find(u =>
    u.username === body.username &&
    u.password === hash
);

if(!user){
    return new Response(JSON.stringify({ok:false}),{status:401,headers:cors});
}

const token = await generateToken(user.username);

await env.CORP_QR_STORAGE.put("TOKEN_"+token, JSON.stringify({
    username:user.username,
    role:user.role,
    exp: Date.now()+86400000
}));

return new Response(JSON.stringify({
    ok:true,
    token,
    role:user.role
}),{headers:cors});

}catch(e){
return new Response(JSON.stringify({error:e.message}),{status:500,headers:cors});
}
}

// ============================================================
// ADD USER
// ============================================================
if(url.pathname === '/add-user' && method === 'POST'){

const auth = await checkToken(request);
if(!auth || auth.role !== "SUPER_ADMIN"){
    return new Response("FORBIDDEN",{status:403});
}

const body = await request.json();

const raw = await env.CORP_QR_STORAGE.get(USER_KEY);
let users = raw ? JSON.parse(raw) : [];

if(users.find(u=>u.username === body.username)){
    return new Response("USER_EXISTS",{status:400});
}

users.push({
    username: body.username,
    password: await sha256(body.password),
    role: body.role || "ADMIN"
});

await env.CORP_QR_STORAGE.put(USER_KEY, JSON.stringify(users));

return new Response(JSON.stringify({ok:true}),{headers:cors});
}

// ============================================================
// LIST USER
// ============================================================
if(url.pathname === '/users' && method === 'GET'){

const auth = await checkToken(request);
if(!auth) return new Response("UNAUTHORIZED",{status:401});

const raw = await env.CORP_QR_STORAGE.get(USER_KEY);
const users = raw ? JSON.parse(raw) : [];

return new Response(JSON.stringify(users.map(u=>({
    username:u.username,
    role:u.role
}))),{headers:cors});
}

// ============================================================
// DELETE USER
// ============================================================
if(url.pathname === '/delete-user' && method === 'POST'){

const auth = await checkToken(request);
if(!auth || auth.role !== "SUPER_ADMIN"){
    return new Response("FORBIDDEN",{status:403});
}

const body = await request.json();

const raw = await env.CORP_QR_STORAGE.get(USER_KEY);
let users = raw ? JSON.parse(raw) : [];

users = users.filter(u=>u.username !== body.username);

await env.CORP_QR_STORAGE.put(USER_KEY, JSON.stringify(users));

return new Response(JSON.stringify({ok:true}),{headers:cors});
}

// ============================================================
// 🔐 CHANGE PASSWORD (SELF)
// ============================================================
if(url.pathname === '/change-password' && method === 'POST'){

const auth = await checkToken(request);
if(!auth) return new Response("UNAUTHORIZED",{status:401});

const body = await request.json();

const raw = await env.CORP_QR_STORAGE.get(USER_KEY);
let users = raw ? JSON.parse(raw) : [];

const idx = users.findIndex(u=>u.username === auth.username);

if(idx === -1) return new Response("USER_NOT_FOUND",{status:404});

users[idx].password = await sha256(body.newPassword);

await env.CORP_QR_STORAGE.put(USER_KEY, JSON.stringify(users));

return new Response(JSON.stringify({ok:true}),{headers:cors});
}

// ============================================================
// 🔥 RESET PASSWORD USER (SUPER ADMIN)
// ============================================================
if(url.pathname === '/reset-password' && method === 'POST'){

const auth = await checkToken(request);
if(!auth || auth.role !== "SUPER_ADMIN"){
    return new Response("FORBIDDEN",{status:403});
}

const body = await request.json();

const raw = await env.CORP_QR_STORAGE.get(USER_KEY);
let users = raw ? JSON.parse(raw) : [];

const idx = users.findIndex(u=>u.username === body.username);

if(idx === -1) return new Response("USER_NOT_FOUND",{status:404});

users[idx].password = await sha256(body.newPassword);

await env.CORP_QR_STORAGE.put(USER_KEY, JSON.stringify(users));

return new Response(JSON.stringify({ok:true}),{headers:cors});
}

// ============================================================
// SAVE ENGINE (FIX GPS + DEVICE TRACKING)
// ============================================================
if(url.pathname === '/save' && method === 'POST'){
try{

const data = await request.json();

const raw = await env.CORP_QR_STORAGE.get(GLOBAL_KEY);
let fresh = raw ? JSON.parse(raw) : {
    visitors:{}, logs:[], version:0, devices:{}, licenses:{}
};

// ================= VISITORS =================
if(data.visitors){
Object.entries(data.visitors).forEach(([reg,v])=>{
const key = (v.site||data.site||"SITE_A") + "_" + reg;
fresh.visitors[key] = v;
});
}

// ================= LOGS =================
if(data.logs){
fresh.logs = [...data.logs,...fresh.logs].slice(0,1000);
}

// ================= DEVICE + GPS =================
if(data.anti && data.deviceId){

let dev = fresh.devices[data.deviceId] || {
    deviceId: data.deviceId,
    license: data.anti.license || "UNKNOWN",
    status: "ACTIVE",
    flags: [],
    lastLocation: null,
    lastUpdate: 0
};

// GPS VALID
if(data.anti.lat && data.anti.lng){

if(dev.lastLocation){
const dx = data.anti.lat - dev.lastLocation.lat;
const dy = data.anti.lng - dev.lastLocation.lng;
const dist = Math.sqrt(dx*dx + dy*dy) * 111000;
const dt = (Date.now() - dev.lastLocation.ts)/1000;
const speed = dist / (dt || 1);

if(speed > 80){
dev.flags.push("SPEED_HACK");
}
}

dev.lastLocation = {
lat: data.anti.lat,
lng: data.anti.lng,
ts: Date.now()
};

}

// AUTO STATUS
if(dev.flags.length > 5){
dev.status = "SUSPICIOUS";
}

// SAVE
dev.lastUpdate = Date.now();
fresh.devices[data.deviceId] = dev;

}

// ================= SAVE =================
fresh.version++;
fresh.lastSync = Date.now();

await env.CORP_QR_STORAGE.put(GLOBAL_KEY, JSON.stringify(fresh));

return new Response(JSON.stringify({ok:true}),{headers:cors});

}catch(e){
return new Response(JSON.stringify({error:e.message}),{status:500,headers:cors});
}
}

// ============================================================
return new Response(JSON.stringify({error:'not found'}),{status:404,headers:cors});

}
};