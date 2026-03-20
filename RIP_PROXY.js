;(async function RIP_PROXY_MAIN() {
// ================================================================
//  RIP PROXY — Anti-Cheat Scanner para Free Fire iOS
//  code by tizi · UNKNOWN Security Team · v3.2
// ================================================================
//
//  CORRECCIONES v3.2:
//   · TLS probe: solo cuenta proxy headers reales (no HSTS/latencia)
//   · IPs/ASN: sección informativa — NO cuenta hacia el veredicto
//   · Cloudflare (AS13335): nunca flaggeado por hosting
//   · 154.223.134.x y otros servidores FF/Cloudflare en allowlist
//
//  VERIFICACIÓN EN 7 PASADAS:
//   [1] Dominio raíz en lista de confianza        → descartar
//   [2] IP en lista de falsos positivos conocidos → descartar
//   [3] Consulta IP-API (ASN, hosting, rDNS)
//   [4] ISP legítimo de FF + solo llamado por FF  → descartar
//   [5] Clasificación ASN / hosting / palabras
//   [6] Verificación rDNS y org/ISP
//   [7] Probe HTTP (banners) en candidatos finales
//
//  VEREDICTO — solo cuenta señales CRÍTICAS:
//   · Infraestructura cheat confirmada
//   · Apps proxy/jailbreak/sideload
//   · Dominios cheat en tráfico de FF
//   · Proxy Login (dominios FF en apps ajenas)
//   · Headers de proxy reales en TLS probe
//   · Certificados raíz instalados
//   Las IPs/ASN sospechosas son SOLO informativas.
// ================================================================

const VERSION         = "3.2"
const LATENCIA_UMBRAL = 600
const IP_FIELDS       = "status,country,city,isp,org,hosting,proxy,query,reverse,as"

// ────────────────────────────────────────────────────────────────
//  PASADA 1 — DOMINIOS RAÍZ SIEMPRE CONFIABLES
// ────────────────────────────────────────────────────────────────

const DOMINIOS_RAIZ_CONFIANZA = new Set([
  "apple.com","icloud.com","mzstatic.com","apple-dns.net","aaplimg.com",
  "cdn-apple.com","apple-mapkit.com","icloud-content.com",
  "google.com","googleapis.com","gstatic.com","googleusercontent.com",
  "google.com.ar","google.com.br","googlevideo.com","ytimg.com",
  "youtube.com","ggpht.com","gvt1.com","gvt2.com","gvt3.com",
  "facebook.com","fbcdn.net","fb.com","instagram.com","whatsapp.com","whatsapp.net",
  "meli.com","mercadopago.com","mercadolibre.com","mercadolibre.com.ar",
  "mercadolibre.com.br","mlstatic.com",
  "amazon.com","amazonaws.com","amazon.com.br","amazon.com.ar",
  "microsoft.com","azure.com","msftconnecttest.com","live.com","outlook.com",
  "akamai.net","akamaized.net","akamaihd.net","cloudfront.net","fastly.net",
  "edgekey.net","edgesuite.net","akadns.net",
  "digicert.com","geotrust.com","verisign.com","comodo.com",
  "letsencrypt.org","symantec.com","entrust.net",
  "tiktok.com","bytedance.com","twitter.com","x.com","t.co",
  "spotify.com","scdn.co","netflix.com","nflxvideo.net",
  "cloudflare.com","cloudflare-dns.com",
  // Garena / Free Fire
  "garena.com","garenagames.com","freefiremobile.com","freefireth.com",
  "ggblueshark.com","ggpolarbear.com","ggwhitehawk.com","ggraven.com",
  "ggvenom.com","ggflamingo.com","garenanow.com","garena.tw","garena.vn",
  "appsflyer.com","adjust.com","amplitude.com","crashlytics.com",
  "firebase.com","firebaseio.com",
])

// ────────────────────────────────────────────────────────────────
//  PASADA 2 — IPs CONOCIDAS COMO FALSOS POSITIVOS
// ────────────────────────────────────────────────────────────────

const IPS_FALSOS_POSITIVOS = new Set([
  // Garena LatAm confirmados
  "104.29.152.79","104.29.152.107","92.223.118.254","23.221.214.168",
  "23.192.36.217","54.69.69.125","104.29.152.189","104.29.137.146",
  "104.29.155.56","104.29.137.203","104.29.155.129","104.29.137.125",
  "104.29.158.97","104.29.152.95","104.29.153.53","104.29.159.185",
  "104.29.157.123","104.29.152.27","104.29.157.107","104.29.137.16",
  "104.29.152.164","104.29.137.53","104.29.135.227","104.29.158.139",
  "104.29.152.157","104.29.156.174","104.29.156.24","104.29.154.91",
  "104.29.155.27","104.29.156.120","104.29.137.112",
  // Cloudflare CDN usados por FF (Brasil/LatAm) — confirmados legítimos
  "154.223.134.4","154.223.134.7","154.223.134.8","154.223.134.10",
  "154.223.134.11","154.223.134.12","154.223.134.13","154.223.134.14",
  // Google DNS público
  "8.8.8.8","8.8.4.4","4.4.4.4",
  // Zenlayer — servidores FF en Argentina (98.98.10.x)
  "98.98.10.66","98.98.10.74","98.98.10.122","98.98.10.138",
  // Servidores FF confirmados (143.92.x y 23.251.x)
  "143.92.125.125","143.92.125.134","143.92.125.147","143.92.125.191",
  "143.92.126.103","23.251.41.39","23.251.41.97","23.251.41.199",
  "23.251.37.122","23.251.37.200",
  // Google LLC servidores de FF (142.x y 108.x)
  "142.251.128.46","142.251.0.188","108.177.123.188","74.125.250.129",
])

// ────────────────────────────────────────────────────────────────
//  PASADA 4 — ISPs LEGÍTIMOS DE FREE FIRE
// ────────────────────────────────────────────────────────────────

const ISP_LEGITIMOS_FF = new Set([
  "zenlayer inc",
  "amazon.com, inc.",
  "amazon technologies inc.",
  "google llc",
  "cloudflare, inc.",
  "akamai technologies",
  "level 3 parent, llc",
  "tencent cloud computing",
  "garena online",
  "sea limited",
])

// ────────────────────────────────────────────────────────────────
//  BASE DE DATOS DE DETECCIÓN
// ────────────────────────────────────────────────────────────────

const HOSTING_KEYWORDS = [
  "hostinger","hstgr","locaweb","kinghost","umbler","hostgator","uol host","uolhost",
  "redehost","weblink","brasileirohost","br.host","dialhost","serverspace","ibrcom",
  "masterweb","superdomin","plankton","vps.br","digitalocean","linode",
  "vultr","hetzner","ovh","ovhcloud","contabo","ionos","godaddy","siteground",
  "cloudways","hstgr.cloud","srv.umbler","kinghost.net","locaweb.com.br",
  "choopa","psychz","m247","serverius","frantech","buyvm","sharktech","quadranet",
  "nexeon","servermania","hostwinds","racknerd","dedipath","spartanhost","cloudie",
  "tsohost","wavenet","fasthosts","multacom","telus","fdcservers","fdc servers",
  "leaseweb","colocation america","b2 net","b2net","path.net","datacamp",
  "tzulo","coresite","vietnix",
]

const ASN_SOSPECHOSOS = {
  "AS35916": "Multacom Corporation",
  "AS47583": "Hostinger International",
  "AS60781": "LeaseWeb Netherlands",
  "AS28753": "LeaseWeb Deutschland",
  "AS16276": "OVH SAS",
  "AS14061": "DigitalOcean",
  "AS20473": "Choopa / Vultr",
  "AS8100":  "QuadraNet",
  "AS40065": "FDC Servers",
  "AS53667": "FranTech Solutions",
  "AS395954":"Leaseweb USA",
  "AS209":   "CenturyLink / Lumen",
  "AS7203":  "Sharktech",
  // AS13335 (Cloudflare) fue removido — demasiados falsos positivos
}

const RDNS_PATRONES = [
  "hstgr.cloud","staticip","srv.","vps.","cloud.","host.","server.",
  "dedicated.",".kinghost.net",".locaweb.com.br",".umbler.net",
  ".hostgator.com.br",".digitalocean.com",".vultr.com",".linode.com",
  ".hetzner.com",".contabo.net",
]

const APPS_CHEAT = {
  "com.touchingapp.potatsolite":      "PotatsoLite — proxy iOS MITM",
  "com.touchingapp.potatso":          "Potatso — proxy iOS",
  "com.monite.proxyff":               "ProxyFF — proxy iOS cheat",
  "com.nssurge.inc.surge-ios":        "Surge — proxy MITM iOS",
  "com.luo.quantumultx":              "Quantumult X — proxy iOS",
  "group.com.luo.quantumult":         "Quantumult — proxy iOS",
  "com.shadowrocket.Shadowrocket":    "Shadowrocket — proxy iOS",
  "com.liguangming.Shadowrocket":     "Shadowrocket — proxy iOS",
  "com.github.shadowsocks":           "Shadowsocks",
  "com.netease.trojan":               "Trojan proxy",
  "com.hiddify.app":                  "Hiddify — proxy",
  "com.karing.app":                   "Karing — proxy",
  "com.metacubex.ClashX":             "ClashX — proxy",
  "com.ssrss.Ssrss":                  "SSR proxy iOS",
  "com.adguard.ios.AdguardPro":       "AdGuard Pro — proxy MITM",
  "com.privateinternetaccess.ios":    "PIA VPN",
  "com.cloudflare.1dot1dot1dot1":     "Cloudflare WARP — proxy",
  "com.opa334.dopamine":              "Dopamine — Jailbreak",
  "org.coolstar.sileo":               "Sileo — JB package manager",
  "org.coolstar.odyssey":             "Odyssey — Jailbreak",
  "com.electrateam.unc0ver":          "unc0ver — Jailbreak",
  "com.tihmstar.checkra1n":           "checkra1n — Jailbreak",
  "org.taurine.jailbreak":            "Taurine — Jailbreak",
  "xyz.palera1n.palera1n":            "palera1n — Jailbreak",
  "com.opa334.TrollStore":            "TrollStore — sideload sin JB",
  "com.opa334.TrollStoreHelper":      "TrollStoreHelper",
  "com.opa334.trolldecrypt":          "TrollDecrypt",
  "com.opa334.trollfools":            "TrollFools — inyector de tweaks",
  "xyz.willy.Zebra":                  "Zebra — JB package manager",
  "com.cydia.Cydia":                  "Cydia — JB package manager",
  "com.rileytestut.AltStore":         "AltStore — sideload",
  "com.altstore.altstoreclassic":     "AltStore Classic",
  "com.sideloadly.sideloadly":        "Sideloadly — sideload",
  "com.esign.ios":                    "ESign — instalador IPAs",
  "com.esign.esign":                  "ESign — instalador IPAs",
  "com.iosgods.iosgods":              "iOSGods — tienda de cheats",
  "com.gbox.pubg":                    "GBox — mod de juegos",
  "com.tigisoftware.Filza":           "Filza — gestor root",
  "com.tigisoftware.FilzaFree":       "Filza Free — gestor root",
  "app.ish.iSH":                      "iSH — shell Linux en iOS",
  "com.apple.dt.Xcode":               "Xcode — IDE (sospechoso en juego)",
  "com.apple.TestFlight":             "TestFlight — beta sideload",
}

const TLD_SOSPECHOSOS = [
  ".site",".store",".netlify.app",".netlify",".xyz",".pw",".top",".click",
  ".bid",".win",".stream",".download",".icu",".gq",".cf",".ml",".ga",
  ".tk",".monster",".fun",".rest",".bar",".lol",
]

const PALABRAS_SOSPECHOSAS = [
  "proxy","cheat","hack","bypass","mitm","inject","spoof","crack",
  "exploit","payload","tunnel","socks","relay","forward","gate",
]

const DOMINIOS_LOGIN_FF = new Set([
  "version.ffmax.purplevioleto.com","version.ggwhitehawk.com",
  "loginbp.ggpolarbear.com","gin.freefiremobile.com",
  "100067.connect.garena.com","100067.msdk.garena.com",
  "client.us.freefiremobile.com","client.sea.freefiremobile.com",
  "sacnetwork.ggblueshark.com","sacevent.ggblueshark.com",
])

const FF_APPS_LEGITIMAS = new Set(["com.dts.freefireth","com.dts.freefiremax"])

const BUNDLES_IGNORADOS = new Set([
  "com.hammerandchisel.discord",
  "com.zhiliaoapp.musically",
  "dk.simonbs.Scriptable",
  "com.apple.mobileSafari",
  "com.apple.AppStore",
])

const INFRA_CHEAT = {
  "46.202.145.85":                    "Fatality Cheats — servidor confirmado",
  "fatalitycheats.xyz":               "Fatality Cheats — dominio confirmado",
  "anubisw.online":                   "Servidor de cheat confirmado — Free Fire",
  "api.baontq.xyz":                   "API de cheat confirmado — Free Fire",
  "authtool.app":                     "Plataforma de distribución de cheats iOS",
  "ipa.authtool.app":                 "Servidor IPA de cheats iOS",
  "proxy.builders":                   "Proxy Team — cheat iOS confirmado",
  "filespace.es":                     "Distribución de cheats iOS",
  "version.ffmax.purplevioleto.com":  "FF MAX modificado — cheat",
  "version.ggwhitehawk.com":          "White Hawk cheat — confirmado",
  "loginbp.ggpolarbear.com":          "Polar Bear cheat — confirmado",
}

const ENDPOINTS_GARENA = [
  { url: "https://gin.freefiremobile.com",        nombre: "FF Login"       },
  { url: "https://client.sea.freefiremobile.com", nombre: "FF Client SEA"  },
  { url: "https://client.us.freefiremobile.com",  nombre: "FF Client US"   },
  { url: "https://sacnetwork.ggblueshark.com",     nombre: "Garena Network" },
]

// Solo estos headers confirman un proxy real — HSTS y latencia son informativos
const HEADERS_PROXY_REALES = [
  "via","x-forwarded-for","x-forwarded-proto","x-real-ip",
  "proxy-connection","x-mitm-proxy","x-proxy-id","forwarded",
]

const DOMINIOS_LEGITIMOS_FF = new Set([
  "garena.com","garena.com.sg","garena.tw","garena.vn","garenagames.com",
  "freefiremobile.com","freefireth.com","ggblueshark.com","ggpolarbear.com",
  "ggwhitehawk.com","ggraven.com","ggvenom.com","ggflamingo.com","garenanow.com",
  "msdk.garena.com","connect.garena.com","sdk.garena.com","store.garena.com",
  "akamaized.net","akamai.net","akamaistream.net","cloudfront.net","fastly.net",
  "apple.com","icloud.com","mzstatic.com","crashlytics.com","firebase.com",
  "firebaseio.com","googleapis.com","gstatic.com","amplitude.com",
  "appsflyer.com","adjust.com","facebook.com","fbcdn.net",
  "google.com","googleusercontent.com","gvt1.com",
])

// ────────────────────────────────────────────────────────────────
//  UTILIDADES
// ────────────────────────────────────────────────────────────────

function raizDominio(d) {
  let p = d.toLowerCase().replace(/^www\./, "").split(".")
  return p.length >= 2 ? p.slice(-2).join(".") : d.toLowerCase()
}

function esDominioRaizConfiable(d) {
  d = d.toLowerCase().replace(/^www\./, "")
  if (DOMINIOS_RAIZ_CONFIANZA.has(raizDominio(d))) return true
  for (let c of DOMINIOS_RAIZ_CONFIANZA) { if (d.endsWith("."+c) || d === c) return true }
  return false
}

function esDominioLegitFF(d) {
  d = d.toLowerCase().replace(/^www\./, "")
  if (DOMINIOS_LEGITIMOS_FF.has(d)) return true
  for (let l of DOMINIOS_LEGITIMOS_FF) { if (d.endsWith("."+l) || d === l) return true }
  return false
}

function formatMs(ms) { return ms < 1000 ? ms+"ms" : (ms/1000).toFixed(1)+"s" }

function formatFecha(d) {
  if (!d) return "—"
  return d.toLocaleString("es-AR", { day:"2-digit", month:"2-digit", year:"numeric", hour:"2-digit", minute:"2-digit" })
}

async function leerArchivo(r) {
  try { return FileManager.local().readString(r) } catch(e) {}
  try { return FileManager.iCloud().readString(r) } catch(e) {}
  return null
}

function parsearNdjson(c) {
  let t = c.trim()
  if (t.startsWith("[")) { try { return JSON.parse(t) } catch(e) {} }
  return t.split("\n").map(l=>l.trim()).filter(l=>l.length>0).map(l=>{try{return JSON.parse(l)}catch(e){return null}}).filter(Boolean)
}

function parsearIps(c) {
  try {
    let lineas = c.trim().split("\n").map(l=>l.trim()).filter(Boolean)
    let header=null, entries=[]
    try { header  = JSON.parse(lineas.find(l=>l.startsWith("{"))||"null") } catch(e) {}
    try { entries = JSON.parse(lineas.find(l=>l.startsWith("["))||"[]")   } catch(e) {}
    return { header, entries }
  } catch(e) { return { header:null, entries:[] } }
}

function esReportePrivacidad(c) { let s=c.trim().slice(0,500); return s.includes("networkActivity")||s.includes("bundleID")||s.includes("timeStamp") }
function esArchivoUsage(c)      { let s=c.trim().slice(0,300); return s.includes("xp_amp_app_usage")||s.includes("roots_installed")||s.includes("usageClientId") }
function esperar(ms) { return new Promise(r=>Timer.schedule(ms,false,r)) }

// ────────────────────────────────────────────────────────────────
//  VALIDACIÓN DEL REPORTE
// ────────────────────────────────────────────────────────────────

function validarReporte(entries) {
  if (!entries||entries.length===0) return { ok:false, motivo:"El archivo está vacío o no tiene entradas válidas." }
  if (!entries.some(e=>e.type==="networkActivity"||e.type==="access")) return { ok:false, motivo:"No se encontraron entradas de red. Este archivo no parece ser un App Privacy Report válido." }
  if (!entries.some(e=>e.bundleID||(e.accessor&&e.accessor.identifier))) return { ok:false, motivo:"No se encontró ningún bundleID. El archivo puede estar corrupto." }
  if (!entries.some(e=>e.timeStamp)) return { ok:false, motivo:"No se encontró ningún timestamp. El archivo puede estar corrupto." }
  let ts=entries.map(e=>e.timeStamp).filter(Boolean)
  let valid=ts.filter(t=>{ let y=parseInt(t.slice(0,4)); return y>=2020&&y<=2030 })
  if (valid.length < ts.length*0.5) return { ok:false, motivo:"Los timestamps están fuera del rango esperado. El archivo puede haber sido manipulado." }
  return { ok:true }
}

// ────────────────────────────────────────────────────────────────
//  PROBE TLS EN VIVO
//  IMPORTANTE: solo marca como sospechoso si detecta HEADERS DE
//  PROXY REALES. Latencia y HSTS son SOLO informativos — no
//  cuentan hacia el veredicto para evitar falsos positivos.
// ────────────────────────────────────────────────────────────────

async function probeTLS(ep) {
  let r = { nombre:ep.nombre, alcanzable:false, latencia:null, headersProxy:[], sospechoso:false, motivo:null, info:[] }
  try {
    let req = new Request(ep.url)
    req.method = "HEAD"; req.timeoutInterval = 8
    req.headers = { "User-Agent":"FreeFire/1.0 CFNetwork/1492.0.1 Darwin/23.0.0", "Accept":"*/*" }
    let t0=Date.now(); try { await req.load() } catch(e) {}
    r.latencia=Date.now()-t0; r.alcanzable=true
    let hdrs=(req.response&&req.response.headers)?req.response.headers:{}
    let hsts=hdrs["strict-transport-security"]||hdrs["Strict-Transport-Security"]||""
    let server=hdrs["server"]||hdrs["Server"]||""

    // Solo headers de proxy reales disparan la alerta
    for (let h of HEADERS_PROXY_REALES) {
      if (Object.keys(hdrs).some(k=>k.toLowerCase()===h)) r.headersProxy.push(h)
    }

    // Informativo adicional (no cuenta hacia veredicto)
    if (r.latencia > LATENCIA_UMBRAL) r.info.push("Latencia: "+formatMs(r.latencia)+" (puede ser normal en mobile)")
    if (!hsts) r.info.push("HSTS no enviado por este endpoint")
    if (server) { let sv=server.toLowerCase(); if (sv.includes("mitm")||sv.includes("proxy")) r.headersProxy.push("server:"+server) }

    // Sospechoso SOLO si hay headers de proxy reales
    if (r.headersProxy.length > 0) {
      r.sospechoso = true
      r.motivo = "Headers de proxy inyectados: " + r.headersProxy.join(", ")
    }
  } catch(e) { r.motivo="Endpoint no alcanzable" }
  return r
}

// ────────────────────────────────────────────────────────────────
//  IP-API BATCH
// ────────────────────────────────────────────────────────────────

async function consultarIPs(targets) {
  try {
    let req=new Request(`http://ip-api.com/batch?fields=${IP_FIELDS}`)
    req.method="POST"; req.body=Data.fromString(JSON.stringify(targets))
    req.headers={"Content-Type":"application/json"}; req.timeoutInterval=15
    let res=await req.loadJSON(); return Array.isArray(res)?res:[]
  } catch(e) { return [] }
}

// ────────────────────────────────────────────────────────────────
//  CLASIFICACIÓN EN 7 PASADAS
// ────────────────────────────────────────────────────────────────

function clasificarDominio(info, dominio, bundlesSolicitantes) {
  // Pasada 1 — raíz confiable
  if (esDominioRaizConfiable(dominio)) return { nivel:null, motivos:[] }

  let motivos=[], nivel=null, domLow=dominio.toLowerCase()

  // Pasada 2 — TLD sospechoso
  for (let tld of TLD_SOSPECHOSOS) {
    if (domLow.endsWith(tld)||domLow.includes(tld+"/")) { nivel="ALTO"; motivos.push(`TLD sospechoso: "${tld}"`); break }
  }

  // Pasada 3 — palabra sospechosa EXACTA en primer segmento
  if (!nivel) {
    let seg = domLow.split(".")[0]
    for (let w of PALABRAS_SOSPECHOSAS) {
      if (seg===w) { nivel="ALTO"; motivos.push(`Dominio sospechoso: "${w}"`); break }
    }
  }

  if (!info) return { nivel, motivos }

  // Pasada 4 — ISP legítimo de FF + solo llamado por apps FF
  if (info.status==="success") {
    let ispLow=(info.isp||"").toLowerCase()
    let soloFF=bundlesSolicitantes&&bundlesSolicitantes.size>0&&[...bundlesSolicitantes].every(b=>FF_APPS_LEGITIMAS.has(b)||BUNDLES_IGNORADOS.has(b))
    let ispLegitimo=[...ISP_LEGITIMOS_FF].some(isp=>ispLow.includes(isp.toLowerCase()))
    if (soloFF&&ispLegitimo) return { nivel:null, motivos:[] }
  }

  if (info.status!=="success") return { nivel, motivos }

  let asn=(info.as||"").split(" ")[0].toUpperCase()
  let esCloudflare = asn==="AS13335"

  // Pasada 5 — Hosting/proxy/ASN
  // Cloudflare NUNCA se flagea por hosting — tiene hosting:true en todos sus IPs
  if (info.hosting && !esCloudflare) { nivel="ALTO"; motivos.push(`Hosting/VPS — ISP: ${info.isp}`) }
  if (info.proxy)                    { nivel="ALTO"; motivos.push("Proxy o VPN detectado") }

  if (ASN_SOSPECHOSOS[asn]) {
    nivel="ALTO"; motivos.push(`ASN asociado a cheats: ${asn} — ${ASN_SOSPECHOSOS[asn]}`)
  }

  // Pasada 6 — rDNS
  let rdns=(info.reverse||"").toLowerCase()
  if (rdns) {
    for (let p of RDNS_PATRONES) { if (rdns.includes(p)) { nivel=nivel||"ALTO"; motivos.push(`rDNS de servidor: ${info.reverse}`); break } }
    if (rdns.match(/^srv\d+\.hstgr\.cloud$/)) { nivel="ALTO"; motivos.push(`VPS Hostinger: ${info.reverse}`) }
  } else if (info.hosting && !esCloudflare) {
    motivos.push("Sin rDNS — típico de VPS proxy")
  }

  let orgStr=((info.org||"")+" "+(info.isp||"")+" "+(info.as||"")).toLowerCase()
  for (let kw of HOSTING_KEYWORDS) {
    if (orgStr.includes(kw)) { nivel=nivel||"MEDIO"; motivos.push(`ISP hosting/proxy: ${kw}`); break }
  }

  return { nivel, motivos }
}

// ────────────────────────────────────────────────────────────────
//  PASADA 7 — PROBE HTTP
// ────────────────────────────────────────────────────────────────

async function probeHTTP(dominio) {
  let seguros=["apple.com","icloud.com","google.com","googleapis.com","gstatic.com","amazon.com","microsoft.com","akamai","cloudfront","fastly","edgekey","aaplimg","facebook.com","fbcdn.net","instagram.com","meli.com","cloudflare.com"]
  if (seguros.some(s=>dominio.toLowerCase().includes(s))) return null
  let res={estado:null,banner:null,activo:false,sospechoso:false}
  for (let esquema of ["https","http"]) {
    try {
      let req=new Request(`${esquema}://${dominio}`)
      req.timeoutInterval=6; req.allowInsecureRequest=true
      let cuerpo=await req.loadString(); res.activo=true
      let resp=req.response||{}; res.estado=resp.statusCode||0
      let hdrs=resp.headers||{}
      let sv=(hdrs["Server"]||hdrs["server"]||"").toLowerCase()
      let texto=sv+" "+(cuerpo||"").slice(0,600).toLowerCase()
      let banners=["nginx","apache","ubuntu","debian","centos","mitmproxy","squid","haproxy","openresty","caddy","traefik","403 forbidden","bad gateway","proxy error"]
      if (sv) { res.banner=sv.split("/")[0].trim(); res.sospechoso=true }
      else { for (let b of banners) { if (texto.includes(b)) { res.banner=b; res.sospechoso=true; break } } }
      if ([403,502,504,400].includes(res.estado)) res.sospechoso=true
      break
    } catch(e) { res.activo=false }
  }
  return res
}

// ────────────────────────────────────────────────────────────────
//  ANÁLISIS USAGE FILE
// ────────────────────────────────────────────────────────────────

const KEYWORDS_CHEAT=["filza","esign","gbox","sideload","dopamine","sileo","trollstore","trolldecrypt","trollfools","unc0ver","checkra1n","jailbreak","cydia","zebra","altstore","iosgods","potatso","shadowrocket","surge","quantumult","hiddify","shadowsocks","trojan","karing","proxyff","cheat","hack","bypass","inject","tweak","substrate","libhooker"]

function analizarUsageFile(parsed) {
  let entries=parsed.entries||parsed||[], resultados=[], vistos=new Set()
  for (let e of entries) {
    let bid=e.bundleId||""; if(!bid||vistos.has(bid)) continue; vistos.add(bid)
    let motivo=null, categoria="aviso"
    if (APPS_CHEAT[bid]) { motivo=APPS_CHEAT[bid]; categoria="critico" }
    else { let bidL=bid.toLowerCase(); for (let kw of KEYWORDS_CHEAT) { if (bidL.includes(kw)) { motivo=`Término sospechoso en bundle: "${kw}"`; break } } }
    if (!motivo) { let bidL=bid.toLowerCase(); if (!FF_APPS_LEGITIMAS.has(bid)&&(bidL.includes("freefire")||bidL.includes("freefir"))) { motivo="Copia sospechosa de Free Fire — bundle ID modificado"; categoria="critico" } }
    if (motivo) resultados.push({ bundleId:bid, version:e.shortAppVersion||"?", tipo:e.eventType||"?", motivo, categoria })
  }
  return resultados
}

// ────────────────────────────────────────────────────────────────
//  ANÁLISIS PRINCIPAL
// ────────────────────────────────────────────────────────────────

async function analizarReporte(entries) {
  let redEntries=entries.filter(e=>e.type==="networkActivity")
  let hitsDominio={}, bundlesPorDominio={}
  for (let e of redEntries) {
    if (BUNDLES_IGNORADOS.has(e.bundleID)) continue
    let d=e.domain||""; if(!d) continue
    hitsDominio[d]=(hitsDominio[d]||0)+(e.hits||1)
    if (!bundlesPorDominio[d]) bundlesPorDominio[d]=new Set()
    bundlesPorDominio[d].add(e.bundleID||"?")
  }
  let todosDominios=Object.entries(hitsDominio).sort((a,b)=>b[1]-a[1]).map(([d])=>d)
  let todosBundles=new Set()
  for (let e of redEntries) { if(e.bundleID&&!BUNDLES_IGNORADOS.has(e.bundleID)) todosBundles.add(e.bundleID) }

  // Clones FF
  let clonesFF=[]
  for (let bid of todosBundles) {
    if (FF_APPS_LEGITIMAS.has(bid)) continue
    let bidL=bid.toLowerCase()
    if (bidL.startsWith("com.dts.freefireth")||bidL.startsWith("com.dts.freefiremax")||(bidL.includes("freefire")&&!FF_APPS_LEGITIMAS.has(bid))) {
      let appE=redEntries.filter(e=>e.bundleID===bid)
      clonesFF.push({ bundleID:bid, desc:"Copia sospechosa de Free Fire — bundle ID modificado", hits:appE.reduce((s,e)=>s+(e.hits||1),0), dominios:[...new Set(appE.map(e=>e.domain).filter(Boolean))] })
    }
  }

  // Apps cheat
  let appsCheat=[...clonesFF]
  for (let [bid,desc] of Object.entries(APPS_CHEAT)) {
    if (todosBundles.has(bid)) {
      let appE=redEntries.filter(e=>e.bundleID===bid)
      appsCheat.push({ bundleID:bid, desc, hits:appE.reduce((s,e)=>s+(e.hits||1),0), dominios:[...new Set(appE.map(e=>e.domain).filter(Boolean))] })
    }
  }

  // Proxy login — SOLO dispara si FF NO llamó el dominio en la misma sesión
  let dominiosFFLegit=new Set()
  for (let e of redEntries) { if(FF_APPS_LEGITIMAS.has(e.bundleID)&&DOMINIOS_LOGIN_FF.has((e.domain||"").toLowerCase())) dominiosFFLegit.add((e.domain||"").toLowerCase()) }
  let proxyLoginVisto={}
  for (let e of redEntries) {
    let d=(e.domain||"").toLowerCase(), bid=e.bundleID||""
    if (!bid||FF_APPS_LEGITIMAS.has(bid)||BUNDLES_IGNORADOS.has(bid)) continue
    if (!DOMINIOS_LOGIN_FF.has(d)||dominiosFFLegit.has(d)) continue
    if (!proxyLoginVisto[d]) proxyLoginVisto[d]={ dominio:e.domain, bundles:new Set(), hits:0 }
    proxyLoginVisto[d].bundles.add(bid); proxyLoginVisto[d].hits+=(e.hits||1)
  }
  let proxyLogin=Object.values(proxyLoginVisto).map(i=>({ dominio:i.dominio, bundles:[...i.bundles], hits:i.hits }))

  // Infra cheat conocida
  let infraDetectada=[]
  for (let e of redEntries) {
    let d=(e.domain||"").toLowerCase(), bid=e.bundleID||""
    if (FF_APPS_LEGITIMAS.has(bid)&&DOMINIOS_LOGIN_FF.has(d)) continue
    for (let [indicador,desc] of Object.entries(INFRA_CHEAT)) {
      if (d===indicador.toLowerCase()||d.endsWith("."+indicador.toLowerCase())) {
        if (DOMINIOS_LOGIN_FF.has(indicador.toLowerCase())&&FF_APPS_LEGITIMAS.has(bid)) continue
        let ex=infraDetectada.find(k=>k.indicador===indicador)
        if (ex) { ex.hits+=(e.hits||1); if(bid) ex.bundles.add(bid) }
        else infraDetectada.push({ indicador, desc, hits:e.hits||1, bundles:new Set(bid?[bid]:[]) })
      }
    }
  }
  infraDetectada=infraDetectada.map(k=>({...k,bundles:[...k.bundles]}))

  // Dominios externos en tráfico FF
  let dominiosExternos=[], dominiosCheatFF=[]
  let vistosPorFF=new Map()
  for (let e of redEntries) {
    if (!FF_APPS_LEGITIMAS.has(e.bundleID)||!e.domain) continue
    let d=e.domain.toLowerCase().replace(/^www\./,"")
    let cur=vistosPorFF.get(d)||{ dominio:e.domain, hits:0 }
    cur.hits+=(e.hits||1); vistosPorFF.set(d,cur)
  }
  for (let [d,info] of vistosPorFF) {
    if (esDominioLegitFF(d)||esDominioRaizConfiable(d)) continue
    let esCheat=false
    for (let [infra,desc] of Object.entries(INFRA_CHEAT)) {
      if (d===infra||d.endsWith("."+infra)) { dominiosCheatFF.push({ dominio:info.dominio, desc, hits:info.hits }); esCheat=true; break }
    }
    if (!esCheat) dominiosExternos.push({ dominio:info.dominio, hits:info.hits })
  }

  // Apps fantasma
  let porBundle={}
  for (let e of redEntries) {
    let bid=e.bundleID||"", dom=(e.domain||"").toLowerCase()
    if (!bid||BUNDLES_IGNORADOS.has(bid)||(FF_APPS_LEGITIMAS.has(bid)&&DOMINIOS_LOGIN_FF.has(dom))) continue
    let esInfra=Object.keys(INFRA_CHEAT).includes(dom)
    let esTLD=TLD_SOSPECHOSOS.some(t=>dom.endsWith(t))
    if (esInfra||esTLD) {
      if (!porBundle[bid]) porBundle[bid]={ dominios:[], hits:0 }
      porBundle[bid].dominios.push(e.domain); porBundle[bid].hits+=(e.hits||1)
    }
  }
  let appsFantasma=Object.entries(porBundle).map(([bid,info])=>({ bundleID:bid, dominios:[...new Set(info.dominios)], hits:info.hits }))

  // IP-API batch (pasadas 3-6)
  Speech.speak("Analizando, esperá que RIP PROXY termine.")
  let candidatos=[], CHUNK=100
  for (let i=0; i<todosDominios.length; i+=CHUNK) {
    let chunk=todosDominios.slice(i,i+CHUNK)
    let resultados=await consultarIPs(chunk)
    if (i+CHUNK>=todosDominios.length/2) Speech.speak("Escáner al cincuenta por ciento.")
    for (let j=0; j<resultados.length; j++) {
      let info=resultados[j], dominio=chunk[j]
      let ip=(info&&info.query)||dominio
      if (esDominioRaizConfiable(dominio)) continue
      if (IPS_FALSOS_POSITIVOS.has(ip)||IPS_FALSOS_POSITIVOS.has(dominio)) continue
      let bundles=bundlesPorDominio[dominio]||new Set()
      let { nivel, motivos }=clasificarDominio(info, dominio, bundles)
      if (!nivel) {
        let domLow=dominio.toLowerCase()
        if (TLD_SOSPECHOSOS.some(t=>domLow.endsWith(t))) { nivel="ALTO"; motivos=["TLD sospechoso"] }
      }
      if (!nivel) continue
      candidatos.push({
        nivel, dominio, ip,
        pais:(info&&info.country)||"?", ciudad:(info&&info.city)||"?",
        isp:(info&&info.isp)||"?", org:(info&&info.org)||"?", asn:(info&&info.as)||"?",
        hosting:!!(info&&info.hosting), proxy:!!(info&&info.proxy), rdns:(info&&info.reverse)||"",
        hits:hitsDominio[dominio],
        bundles:[...bundles].filter(b=>!BUNDLES_IGNORADOS.has(b)).slice(0,4),
        motivos, esTLD:TLD_SOSPECHOSOS.some(t=>dominio.toLowerCase().endsWith(t)),
      })
    }
    if (i+CHUNK<todosDominios.length) await esperar(1400)
  }

  // Pasada 7 — probe HTTP
  Speech.speak("Escáner al noventa por ciento.")
  let probeResultados=await Promise.all(candidatos.map(c=>probeHTTP(c.dominio)))
  let hallazgos=candidatos.map((c,idx)=>{
    let probe=probeResultados[idx], nivel=c.nivel, motivos=[...c.motivos]
    if (probe) {
      if (probe.sospechoso&&probe.banner) { nivel="ALTO"; motivos.push(`Servidor: ${probe.banner}`) }
      if (probe.estado===403) motivos.push("HTTP 403 — activo pero bloqueando acceso")
      if (!probe.activo) motivos.push("Sin respuesta HTTP")
    }
    return {...c,nivel,motivos,probe}
  })

  hallazgos.sort((a,b)=>{
    let aT=a.esTLD?0:1, bT=b.esTLD?0:1; if(aT!==bT) return aT-bT
    let aA=(a.asn||"").split(" ")[0].toUpperCase(), bA=(b.asn||"").split(" ")[0].toUpperCase()
    let aK=ASN_SOSPECHOSOS[aA]?0:1, bK=ASN_SOSPECHOSOS[bA]?0:1; if(aK!==bK) return aK-bK
    let nO={ALTO:0,MEDIO:1}; if(a.nivel!==b.nivel) return nO[a.nivel]-nO[b.nivel]
    return b.hits-a.hits
  })

  return { hallazgos, redEntries, appsCheat, infraDetectada, appsFantasma, proxyLogin, dominiosExternos, dominiosCheatFF }
}

// ────────────────────────────────────────────────────────────────
//  REPORTE HTML
// ────────────────────────────────────────────────────────────────

function construirReporte(tlsResultados, hallazgos, redEntries, appsCheat, infraDetectada, usageHallazgos, ipsMeta, appsFantasma, proxyLogin, dominiosExternos, dominiosCheatFF, nombreArchivo) {

  let ts=redEntries.map(e=>e.timeStamp).filter(Boolean).sort()
  let tsI=ts.length?new Date(ts[0]):null, tsF=ts.length?new Date(ts[ts.length-1]):null
  let durStr="—", alertaDur=false
  if (tsI&&tsF) { let d=Math.floor((tsF-tsI)/60000), h=Math.floor(d/60), dd=Math.floor(h/24); durStr=dd>0?`${dd}d ${h%24}h ${d%60}min`:h>0?`${h}h ${d%60}min`:`${d} min`; if(d<20) alertaDur=true }
  let alertaV=false, strV=""
  if (tsF) { let dN=Math.floor((new Date()-tsF)/60000); if(dN>15){ alertaV=true; strV=dN>=60?`${Math.floor(dN/60)}h ${dN%60}min`:`${dN}min` } }

  // ── VEREDICTO: solo señales críticas ──
  // Las IPs/ASN sospechosas son INFORMATIVAS y NO cuentan
  let señalesCriticas =
    infraDetectada.length +
    appsCheat.length +
    dominiosCheatFF.length +
    proxyLogin.length +
    tlsResultados.filter(r=>r.sospechoso).length +   // solo si hay headers reales
    (usageHallazgos.filter(f=>f.categoria==="critico").length > 0 ? 1 : 0) +
    ((ipsMeta&&ipsMeta.rootsInstalled>0) ? 1 : 0)

  let veredicto=señalesCriticas===0?"LIMPIO":señalesCriticas<=2?"SOSPECHOSO":"CHEAT DETECTADO"
  let colorV=señalesCriticas===0?"#00e676":señalesCriticas<=2?"#ffab00":"#ff1744"
  let iconoV=señalesCriticas===0?"✅":señalesCriticas<=2?"⚠️":"🚨"

  let filasTLS=tlsResultados.map(r=>{
    let color=!r.alcanzable?"#444":r.sospechoso?"#ff1744":"#00e676"
    let estado=!r.alcanzable?"sin acceso":r.sospechoso?"⚠ proxy detectado":"normal"
    let latTxt=r.latencia!==null?formatMs(r.latencia):"—"
    let latColor=r.latencia>LATENCIA_UMBRAL?"#888":"#444"
    let detalleDiv=r.motivo?`<div style="font-size:10px;color:#ff8a65;margin-top:2px;">${r.motivo}</div>`:""
    let infoDiv=r.info&&r.info.length?`<div style="font-size:9px;color:#333;margin-top:2px;">${r.info.join(" · ")}</div>`:""
    return `<tr><td style="padding:10px 14px;font-size:12px;color:#888;border-bottom:1px solid #0d0d1a;">${r.nombre}</td><td style="padding:10px 14px;border-bottom:1px solid #0d0d1a;"><span style="color:${color};font-size:12px;font-weight:600;">${estado}</span>${detalleDiv}${infoDiv}</td><td style="padding:10px 14px;font-size:12px;color:${latColor};border-bottom:1px solid #0d0d1a;text-align:right;">${latTxt}</td></tr>`
  }).join("")

  let alertaCert=(ipsMeta&&ipsMeta.rootsInstalled>0)?`<div style="background:#0a0a12;border-left:3px solid #e040fb;border-radius:6px;padding:14px 16px;margin-bottom:10px;"><div style="color:#e040fb;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;">🔐 Certificado Raíz Instalado</div><div style="color:#ddd;font-size:12px;">${ipsMeta.rootsInstalled} certificado${ipsMeta.rootsInstalled>1?"s":""} raíz detectado${ipsMeta.rootsInstalled>1?"s":""}.</div><div style="color:#888;font-size:11px;margin-top:3px;">Permite interceptar HTTPS — señal directa de proxy MITM.</div></div>`:""

  function tarjeta(icono,etiq,titulo,sub,det,col) {
    return `<div style="background:#0a0a12;border:1px solid ${col}22;border-left:3px solid ${col};border-radius:6px;padding:14px 16px;margin-bottom:10px;"><div style="color:${col};font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;">${icono} ${etiq}</div><div style="color:#fff;font-size:13px;font-weight:600;margin-bottom:2px;">${titulo}</div>${sub?`<div style="color:#aaa;font-size:11px;margin-bottom:4px;">${sub}</div>`:""  }${det?`<div style="color:#555;font-size:10px;">${det}</div>`:""}</div>`
  }

  let criticas=""
  for (let a of appsCheat)       criticas+=tarjeta("⛔","App Cheat / Proxy",a.bundleID,a.desc,`${a.hits} conexiones`,"#ff1744")
  for (let k of infraDetectada)  criticas+=tarjeta("🚨","Infra Cheat Confirmada",k.indicador,k.desc,`${k.hits} conexiones · ${k.bundles.join(", ")||"?"}`,"#ff1744")
  for (let d of dominiosCheatFF) criticas+=tarjeta("🚨","Cheat en Tráfico de FF",d.dominio,d.desc,`${d.hits} conexiones desde Free Fire`,"#ff1744")
  for (let p of proxyLogin)      criticas+=tarjeta("⚠️","Proxy Login FF",p.dominio,"Dominio de login de FF contactado por app ajena",`${p.hits} hits · ${p.bundles.join(", ")}`,"#ffab00")

  let secUsage=""
  if (usageHallazgos.length>0) {
    let f=usageHallazgos.map(h=>{ let c=h.categoria==="critico"?"#ff1744":h.categoria==="vpn"?"#ffab00":"#888", e=h.categoria==="critico"?"CRÍTICO":h.categoria==="vpn"?"VPN":"AVISO"; return `<div style="background:#0a0a12;border-left:3px solid ${c};border-radius:4px;padding:10px 14px;margin-bottom:6px;"><div style="color:${c};font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:3px;">${e}</div><div style="color:#ddd;font-size:12px;font-weight:600;">${h.bundleId}</div><div style="color:#777;font-size:11px;margin-top:2px;">${h.motivo}</div></div>` }).join("")
    secUsage=`<div style="margin-top:28px;"><div style="font-size:10px;font-weight:700;color:#333;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:10px;">📲 Apps en Usage File</div>${f}</div>`
  }

  let secDomFF=""
  if (dominiosExternos.length>0) {
    let f=dominiosExternos.map(d=>`<div style="background:#0a0a12;border-left:3px solid #ffab00;border-radius:4px;padding:10px 14px;margin-bottom:6px;"><div style="color:#ffab00;font-size:12px;font-weight:600;">${d.dominio}</div><div style="color:#444;font-size:10px;margin-top:2px;">Dominio externo en tráfico de FF · ${d.hits} conexiones</div></div>`).join("")
    secDomFF=`<div style="margin-top:28px;"><div style="font-size:10px;font-weight:700;color:#333;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:10px;">⚠️ Dominios Externos en Tráfico de FF</div>${f}</div>`
  }

  // IPs/ASN — sección INFORMATIVA, no cuenta en veredicto
  let ipCards=hallazgos.length===0
    ? `<div style="background:#0a0a12;border-left:3px solid #00e676;border-radius:4px;padding:12px 14px;color:#00e676;font-size:12px;">Sin IPs de hosting o proxy detectadas.</div>`
    : hallazgos.map(h=>{
        let color=h.esTLD?"#ffab00":h.nivel==="ALTO"?"#ff5252":"#ffab00"
        let etiq=h.esTLD?"DOMINIO SOSPECHOSO":h.nivel==="ALTO"?"SOSPECHOSO":"POSIBLE"
        return `<div style="background:#0a0a12;border-left:2px solid ${color}66;border-radius:4px;padding:12px 14px;margin-bottom:8px;"><div style="color:${color};font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;">${etiq}</div><div style="color:#ccc;font-size:13px;font-weight:600;">${h.dominio}</div><div style="color:#444;font-size:10px;margin-top:4px;">IP: ${h.ip} · ${h.pais}/${h.ciudad} · ${h.asn}</div><div style="color:#444;font-size:10px;">ISP: ${h.isp}</div>${h.rdns?`<div style="color:#444;font-size:10px;">rDNS: ${h.rdns}</div>`:""}<div style="color:#ff8a65;font-size:11px;margin-top:4px;">${h.motivos.join("<br>")}</div><div style="color:#333;font-size:10px;margin-top:4px;">${h.hits} conexiones · ${h.bundles.join(", ")}</div></div>`
      }).join("")

  let secFantasma=""
  if (appsFantasma.length>0) {
    let f=appsFantasma.map(a=>`<div style="background:#0a0a12;border-left:2px solid #333;border-radius:4px;padding:10px 14px;margin-bottom:6px;"><div style="color:#666;font-size:12px;font-weight:600;">${a.bundleID}</div><div style="color:#333;font-size:10px;margin-top:2px;">${a.dominios.slice(0,4).join(", ")} · ${a.hits} hits</div></div>`).join("")
    secFantasma=`<div style="margin-top:28px;"><div style="font-size:10px;font-weight:700;color:#333;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:10px;">👻 Apps Fantasma</div>${f}</div>`
  }

  return `<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1"><title>RIP PROXY</title><style>*{box-sizing:border-box;margin:0;padding:0}body{background:#06060f;color:#e0e0e0;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",sans-serif;padding:0 0 60px 0;max-width:580px;margin:0 auto}.header{background:linear-gradient(180deg,#0d0d20 0%,#06060f 100%);padding:32px 20px 24px;border-bottom:1px solid #0d0d1a}.contenido{padding:20px}table{width:100%;border-collapse:collapse}th{font-size:10px;color:#333;font-weight:600;padding:8px 14px;text-align:left;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid #0d0d1a}</style></head><body>
<div class="header">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;"><div style="width:40px;height:40px;background:linear-gradient(135deg,#6c00ff,#00c4ff);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;">🔍</div><div><div style="font-size:18px;font-weight:800;letter-spacing:1px;color:#fff;">RIP PROXY</div><div style="font-size:10px;color:#333;margin-top:1px;">code by tizi · UNKNOWN Security Team · v${VERSION}</div></div></div>
  <div style="background:#0a0a18;border:1px solid ${colorV}22;border-radius:10px;padding:20px;text-align:center;">
    <div style="font-size:36px;margin-bottom:8px;">${iconoV}</div>
    <div style="font-size:20px;font-weight:800;color:${colorV};letter-spacing:2px;margin-bottom:6px;">${veredicto}</div>
    <div style="font-size:12px;color:#444;">${señalesCriticas} señal${señalesCriticas!==1?"es":""} crítica${señalesCriticas!==1?"s":""} · ${formatFecha(tsI)} → ${formatFecha(tsF)} · ${durStr}</div>
    ${alertaDur?`<div style="color:#ffab00;font-size:11px;margin-top:6px;">⚠ Reporte cubre menos de 20 minutos</div>`:""}
    ${alertaV?`<div style="color:#ff8a65;font-size:11px;margin-top:4px;">Último registro hace ${strV}</div>`:""}
  </div>
</div>
<div class="contenido">
  <div style="margin-top:0;"><div style="font-size:10px;font-weight:700;color:#333;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:12px;">🔐 Probe TLS en vivo</div>
    <div style="background:#0a0a12;border-radius:6px;overflow:hidden;margin-bottom:6px;"><table><thead><tr><th>Endpoint</th><th>Estado</th><th style="text-align:right;">Latencia</th></tr></thead><tbody>${filasTLS}</tbody></table></div>
    <div style="font-size:10px;color:#222;padding:0 2px;">Solo headers de proxy reales disparan alerta · Latencia y HSTS son informativos</div>
  </div>
  ${alertaCert?`<div style="margin-top:20px;">${alertaCert}</div>`:""}
  ${criticas?`<div style="margin-top:28px;"><div style="font-size:10px;font-weight:700;color:#333;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:10px;">🚨 Detecciones Críticas</div>${criticas}</div>`:""}
  ${secUsage}
  <div style="margin-top:28px;">
    <div style="font-size:10px;font-weight:700;color:#333;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:6px;">🌐 IPs / ASN / Hosting</div>
    <div style="font-size:10px;color:#333;margin-bottom:10px;">Solo informativo — no afecta el veredicto</div>
    ${ipCards}
  </div>
  ${secDomFF}
  ${secFantasma}
  <div style="margin-top:32px;background:#0a0a12;border-radius:6px;padding:16px;"><div style="font-size:10px;font-weight:700;color:#6c00ff;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;">Verificación en 7 pasadas</div><div style="display:grid;grid-template-columns:1fr 1fr;gap:4px 12px;">${["Pasada 1: Raíz confiable","Pasada 2: IPs conocidas","Pasada 3: IP-API lookup","Pasada 4: ISP legítimo FF","Pasada 5: ASN / VPS","Pasada 6: rDNS y org","Pasada 7: Banners HTTP","Probe TLS (headers reales)","Bundle IDs cheat/JB","Infra iOS confirmada","Proxy Login FF","Dominios externos FF","Apps fantasma","Certificados raíz"].map(c=>`<div style="font-size:10px;color:#222;padding:2px 0;">✓ ${c}</div>`).join("")}</div></div>
</div>
<div style="margin-top:40px;padding:16px 20px;border-top:1px solid #0a0a18;text-align:center;"><div style="color:#1a1a2e;font-size:10px;">RIP PROXY v${VERSION} · code by tizi · UNKNOWN Security Team</div></div>
</body></html>`
}

// ────────────────────────────────────────────────────────────────
//  MAIN
// ────────────────────────────────────────────────────────────────

  let bienvenida=new Alert()
  bienvenida.title="RIP PROXY v3.2"; bienvenida.message="Scanner Anti-Cheat iOS · code by tizi\nVerificación en 7 pasadas · 14 capas\n\nNecesitás el App Privacy Report exportado desde:\nConfiguración → Privacidad → Informe de privacidad de apps → Exportar\n\nEl archivo Usage (.ips) es opcional."
  bienvenida.addAction("Seleccionar archivos"); bienvenida.addCancelAction("Cancelar")
  if (await bienvenida.present()===-1) { Script.complete(); return }

  let a1=new Alert(); a1.title="Archivo 1 — Obligatorio"; a1.message="Seleccioná el App_Privacy_Report.ndjson"; a1.addAction("Seleccionar"); a1.addCancelAction("Cancelar")
  if (await a1.present()===-1) { Script.complete(); return }
  let ruta1=await DocumentPicker.openFile()
  if (!ruta1) { Script.complete(); return }
  let cont1=await leerArchivo(ruta1)
  if (!cont1) { let a=new Alert(); a.title="Error"; a.message="No se pudo leer el archivo."; a.addAction("OK"); await a.present(); Script.complete(); return }

  let a2=new Alert(); a2.title="Archivo 2 — Opcional"; a2.message="Seleccioná el xp_amp_app_usage_dnu*.ips o salteá."; a2.addAction("Seleccionar"); a2.addCancelAction("Saltear")
  let ruta2=null, cont2=null
  if (await a2.present()!==-1) { ruta2=await DocumentPicker.openFile(); if(ruta2) cont2=await leerArchivo(ruta2) }

  function clasificarArchivo(c,r) {
    if (esReportePrivacidad(c)) return "ndjson"
    if (esArchivoUsage(c))     return "ips"
    let n=(r||"").split("/").pop().toLowerCase()
    if (n.endsWith(".ndjson")||n.includes("privacy")) return "ndjson"
    if (n.endsWith(".ips")||n.includes("xp_amp"))     return "ips"
    return "desconocido"
  }

  let tipo1=clasificarArchivo(cont1,ruta1)
  let ndjsonCont=null, ndjsonRuta=null, ipsCont=null
  if (tipo1==="ndjson") { ndjsonCont=cont1; ndjsonRuta=ruta1; ipsCont=cont2 }
  else if (tipo1==="ips") { ipsCont=cont1; ndjsonCont=cont2; ndjsonRuta=ruta2 }
  else { let a=new Alert(); a.title="Archivo no reconocido"; a.message="Verificá que seleccionaste el App_Privacy_Report.ndjson."; a.addAction("OK"); await a.present(); Script.complete(); return }

  if (!ndjsonCont) { let a=new Alert(); a.title="Reporte ausente"; a.message="El App Privacy Report (.ndjson) es obligatorio.\n\nConfiguración → Privacidad → Informe de privacidad de apps → Exportar"; a.addAction("OK"); await a.present(); Script.complete(); return }

  let entradas=parsearNdjson(ndjsonCont)
  let val=validarReporte(entradas)
  if (!val.ok) { let a=new Alert(); a.title="Reporte inválido"; a.message=val.motivo+"\n\nExportá desde: Configuración → Privacidad → Informe de privacidad de apps"; a.addAction("OK"); await a.present(); Script.complete(); return }

  let usageH=[], ipsMeta={ rootsInstalled:0, iosVersion:null }
  if (ipsCont) {
    let p=parsearIps(ipsCont); usageH=analizarUsageFile(p)
    if (p.header) { let m=(p.header.os_version||"").match(/iPhone OS ([\d.]+)/); ipsMeta.iosVersion=m?m[1]:p.header.os_version||null; ipsMeta.rootsInstalled=p.header.roots_installed||0 }
  }

  let tlsR=await Promise.all(ENDPOINTS_GARENA.map(ep=>probeTLS(ep)))
  let { hallazgos, redEntries, appsCheat, infraDetectada, appsFantasma, proxyLogin, dominiosExternos, dominiosCheatFF }=await analizarReporte(entradas)
  let nombreArch=(ndjsonRuta||"archivo").split("/").pop()
  Speech.speak("RIP PROXY finalizado. Revisá los resultados con cuidado.")

  let html=construirReporte(tlsR, hallazgos, redEntries, appsCheat, infraDetectada, usageH, ipsMeta, appsFantasma, proxyLogin, dominiosExternos, dominiosCheatFF, nombreArch)
  let wv=new WebView(); await wv.loadHTML(html); await wv.present(false)
  Script.complete()

})()
