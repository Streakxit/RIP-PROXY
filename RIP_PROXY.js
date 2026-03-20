// ================================================================
//  RIP PROXY — Anti-Cheat Scanner para Free Fire iOS
//  code by tizi · UNKNOWN Security Team · v3.0
// ================================================================
//
//  CAPAS DE DETECCIÓN:
//   [1] Probe TLS en vivo         — headers de proxy, latencia, HSTS
//   [2] IP-API Batch              — ASN, VPS, hosting, rDNS, ISP
//   [3] Probe HTTP                — banners de servidor sospechosos
//   [4] Bundle IDs                — apps proxy / jailbreak / sideload
//   [5] Infraestructura conocida  — dominios e IPs de cheats confirmados
//   [6] Proxy Login               — dominios FF llamados por apps ajenas
//   [7] Apps fantasma             — ausentes en app_usage, dominios sospechosos
//   [8] TLD y palabras clave      — extensiones y términos sospechosos
//   [9] Certificados raíz         — roots_installed > 0 (señal de MITM)
//  [10] Tráfico de Free Fire      — dominios externos contactados por el juego
//  [11] Clones de Free Fire       — bundle IDs modificados del juego
//
//  USO:
//   Exportar App Privacy Report desde:
//   Configuración → Privacidad → Informe de privacidad de apps → Exportar
//   (Opcional) archivo xp_amp_app_usage_dnu*.ips desde Datos de análisis
// ================================================================

const VERSION = "3.0"
const LATENCIA_UMBRAL = 600
const IP_FIELDS = "status,country,city,isp,org,hosting,proxy,query,reverse,as"

// ────────────────────────────────────────────────────────────────
//  BASE DE DATOS DE DETECCIÓN
// ────────────────────────────────────────────────────────────────

const HOSTING_KEYWORDS = [
  "hostinger","hstgr","locaweb","kinghost","umbler","hostgator","uol host","uolhost",
  "redehost","weblink","brasileirohost","br.host","dialhost","serverspace","ibrcom",
  "masterweb","superdomin","plankton","vps.br","digitalocean","linode","akamai",
  "vultr","hetzner","ovh","ovhcloud","contabo","ionos","godaddy","siteground",
  "cloudways","amazon","aws","amazonaws","google cloud","googlecloud","microsoft azure",
  "azure","alibaba cloud","alibabacloud","tencent cloud","tencentcloud","hstgr.cloud",
  "srv.umbler","kinghost.net","locaweb.com.br","choopa","psychz","m247","serverius",
  "frantech","buyvm","sharktech","quadranet","nexeon","servermania","hostwinds",
  "racknerd","dedipath","spartanhost","cloudie","tsohost","wavenet","fasthosts",
  "multacom","telus","fdcservers","fdc servers","leaseweb","colocation america",
  "b2 net","b2net","path.net","datacamp","tzulo","coresite","vietnix",
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
  "AS13335": "Cloudflare",
  "AS209":   "CenturyLink / Lumen",
  "AS7203":  "Sharktech",
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

const SUFIJOS_CONFIANZA = ["apple.com","icloud.com","google.com","meli.com","mercadopago.com","instagram.com","facebook.com"]
if (SUFIJOS_CONFIANZA.some(s => domLow.endsWith("." + s) || domLow === s)) {
  return { nivel: null, motivos: [] }
}

const PALABRAS_SOSPECHOSAS = [
  "proxy","cheat","hack","bypass","mitm","inject","spoof","crack",
  "exploit","payload","tunnel","vpn","socks","relay","forward","gate",
]

const IPS_FALSOS_POSITIVOS = new Set([
  "104.29.152.79","104.29.152.107","92.223.118.254","23.221.214.168",
  "23.192.36.217","54.69.69.125","104.29.152.189","104.29.137.146",
  "104.29.155.56","104.29.137.203","104.29.155.129","104.29.137.125",
  "104.29.158.97","104.29.152.95","104.29.153.53","104.29.159.185",
  "104.29.157.123","104.29.152.27","104.29.157.107","104.29.137.16",
  "104.29.152.164","104.29.137.53","104.29.135.227","104.29.158.139",
  "104.29.152.157","104.29.156.174","104.29.156.24","104.29.154.91",
  "104.29.155.27","104.29.156.120","104.29.137.112",
])

const DOMINIOS_LOGIN_FF = new Set([
  "version.ffmax.purplevioleto.com","version.ggwhitehawk.com",
  "loginbp.ggpolarbear.com","gin.freefiremobile.com",
  "100067.connect.garena.com","100067.msdk.garena.com",
  "client.us.freefiremobile.com","client.sea.freefiremobile.com",
  "sacnetwork.ggblueshark.com","sacevent.ggblueshark.com",
])

const FF_APPS_LEGITIMAS = new Set(["com.dts.freefireth","com.dts.freefiremax"])

const INFRA_CHEAT = {
  "46.202.145.85":                    "Fatality Cheats — servidor confirmado",
  "fatalitycheats.xyz":               "Fatality Cheats — dominio oficial",
  "anubisw.online":                   "Servidor de cheat — Free Fire",
  "api.baontq.xyz":                   "API de cheat — Free Fire",
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

const HEADERS_PROXY_CONOCIDOS = [
  "via","x-forwarded-for","x-forwarded-proto","x-real-ip",
  "proxy-connection","x-mitm-proxy","x-proxy-id","forwarded",
  "x-cache","x-served-by","x-request-id",
]

const DOMINIOS_LEGITIMOS_FF = new Set([
  "garena.com","garena.com.sg","garena.tw","garena.vn","garenagames.com",
  "freefiremobile.com","freefireth.com","ggblueshark.com","ggpolarbear.com",
  "ggwhitehawk.com","ggraven.com","ggvenom.com","ggflamingo.com",
  "msdk.garena.com","connect.garena.com","sdk.garena.com","store.garena.com",
  "akamaized.net","akamai.net","akamaistream.net","cloudfront.net","fastly.net",
  "apple.com","icloud.com","mzstatic.com","crashlytics.com","firebase.com",
  "firebaseio.com","googleapis.com","gstatic.com","amplitude.com",
  "appsflyer.com","adjust.com","facebook.com","fbcdn.net",
])

const BUNDLES_IGNORADOS = new Set(["com.hammerandchisel.discord","com.zhiliaoapp.musically"])

// ────────────────────────────────────────────────────────────────
//  UTILIDADES
// ────────────────────────────────────────────────────────────────

function dominioEsLegitimo(d) {
  d = d.toLowerCase().replace(/^www\./, "")
  if (DOMINIOS_LEGITIMOS_FF.has(d)) return true
  for (let l of DOMINIOS_LEGITIMOS_FF) { if (d.endsWith("." + l) || d === l) return true }
  return false
}

function formatMs(ms) { return ms < 1000 ? ms + "ms" : (ms/1000).toFixed(1) + "s" }

function formatFecha(d) {
  if (!d) return "—"
  return d.toLocaleString("es-AR", { day:"2-digit", month:"2-digit", year:"numeric", hour:"2-digit", minute:"2-digit" })
}

async function leerArchivo(ruta) {
  try { return FileManager.local().readString(ruta) } catch(e) {}
  try { return FileManager.iCloud().readString(ruta) } catch(e) {}
  return null
}

function parsearNdjson(c) {
  let t = c.trim()
  if (t.startsWith("[")) { try { return JSON.parse(t) } catch(e) {} }
  return t.split("\n").map(l => l.trim()).filter(l => l.length > 0)
    .map(l => { try { return JSON.parse(l) } catch(e) { return null } }).filter(Boolean)
}

function parsearIps(c) {
  try {
    let lineas = c.trim().split("\n").map(l => l.trim()).filter(Boolean)
    let header = null, entries = []
    try { header  = JSON.parse(lineas.find(l => l.startsWith("{")) || "null") } catch(e) {}
    try { entries = JSON.parse(lineas.find(l => l.startsWith("[")) || "[]")   } catch(e) {}
    return { header, entries }
  } catch(e) { return { header: null, entries: [] } }
}

function esReportePrivacidad(c) {
  let s = c.trim().slice(0, 500)
  return s.includes("networkActivity") || s.includes("bundleID") || s.includes("timeStamp")
}

function esArchivoUsage(c) {
  let s = c.trim().slice(0, 300)
  return s.includes("xp_amp_app_usage") || s.includes("roots_installed") || s.includes("usageClientId")
}

function esperar(ms) { return new Promise(r => Timer.schedule(ms, false, r)) }

// ────────────────────────────────────────────────────────────────
//  CAPA 1 — PROBE TLS EN VIVO
// ────────────────────────────────────────────────────────────────

async function probeTLS(ep) {
  let r = {
    nombre: ep.nombre, alcanzable: false, latencia: null,
    headersProxy: [], sospechoso: false, motivo: null,
  }
  try {
    let req = new Request(ep.url)
    req.method = "HEAD"
    req.timeoutInterval = 8
    req.headers = { "User-Agent": "FreeFire/1.0 CFNetwork/1492.0.1 Darwin/23.0.0", "Accept": "*/*" }
    let t0 = Date.now()
    try { await req.load() } catch(e) {}
    r.latencia    = Date.now() - t0
    r.alcanzable  = true
    let hdrs = (req.response && req.response.headers) ? req.response.headers : {}
    let server = hdrs["server"] || hdrs["Server"] || ""
    let hsts   = hdrs["strict-transport-security"] || hdrs["Strict-Transport-Security"] || ""
    for (let h of HEADERS_PROXY_CONOCIDOS) {
      if (Object.keys(hdrs).some(k => k.toLowerCase() === h)) r.headersProxy.push(h)
    }
    let motivos = []
    if (r.headersProxy.length > 0)   motivos.push("Headers de proxy detectados: " + r.headersProxy.join(", "))
    if (r.latencia > LATENCIA_UMBRAL) motivos.push("Latencia anómala: " + formatMs(r.latencia))
    if (server) { let sv = server.toLowerCase(); if (sv.includes("mitm") || sv.includes("proxy") || sv.includes("nginx") || sv.includes("apache")) motivos.push("Header server inusual: " + server) }
    if (!hsts) motivos.push("HSTS ausente — posible stripping por proxy")
    if (motivos.length > 0) { r.sospechoso = true; r.motivo = motivos.join(" · ") }
  } catch(e) { r.motivo = "Endpoint no alcanzable" }
  return r
}

// ────────────────────────────────────────────────────────────────
//  CAPA 2 — IP-API BATCH
// ────────────────────────────────────────────────────────────────

async function consultarIPs(targets) {
  try {
    let req = new Request(`http://ip-api.com/batch?fields=${IP_FIELDS}`)
    req.method = "POST"
    req.body   = Data.fromString(JSON.stringify(targets))
    req.headers = { "Content-Type": "application/json" }
    req.timeoutInterval = 15
    let res = await req.loadJSON()
    return Array.isArray(res) ? res : []
  } catch(e) { return [] }
}

function clasificarIP(info, dominio) {
  if (!info) return { nivel: null, motivos: [] }
  let motivos = [], nivel = null
  let domLow = (dominio || "").toLowerCase()

  for (let tld of TLD_SOSPECHOSOS) {
    if (domLow.endsWith(tld) || domLow.includes(tld + "/")) {
      nivel = "ALTO"; motivos.push(`TLD sospechoso: "${tld}"`); break
    }
  }
  if (!nivel) {
    let parte = domLow.split(".")[0]
    for (let w of PALABRAS_SOSPECHOSAS) {
      if (parte.includes(w) || domLow.includes(w + ".")) {
        nivel = "ALTO"; motivos.push(`Término sospechoso en dominio: "${w}"`); break
      }
    }
  }
  if (info.hosting) { nivel = "ALTO"; motivos.push(`Hosting/VPS — ISP: ${info.isp}`) }
  if (info.proxy)   { nivel = "ALTO"; motivos.push("Proxy o VPN detectado") }

  let asn = (info.as || "").split(" ")[0].toUpperCase()
  if (ASN_SOSPECHOSOS[asn]) {
    if (asn === "AS13335") {
      if (/^[\d.:]+$/.test(dominio || "")) { nivel = "ALTO"; motivos.push(`Cloudflare accedido por IP directa (${asn})`) }
    } else {
      nivel = "ALTO"; motivos.push(`ASN asociado a cheats: ${asn} — ${ASN_SOSPECHOSOS[asn]}`)
    }
  }

  let rdns = (info.reverse || "").toLowerCase()
  if (rdns) {
    for (let p of RDNS_PATRONES) {
      if (rdns.includes(p)) { nivel = nivel || "ALTO"; motivos.push(`rDNS de servidor: ${info.reverse}`); break }
    }
    if (rdns.match(/^srv\d+\.hstgr\.cloud$/)) { nivel = "ALTO"; motivos.push(`VPS Hostinger: ${info.reverse}`) }
  } else if (info.hosting) {
    motivos.push("Sin rDNS — típico de VPS usado como proxy")
  }

  let orgStr = ((info.org||"")+" "+(info.isp||"")+" "+(info.as||"")).toLowerCase()
  for (let kw of HOSTING_KEYWORDS) {
    if (orgStr.includes(kw)) { nivel = nivel || "MEDIO"; motivos.push(`Proveedor asociado a cheats: ${kw}`); break }
  }

  return { nivel, motivos }
}

// ────────────────────────────────────────────────────────────────
//  CAPA 3 — PROBE HTTP (BANNERS)
// ────────────────────────────────────────────────────────────────

async function probeHTTP(dominio) {
  let seguros = ["apple.com","icloud.com","google.com","googleapis.com","gstatic.com","amazon.com","microsoft.com","akamai","cloudfront","fastly","edgekey","aaplimg"]
  if (seguros.some(s => dominio.toLowerCase().includes(s))) return null
  let res = { estado: null, banner: null, activo: false, sospechoso: false }
  for (let esquema of ["https","http"]) {
    try {
      let req = new Request(`${esquema}://${dominio}`)
      req.timeoutInterval = 6
      req.allowInsecureRequest = true
      let cuerpo = await req.loadString()
      res.activo = true
      let resp  = req.response || {}
      res.estado = resp.statusCode || 0
      let hdrs  = resp.headers || {}
      let sv    = (hdrs["Server"] || hdrs["server"] || "").toLowerCase()
      let texto = sv + " " + (cuerpo || "").slice(0, 600).toLowerCase()
      let banners = ["nginx","apache","ubuntu","debian","centos","mitmproxy","squid","haproxy","openresty","caddy","traefik","403 forbidden","bad gateway","proxy error"]
      if (sv) { res.banner = sv.split("/")[0].trim(); res.sospechoso = true }
      else { for (let b of banners) { if (texto.includes(b)) { res.banner = b; res.sospechoso = true; break } } }
      if ([403,502,504,400].includes(res.estado)) res.sospechoso = true
      break
    } catch(e) { res.activo = false }
  }
  return res
}

// ────────────────────────────────────────────────────────────────
//  CAPA 4 — ANÁLISIS BUNDLE IDS (IPS FILE)
// ────────────────────────────────────────────────────────────────

const KEYWORDS_CHEAT = [
  "filza","esign","gbox","sideload","dopamine","sileo","trollstore","trolldecrypt",
  "trollfools","unc0ver","checkra1n","jailbreak","cydia","zebra","altstore","iosgods",
  "potatso","shadowrocket","surge","quantumult","hiddify","shadowsocks","trojan",
  "karing","proxyff","cheat","hack","bypass","inject","tweak","substrate","libhooker",
]

function analizarUsageFile(parsed) {
  let entries = parsed.entries || parsed || []
  let resultados = [], vistos = new Set()
  for (let e of entries) {
    let bid = e.bundleId || ""; if (!bid || vistos.has(bid)) continue; vistos.add(bid)
    let motivo = null, categoria = "aviso"
    if (APPS_CHEAT[bid]) { motivo = APPS_CHEAT[bid]; categoria = "critico" }
    else { let bidL = bid.toLowerCase(); for (let kw of KEYWORDS_CHEAT) { if (bidL.includes(kw)) { motivo = `Término sospechoso en bundle: "${kw}"`; break } } }
    if (!motivo) {
      let bidL = bid.toLowerCase()
      if (!FF_APPS_LEGITIMAS.has(bid) && (bidL.includes("freefire") || bidL.includes("freefir"))) { motivo = "Copia sospechosa de Free Fire — bundle ID modificado"; categoria = "critico" }
    }
    if (motivo) resultados.push({ bundleId: bid, version: e.shortAppVersion || "?", tipo: e.eventType || "?", motivo, categoria })
  }
  return resultados
}

// ────────────────────────────────────────────────────────────────
//  ANÁLISIS PRINCIPAL DEL APP PRIVACY REPORT
// ────────────────────────────────────────────────────────────────

async function analizarReporte(entries) {
  let redEntries = entries.filter(e => e.type === "networkActivity")
  let hitsDominio = {}, bundlesPorDominio = {}
  for (let e of redEntries) {
    if (BUNDLES_IGNORADOS.has(e.bundleID)) continue
    let d = e.domain || ""; if (!d) continue
    hitsDominio[d] = (hitsDominio[d] || 0) + (e.hits || 1)
    if (!bundlesPorDominio[d]) bundlesPorDominio[d] = new Set()
    bundlesPorDominio[d].add(e.bundleID || "?")
  }

  let todosDominios = Object.entries(hitsDominio).sort((a,b) => b[1]-a[1]).map(([d]) => d)
  let todosBundles  = new Set()
  for (let e of redEntries) { if (e.bundleID && !BUNDLES_IGNORADOS.has(e.bundleID)) todosBundles.add(e.bundleID) }

  // Clones de FF
  let clonesFF = []
  for (let bid of todosBundles) {
    if (FF_APPS_LEGITIMAS.has(bid)) continue
    let bidL = bid.toLowerCase()
    if (bidL.startsWith("com.dts.freefireth") || bidL.startsWith("com.dts.freefiremax") || (bidL.includes("freefire") && !FF_APPS_LEGITIMAS.has(bid))) {
      let appE = redEntries.filter(e => e.bundleID === bid)
      clonesFF.push({ bundleID: bid, desc: "Copia sospechosa de Free Fire — bundle ID modificado", hits: appE.reduce((s,e) => s+(e.hits||1), 0), dominios: [...new Set(appE.map(e => e.domain).filter(Boolean))] })
    }
  }

  // Apps con cheat detectadas
  let appsCheat = [...clonesFF]
  for (let [bid, desc] of Object.entries(APPS_CHEAT)) {
    if (todosBundles.has(bid)) {
      let appE = redEntries.filter(e => e.bundleID === bid)
      appsCheat.push({ bundleID: bid, desc, hits: appE.reduce((s,e) => s+(e.hits||1), 0), dominios: [...new Set(appE.map(e => e.domain).filter(Boolean))] })
    }
  }

  // Proxy login
  let dominiosLoginFF = new Set()
  for (let e of redEntries) { if (FF_APPS_LEGITIMAS.has(e.bundleID) && DOMINIOS_LOGIN_FF.has((e.domain||"").toLowerCase())) dominiosLoginFF.add((e.domain||"").toLowerCase()) }
  let proxyLoginVisto = {}
  for (let e of redEntries) {
    let d = (e.domain||"").toLowerCase(), bid = e.bundleID||""
    if (!bid || FF_APPS_LEGITIMAS.has(bid) || BUNDLES_IGNORADOS.has(bid) || !DOMINIOS_LOGIN_FF.has(d) || dominiosLoginFF.has(d)) continue
    if (!proxyLoginVisto[d]) proxyLoginVisto[d] = { dominio: e.domain, bundles: new Set(), hits: 0 }
    proxyLoginVisto[d].bundles.add(bid); proxyLoginVisto[d].hits += (e.hits||1)
  }
  let proxyLogin = Object.values(proxyLoginVisto).map(i => ({ dominio: i.dominio, bundles: [...i.bundles], hits: i.hits }))

  // Infra cheat conocida
  let infraDetectada = []
  for (let e of redEntries) {
    let d = (e.domain||"").toLowerCase(), bid = e.bundleID||""
    if (FF_APPS_LEGITIMAS.has(bid) && DOMINIOS_LOGIN_FF.has(d)) continue
    for (let [indicador, desc] of Object.entries(INFRA_CHEAT)) {
      if (d === indicador.toLowerCase() || d.endsWith("."+indicador.toLowerCase())) {
        if (DOMINIOS_LOGIN_FF.has(indicador.toLowerCase()) && FF_APPS_LEGITIMAS.has(bid)) continue
        let ex = infraDetectada.find(k => k.indicador === indicador)
        if (ex) { ex.hits += (e.hits||1); if (bid) ex.bundles.add(bid) }
        else infraDetectada.push({ indicador, desc, hits: e.hits||1, bundles: new Set(bid?[bid]:[]) })
      }
    }
  }
  infraDetectada = infraDetectada.map(k => ({ ...k, bundles: [...k.bundles] }))

  // Dominios externos en tráfico de FF
  let dominiosExternos = [], dominiosCheatFF = []
  let vistosPorFF = new Map()
  for (let e of redEntries) {
    if (!FF_APPS_LEGITIMAS.has(e.bundleID) || !e.domain) continue
    let d = e.domain.toLowerCase().replace(/^www\./, "")
    let cur = vistosPorFF.get(d) || { dominio: e.domain, hits: 0 }
    cur.hits += (e.hits||1); vistosPorFF.set(d, cur)
  }
  for (let [d, info] of vistosPorFF) {
    if (dominioEsLegitimo(d)) continue
    let esCheat = false
    for (let [infra, desc] of Object.entries(INFRA_CHEAT)) {
      if (d === infra || d.endsWith("."+infra)) { dominiosCheatFF.push({ dominio: info.dominio, desc, hits: info.hits }); esCheat = true; break }
    }
    if (!esCheat) dominiosExternos.push({ dominio: info.dominio, hits: info.hits })
  }

  // Apps fantasma
  let porBundle = {}
  for (let e of redEntries) {
    let bid = e.bundleID||"", dom = (e.domain||"").toLowerCase()
    if (!bid || (FF_APPS_LEGITIMAS.has(bid) && DOMINIOS_LOGIN_FF.has(dom))) continue
    let esInfra = Object.keys(INFRA_CHEAT).includes(dom)
    let esTLD   = TLD_SOSPECHOSOS.some(t => dom.endsWith(t))
    if (esInfra || esTLD) {
      if (!porBundle[bid]) porBundle[bid] = { dominios: [], hits: 0 }
      porBundle[bid].dominios.push(e.domain); porBundle[bid].hits += (e.hits||1)
    }
  }
  let appsFantasma = Object.entries(porBundle).map(([bid,info]) => ({ bundleID: bid, dominios: [...new Set(info.dominios)], hits: info.hits }))

  // IP-API batch
  Speech.speak("Analizando red, esperá que RIP PROXY termine.")
  let candidatos = [], CHUNK = 100
  for (let i = 0; i < todosDominios.length; i += CHUNK) {
    let chunk = todosDominios.slice(i, i+CHUNK)
    let resultados = await consultarIPs(chunk)
    if (i + CHUNK >= todosDominios.length / 2) Speech.speak("Escáner al cincuenta por ciento.")
    for (let j = 0; j < resultados.length; j++) {
      let info = resultados[j], dominio = chunk[j]
      let ip = (info && info.query) || dominio
      if (IPS_FALSOS_POSITIVOS.has(ip) || IPS_FALSOS_POSITIVOS.has(dominio)) continue
      let domLow = dominio.toLowerCase()
      let esTLD = TLD_SOSPECHOSOS.some(t => domLow.endsWith(t)) || PALABRAS_SOSPECHOSAS.some(w => domLow.split(".")[0].includes(w))
      let { nivel, motivos } = (info && info.status === "success") ? clasificarIP(info, dominio) : { nivel: null, motivos: [] }
      if (!nivel && esTLD) { nivel = "ALTO"; motivos = ["TLD o dominio sospechoso"] }
      if (!nivel && !esTLD) continue
      candidatos.push({
        nivel, dominio, ip,
        pais:    (info&&info.country)||"?",
        ciudad:  (info&&info.city)||"?",
        isp:     (info&&info.isp)||"?",
        org:     (info&&info.org)||"?",
        asn:     (info&&info.as)||"?",
        hosting: !!(info&&info.hosting),
        proxy:   !!(info&&info.proxy),
        rdns:    (info&&info.reverse)||"",
        hits:    hitsDominio[dominio],
        bundles: [...bundlesPorDominio[dominio]].slice(0, 4),
        motivos, esTLD,
      })
    }
    if (i + CHUNK < todosDominios.length) await esperar(1400)
  }

  // Probe HTTP en paralelo
  Speech.speak("Escáner al noventa por ciento.")
  let probeResultados = await Promise.all(candidatos.map(c => probeHTTP(c.dominio)))
  let hallazgos = candidatos.map((c, idx) => {
    let probe = probeResultados[idx], nivel = c.nivel, motivos = [...c.motivos]
    if (probe) {
      if (probe.sospechoso && probe.banner) { nivel = "ALTO"; motivos.push(`Servidor: ${probe.banner}`) }
      if (probe.estado === 403) motivos.push("HTTP 403 — activo pero bloqueando acceso")
      if (!probe.activo) motivos.push("Sin respuesta HTTP")
    }
    return { ...c, nivel, motivos, probe }
  })

  hallazgos.sort((a,b) => {
    let aT = a.esTLD?0:1, bT = b.esTLD?0:1; if(aT!==bT) return aT-bT
    let aA = (a.asn||"").split(" ")[0].toUpperCase(), bA = (b.asn||"").split(" ")[0].toUpperCase()
    let aK = ASN_SOSPECHOSOS[aA]?0:1, bK = ASN_SOSPECHOSOS[bA]?0:1; if(aK!==bK) return aK-bK
    let nO = {ALTO:0,MEDIO:1}; if(a.nivel!==b.nivel) return nO[a.nivel]-nO[b.nivel]
    return b.hits-a.hits
  })

  return { hallazgos, redEntries, appsCheat, infraDetectada, appsFantasma, proxyLogin, dominiosExternos, dominiosCheatFF }
}

// ────────────────────────────────────────────────────────────────
//  CONSTRUCCIÓN DEL REPORTE
// ────────────────────────────────────────────────────────────────

function construirReporte(tlsResultados, hallazgos, redEntries, appsCheat, infraDetectada, usageHallazgos, ipsMeta, appsFantasma, proxyLogin, dominiosExternos, dominiosCheatFF, nombreArchivo) {

  // Timestamps del reporte
  let timestamps = redEntries.map(e => e.timeStamp).filter(Boolean).sort()
  let tsInicio = timestamps.length ? new Date(timestamps[0]) : null
  let tsFin    = timestamps.length ? new Date(timestamps[timestamps.length-1]) : null

  let duracionStr = "—", alertaDuracion = false
  if (tsInicio && tsFin) {
    let diff = Math.floor((tsFin-tsInicio)/60000)
    let h = Math.floor(diff/60), d = Math.floor(h/24)
    duracionStr = d>0 ? `${d}d ${h%24}h ${diff%60}min` : h>0 ? `${h}h ${diff%60}min` : `${diff} min`
    if (diff < 20) alertaDuracion = true
  }

  let alertaVencido = false, strVencido = ""
  if (tsFin) {
    let diffAhora = Math.floor((new Date()-tsFin)/60000)
    if (diffAhora > 15) { alertaVencido = true; strVencido = diffAhora>=60 ? `${Math.floor(diffAhora/60)}h ${diffAhora%60}min` : `${diffAhora}min` }
  }

  // Conteo de señales para veredicto
  let senales = infraDetectada.length + appsCheat.length + dominiosCheatFF.length
    + proxyLogin.length + tlsResultados.filter(r => r.sospechoso).length
    + (dominiosExternos.length > 0 ? 1 : 0)
    + (usageHallazgos.filter(f => f.categoria === "critico").length > 0 ? 1 : 0)

  let veredicto = senales === 0 ? "LIMPIO" : senales <= 2 ? "SOSPECHOSO" : "CHEAT DETECTADO"
  let colorV    = senales === 0 ? "#00e676" : senales <= 2 ? "#ffab00" : "#ff1744"
  let iconoV    = senales === 0 ? "✅" : senales <= 2 ? "⚠️" : "🚨"

  // Filas TLS
  let filasTLS = tlsResultados.map(r => {
    let color  = !r.alcanzable ? "#666" : r.sospechoso ? "#ff1744" : "#00e676"
    let estado = !r.alcanzable ? "sin acceso" : r.sospechoso ? "sospechoso" : "normal"
    let latTxt = r.latencia !== null ? formatMs(r.latencia) : "—"
    let latColor = r.latencia > LATENCIA_UMBRAL ? "#ffab00" : "#555"
    let detalleDiv = r.motivo ? `<div style="font-size:10px;color:#ff8a65;margin-top:2px;line-height:1.4;">${r.motivo}</div>` : ""
    return `
      <tr>
        <td style="padding:10px 14px;font-size:12px;color:#aaa;border-bottom:1px solid #111;">${r.nombre}</td>
        <td style="padding:10px 14px;border-bottom:1px solid #111;">
          <span style="color:${color};font-size:12px;font-weight:600;">${estado}</span>
          ${detalleDiv}
        </td>
        <td style="padding:10px 14px;font-size:12px;color:${latColor};border-bottom:1px solid #111;text-align:right;">${latTxt}</td>
      </tr>`
  }).join("")

  // Tarjetas de hallazgos críticos
  function tarjetaCritica(icono, etiqueta, titulo, subtitulo, detalle, colorBorde) {
    return `
    <div style="background:#0a0a12;border:1px solid ${colorBorde}33;border-left:3px solid ${colorBorde};border-radius:6px;padding:14px 16px;margin-bottom:10px;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
        <span style="font-size:11px;font-weight:700;color:${colorBorde};text-transform:uppercase;letter-spacing:0.5px;">${icono} ${etiqueta}</span>
      </div>
      <div style="color:#fff;font-size:13px;font-weight:600;margin-bottom:2px;">${titulo}</div>
      ${subtitulo ? `<div style="color:#aaa;font-size:11px;margin-bottom:4px;">${subtitulo}</div>` : ""}
      ${detalle   ? `<div style="color:#666;font-size:10px;">${detalle}</div>` : ""}
    </div>`
  }

  let tarjetasCriticas = ""

  for (let a of appsCheat) {
    tarjetasCriticas += tarjetaCritica("⛔", "App Cheat / Proxy", a.bundleID, a.desc, `${a.hits} conexiones`, "#ff1744")
  }
  for (let k of infraDetectada) {
    tarjetasCriticas += tarjetaCritica("🚨", "Infraestructura Cheat", k.indicador, k.desc, `${k.hits} conexiones · ${k.bundles.join(", ")||"?"}`, "#ff1744")
  }
  for (let d of dominiosCheatFF) {
    tarjetasCriticas += tarjetaCritica("🚨", "Cheat en tráfico de Free Fire", d.dominio, d.desc, `${d.hits} conexiones desde la app`, "#ff1744")
  }
  for (let p of proxyLogin) {
    tarjetasCriticas += tarjetaCritica("⚠️", "Proxy Login", p.dominio, "Dominio de login de FF contactado por app ajena", `${p.hits} hits · ${p.bundles.join(", ")}`, "#ffab00")
  }

  // Sección usage file
  let seccionUsage = ""
  if (usageHallazgos.length > 0) {
    let filas = usageHallazgos.map(f => {
      let color = f.categoria === "critico" ? "#ff1744" : f.categoria === "vpn" ? "#ffab00" : "#888"
      let etiq  = f.categoria === "critico" ? "CRÍTICO" : f.categoria === "vpn" ? "VPN" : "AVISO"
      return `
      <div style="background:#0a0a12;border-left:3px solid ${color};border-radius:4px;padding:10px 14px;margin-bottom:6px;">
        <div style="color:${color};font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:3px;">${etiq}</div>
        <div style="color:#ddd;font-size:12px;font-weight:600;">${f.bundleId}</div>
        <div style="color:#888;font-size:11px;margin-top:2px;">${f.motivo}</div>
      </div>`
    }).join("")
    seccionUsage = `
    <div style="margin-top:28px;">
      <div style="font-size:10px;font-weight:700;color:#555;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;">📲 Apps en Usage File</div>
      ${filas}
    </div>`
  }

  // Certificado raíz
  let alertaCert = ""
  if (ipsMeta && ipsMeta.rootsInstalled > 0) {
    alertaCert = `
    <div style="background:#0a0a12;border:1px solid #e040fb33;border-left:3px solid #e040fb;border-radius:6px;padding:14px 16px;margin-bottom:10px;">
      <div style="color:#e040fb;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">🔐 Certificado Raíz Instalado</div>
      <div style="color:#ddd;font-size:12px;">${ipsMeta.rootsInstalled} certificado${ipsMeta.rootsInstalled>1?"s":""} raíz instalado${ipsMeta.rootsInstalled>1?"s":""}.</div>
      <div style="color:#888;font-size:11px;margin-top:3px;">Los certificados raíz permiten interceptar HTTPS — señal directa de proxy MITM.</div>
    </div>`
  }

  // Dominios externos en tráfico FF
  let seccionDominiosFF = ""
  if (dominiosExternos.length > 0) {
    let filas = dominiosExternos.map(d => `
      <div style="background:#0a0a12;border-left:3px solid #ffab00;border-radius:4px;padding:10px 14px;margin-bottom:6px;">
        <div style="color:#ffab00;font-size:12px;font-weight:600;">${d.dominio}</div>
        <div style="color:#666;font-size:10px;margin-top:2px;">Dominio externo en tráfico de Free Fire · ${d.hits} conexiones</div>
      </div>`).join("")
    seccionDominiosFF = `
    <div style="margin-top:28px;">
      <div style="font-size:10px;font-weight:700;color:#555;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;">⚠️ Dominios Externos en Tráfico de Free Fire</div>
      ${filas}
    </div>`
  }

  // IPs sospechosas
  let seccionIPs = ""
  if (hallazgos.length === 0) {
    seccionIPs = `<div style="background:#0a0a12;border-left:3px solid #00e676;border-radius:4px;padding:12px 14px;color:#00e676;font-size:12px;">Sin IPs de hosting o proxy detectadas.</div>`
  } else {
    let filas = hallazgos.map(h => {
      let color = h.esTLD ? "#ffab00" : h.nivel==="ALTO" ? "#ff1744" : "#ffab00"
      let etiq  = h.esTLD ? "DOMINIO SOSPECHOSO" : h.nivel==="ALTO" ? "SOSPECHOSO" : "POSIBLE"
      return `
      <div style="background:#0a0a12;border-left:3px solid ${color};border-radius:4px;padding:12px 14px;margin-bottom:8px;">
        <div style="color:${color};font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">${etiq}</div>
        <div style="color:#fff;font-size:13px;font-weight:600;">${h.dominio}</div>
        <div style="color:#666;font-size:10px;margin-top:4px;">IP: ${h.ip} · ${h.pais} / ${h.ciudad} · ${h.asn}</div>
        <div style="color:#666;font-size:10px;">ISP: ${h.isp}</div>
        ${h.rdns ? `<div style="color:#666;font-size:10px;">rDNS: ${h.rdns}</div>` : ""}
        <div style="color:#ff8a65;font-size:11px;margin-top:4px;">${h.motivos.join("<br>")}</div>
        <div style="color:#444;font-size:10px;margin-top:4px;">${h.hits} conexiones · ${h.bundles.join(", ")}</div>
      </div>`
    }).join("")
    seccionIPs = filas
  }

  // Apps fantasma
  let seccionFantasma = ""
  if (appsFantasma.length > 0) {
    let filas = appsFantasma.map(a => `
      <div style="background:#0a0a12;border-left:3px solid #555;border-radius:4px;padding:10px 14px;margin-bottom:6px;">
        <div style="color:#aaa;font-size:12px;font-weight:600;">${a.bundleID}</div>
        <div style="color:#555;font-size:10px;margin-top:2px;">${a.dominios.slice(0,4).join(", ")} · ${a.hits} hits</div>
      </div>`).join("")
    seccionFantasma = `
    <div style="margin-top:28px;">
      <div style="font-size:10px;font-weight:700;color:#555;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;">👻 Apps Fantasma</div>
      ${filas}
    </div>`
  }

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
  <title>RIP PROXY</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #06060f;
      color: #e0e0e0;
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
      padding: 0 0 60px 0;
      max-width: 580px;
      margin: 0 auto;
    }
    .header {
      background: linear-gradient(180deg, #0d0d20 0%, #06060f 100%);
      padding: 32px 20px 24px;
      border-bottom: 1px solid #111;
    }
    .contenido { padding: 20px; }
    .seccion { margin-top: 28px; }
    .etiqueta-seccion {
      font-size: 10px; font-weight: 700; color: #444;
      text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 12px;
    }
    table { width: 100%; border-collapse: collapse; }
    th { font-size: 10px; color: #444; font-weight: 600; padding: 8px 14px; text-align: left; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #111; }
    .footer { margin-top: 40px; padding: 16px 20px; border-top: 1px solid #0d0d1a; text-align: center; }
  </style>
</head>
<body>

<!-- ENCABEZADO -->
<div class="header">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
    <div style="width:40px;height:40px;background:linear-gradient(135deg,#6c00ff,#00c4ff);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;">🔍</div>
    <div>
      <div style="font-size:18px;font-weight:800;letter-spacing:1px;color:#fff;">RIP PROXY</div>
      <div style="font-size:10px;color:#444;margin-top:1px;">code by tizi · UNKNOWN Security Team · v${VERSION}</div>
    </div>
  </div>

  <!-- VEREDICTO -->
  <div style="background:#0a0a18;border:1px solid ${colorV}22;border-radius:10px;padding:20px;text-align:center;">
    <div style="font-size:36px;margin-bottom:8px;">${iconoV}</div>
    <div style="font-size:20px;font-weight:800;color:${colorV};letter-spacing:2px;margin-bottom:6px;">${veredicto}</div>
    <div style="font-size:12px;color:#555;">${senales} señal${senales!==1?"es":""} crítica${senales!==1?"s":""} · ${formatFecha(tsInicio)} → ${formatFecha(tsFin)} · ${duracionStr}</div>
    ${alertaDuracion ? `<div style="color:#ffab00;font-size:11px;margin-top:6px;">⚠ Reporte cubre menos de 20 minutos</div>` : ""}
    ${alertaVencido  ? `<div style="color:#ff8a65;font-size:11px;margin-top:4px;">Último registro hace ${strVencido}</div>` : ""}
  </div>
</div>

<div class="contenido">

  <!-- CAPA 1: TLS EN VIVO -->
  <div class="seccion">
    <div class="etiqueta-seccion">🔐 Probe TLS en vivo</div>
    <div style="background:#0a0a12;border-radius:6px;overflow:hidden;">
      <table>
        <thead><tr><th>Endpoint</th><th>Estado</th><th style="text-align:right;">Latencia</th></tr></thead>
        <tbody>${filasTLS}</tbody>
      </table>
    </div>
    <div style="font-size:10px;color:#333;margin-top:6px;padding:0 2px;">Umbral de latencia: ${LATENCIA_UMBRAL}ms · Los proxies MITM generan overhead de red consistente en todos los endpoints</div>
  </div>

  <!-- ALERTAS DE CERTIFICADO -->
  ${alertaCert ? `<div class="seccion"><div class="etiqueta-seccion">🔐 Certificados</div>${alertaCert}</div>` : ""}

  <!-- HALLAZGOS CRÍTICOS -->
  ${tarjetasCriticas ? `<div class="seccion"><div class="etiqueta-seccion">🚨 Detecciones Críticas</div>${tarjetasCriticas}</div>` : ""}

  <!-- USAGE FILE -->
  ${seccionUsage}

  <!-- IPs Y ASN -->
  <div class="seccion">
    <div class="etiqueta-seccion">🌐 IPs / ASN / Hosting</div>
    ${seccionIPs}
  </div>

  <!-- DOMINIOS EXTERNOS FF -->
  ${seccionDominiosFF}

  <!-- APPS FANTASMA -->
  ${seccionFantasma}

  <!-- COBERTURA -->
  <div style="margin-top:32px;background:#0a0a12;border-radius:6px;padding:16px;">
    <div style="font-size:10px;font-weight:700;color:#6c00ff;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;">Capas de detección activas</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px 12px;">
      ${[
        "Probe TLS en vivo","Headers de proxy","Latencia anómala (MITM)",
        "ASN / VPS / Hosting","rDNS de servidores","Banners HTTP sospechosos",
        "Bundle IDs cheat/JB/sideload","Infra iOS confirmada","Proxy Login FF",
        "Dominios externos en FF","Apps fantasma","Certificados raíz",
        "TLD y palabras clave","Clones de Free Fire"
      ].map(c => `<div style="font-size:10px;color:#333;padding:2px 0;">✓ ${c}</div>`).join("")}
    </div>
  </div>

</div>

<div class="footer">
  <div style="color:#222;font-size:10px;">RIP PROXY v${VERSION} · code by tizi · UNKNOWN Security Team</div>
  <div style="color:#1a1a2e;font-size:9px;margin-top:3px;">${nombreArchivo}</div>
</div>

</body>
</html>`
}

// ────────────────────────────────────────────────────────────────
//  MAIN
// ────────────────────────────────────────────────────────────────

async function main() {

  let alertaBienvenida = new Alert()
  alertaBienvenida.title   = "RIP PROXY v3.0"
  alertaBienvenida.message = "Scanner Anti-Cheat iOS para Free Fire\ncode by tizi · UNKNOWN Security Team\n\nNecesitás el App Privacy Report exportado desde:\nConfiguración → Privacidad → Informe de privacidad de apps → Exportar\n\nEl archivo Usage (.ips) es opcional."
  alertaBienvenida.addAction("Seleccionar archivos")
  alertaBienvenida.addCancelAction("Cancelar")
  if (await alertaBienvenida.present() === -1) { Script.complete(); return }

  // Archivo 1
  let a1 = new Alert(); a1.title = "Archivo 1 — Obligatorio"; a1.message = "Seleccioná el App_Privacy_Report.ndjson"; a1.addAction("Seleccionar"); a1.addCancelAction("Cancelar")
  if (await a1.present() === -1) { Script.complete(); return }
  let ruta1 = await DocumentPicker.openFile()
  if (!ruta1) { Script.complete(); return }
  let contenido1 = await leerArchivo(ruta1)
  if (!contenido1) { let a = new Alert(); a.title = "Error"; a.message = "No se pudo leer el archivo."; a.addAction("OK"); await a.present(); return }

  // Archivo 2 (opcional)
  let a2 = new Alert(); a2.title = "Archivo 2 — Opcional"; a2.message = "Seleccioná el xp_amp_app_usage_dnu*.ips para análisis completo."; a2.addAction("Seleccionar"); a2.addCancelAction("Saltear")
  let ruta2 = null, contenido2 = null
  if (await a2.present() !== -1) {
    ruta2 = await DocumentPicker.openFile()
    if (ruta2) contenido2 = await leerArchivo(ruta2)
  }

  // Clasificar archivos
  function clasificar(c, r) {
    if (esReportePrivacidad(c)) return "ndjson"
    if (esArchivoUsage(c))     return "ips"
    let n = (r||"").split("/").pop().toLowerCase()
    if (n.endsWith(".ndjson") || n.includes("privacy")) return "ndjson"
    if (n.endsWith(".ips") || n.includes("xp_amp"))     return "ips"
    return "desconocido"
  }

  let tipo1 = clasificar(contenido1, ruta1)
  let tipo2 = contenido2 ? clasificar(contenido2, ruta2) : null
  let contenidoNdjson = null, rutaNdjson = null, contenidoIps = null

  if (tipo1 === "ndjson") { contenidoNdjson = contenido1; rutaNdjson = ruta1; contenidoIps = contenido2 }
  else if (tipo1 === "ips") { contenidoIps = contenido1; contenidoNdjson = contenido2; rutaNdjson = ruta2 }
  else { let a = new Alert(); a.title = "Archivo no reconocido"; a.message = "Verificá que seleccionaste el App_Privacy_Report.ndjson correcto."; a.addAction("OK"); await a.present(); return }

  if (!contenidoNdjson) { let a = new Alert(); a.title = "Reporte ausente"; a.message = "El App Privacy Report (.ndjson) es obligatorio.\n\nConfiguración → Privacidad → Informe de privacidad de apps → Exportar"; a.addAction("OK"); await a.present(); return }

  let entradas = parsearNdjson(contenidoNdjson)
  if (!entradas || entradas.length === 0) { let a = new Alert(); a.title = "Archivo inválido"; a.message = "El App Privacy Report no contiene entradas válidas."; a.addAction("OK"); await a.present(); return }

  // Analizar usage file
  let usageHallazgos = [], ipsMeta = { rootsInstalled: 0, iosVersion: null }
  if (contenidoIps) {
    let parsed = parsearIps(contenidoIps)
    usageHallazgos = analizarUsageFile(parsed)
    if (parsed.header) {
      let osMatch = (parsed.header.os_version || "").match(/iPhone OS ([\d.]+)/)
      ipsMeta.iosVersion     = osMatch ? osMatch[1] : parsed.header.os_version || null
      ipsMeta.rootsInstalled = parsed.header.roots_installed || 0
    }
  }

  // Probe TLS en paralelo
  let tlsResultados = await Promise.all(ENDPOINTS_GARENA.map(ep => probeTLS(ep)))

  // Análisis del reporte
  let { hallazgos, redEntries, appsCheat, infraDetectada, appsFantasma, proxyLogin, dominiosExternos, dominiosCheatFF } = await analizarReporte(entradas)

  let nombreArchivo = (rutaNdjson || "archivo").split("/").pop()
  Speech.speak("RIP PROXY finalizado. Revisá los resultados.")

  // Construir y mostrar reporte
  let html = construirReporte(tlsResultados, hallazgos, redEntries, appsCheat, infraDetectada, usageHallazgos, ipsMeta, appsFantasma, proxyLogin, dominiosExternos, dominiosCheatFF, nombreArchivo)

  let wv = new WebView()
  await wv.loadHTML(html)
  await wv.present(false)

  Script.complete()
}

main()

