// ============================================================
//  RIP PROXY — Detector de MITM por comportamiento TLS
//  code by tizi | v1.0
// ============================================================
//
//  Este scanner NO usa listas de IPs ni hostings conocidos.
//  Detecta el cheat analizando el COMPORTAMIENTO REAL de la
//  conexión TLS y las conexiones que Free Fire hace en el
//  dispositivo — técnica que no puede ser evadida simplemente
//  cambiando de servidor.
//
//  MÓDULOS:
//   1. PROBE TLS EN VIVO   — detecta headers de proxy en respuestas de Garena
//   2. ANÁLISIS DE LATENCIA — overhead anómalo = proxy intermedio
//   3. ANÁLISIS DE REPORTE  — dominios anómalos en tráfico de Free Fire
//
//  USO:
//   • Para módulo 3: exportar App Privacy Report desde
//     Ajustes → Privacidad → Informe de privacidad de apps → Exportar
// ============================================================

// ─────────────────────────────────────────────────────────────
//  CONFIGURACIÓN
// ─────────────────────────────────────────────────────────────

const VERSION       = "1.0"
const TIMEOUT_MS    = 8000
const LATENCIA_UMBRAL_MS = 600  // más de esto = overhead sospechoso de proxy

// Endpoints legítimos de Garena para el probe TLS
const PROBE_ENDPOINTS = [
  { url: "https://gin.freefiremobile.com",          nombre: "FF Login (gin)"       },
  { url: "https://client.sea.freefiremobile.com",   nombre: "FF Client SEA"        },
  { url: "https://client.us.freefiremobile.com",    nombre: "FF Client US"         },
  { url: "https://sacnetwork.ggblueshark.com",       nombre: "Garena SAC Network"   },
]

// Headers que mitmproxy y proxies similares típicamente inyectan
const HEADERS_PROXY_SOSPECHOSOS = [
  "via",
  "x-forwarded-for",
  "x-forwarded-proto",
  "x-real-ip",
  "proxy-connection",
  "x-mitm-proxy",
  "x-proxy-id",
  "forwarded",
  "x-cache",
  "x-served-by",
  "x-request-id",
]

// Dominios 100% legítimos de Free Fire / Garena
// Cualquier dominio fuera de este set contactado por las apps de FF = señal de proxy
const FF_DOMINIOS_LEGITIMOS = new Set([
  // Garena core
  "garena.com", "garena.com.sg", "garena.tw", "garena.vn",
  "garenagames.com",
  // Free Fire mobile
  "freefiremobile.com",
  "freefireth.com",
  // CDN y servidores de juego
  "ggblueshark.com",
  "ggpolarbear.com",
  "ggwhitehawk.com",
  "ggraven.com",
  "ggvenom.com",
  "ggflamingo.com",
  // APIs y servicios Garena
  "msdk.garena.com",
  "connect.garena.com",
  "sdk.garena.com",
  "store.garena.com",
  // CDN oficiales
  "akamaized.net",
  "akamai.net",
  "akamaistream.net",
  "cloudfront.net",
  "fastly.net",
  // Apple / iOS (legítimos)
  "apple.com",
  "icloud.com",
  "mzstatic.com",
  "crashlytics.com",
  "firebase.com",
  "firebaseio.com",
  "googleapis.com",
  "gstatic.com",
  "amplitude.com",
  "appsflyer.com",
  "adjust.com",
  "facebook.com",
  "fbcdn.net",
])

// Bundle IDs de Free Fire
const FF_BUNDLE_IDS = new Set([
  "com.dts.freefireth",
  "com.dts.freefiremax",
])

// Infraestructura de cheats conocida (complementario, no principal)
const INFRA_CHEAT_CONOCIDA = {
  "46.202.145.85":             "Fatality Cheats — servidor confirmado",
  "fatalitycheats.xyz":        "Fatality Cheats — dominio confirmado",
  "anubisw.online":            "Servidor de cheat confirmado",
  "api.baontq.xyz":            "API de cheat confirmado",
  "authtool.app":              "Plataforma de distribución de cheats iOS",
  "ipa.authtool.app":          "Servidor IPA de cheats iOS",
  "proxy.builders":            "Proxy Team — sitio de cheat iOS confirmado",
  "filespace.es":              "Distribución de cheats iOS",
  "version.ffmax.purplevioleto.com": "Free Fire MAX modificado — cheat",
  "version.ggwhitehawk.com":         "White Hawk cheat — confirmado",
  "loginbp.ggpolarbear.com":         "Polar Bear cheat — confirmado",
}

// ─────────────────────────────────────────────────────────────
//  UTILIDADES
// ─────────────────────────────────────────────────────────────

function extraerDominio(dominio) {
  if (!dominio) return ""
  return dominio.toLowerCase().replace(/^www\./, "")
}

function esDominioLegitimo(dominio) {
  let d = extraerDominio(dominio)
  if (FF_DOMINIOS_LEGITIMOS.has(d)) return true
  for (let legit of FF_DOMINIOS_LEGITIMOS) {
    if (d.endsWith("." + legit) || d === legit) return true
  }
  return false
}

function formatearLatencia(ms) {
  if (ms < 1000) return ms + "ms"
  return (ms / 1000).toFixed(1) + "s"
}

async function leerArchivo(path) {
  try {
    let fm = FileManager.local()
    return fm.readString(path)
  } catch(e) {
    try {
      let fm = FileManager.iCloud()
      return fm.readString(path)
    } catch(e2) {
      return null
    }
  }
}

function parsearNdjson(contenido) {
  let limpio = contenido.trim()
  if (limpio.startsWith("[")) {
    try { return JSON.parse(limpio) } catch(e) {}
  }
  return limpio
    .split("\n")
    .map(l => l.trim())
    .filter(l => l.length > 0)
    .map(l => { try { return JSON.parse(l) } catch(e) { return null } })
    .filter(Boolean)
}

// ─────────────────────────────────────────────────────────────
//  MÓDULO 1 — PROBE TLS EN VIVO
// ─────────────────────────────────────────────────────────────
//
//  Hace un request a cada endpoint de Garena y analiza:
//  • Headers de proxy inyectados por mitmproxy
//  • Header "server" inusual (mitmproxy lo reemplaza)
//  • Ausencia de headers de seguridad que Garena siempre envía
//  • Presencia de headers propios del proxy
// ─────────────────────────────────────────────────────────────

async function probeTLS(endpoint) {
  let resultado = {
    url:           endpoint.url,
    nombre:        endpoint.nombre,
    alcanzable:    false,
    latencia_ms:   null,
    headers_proxy: [],
    server_header: null,
    hsts:          null,
    sospechoso:    false,
    motivo:        null,
  }

  try {
    let req = new Request(endpoint.url)
    req.timeoutInterval = TIMEOUT_MS / 1000
    req.method = "HEAD"

    // Headers para simular cliente iOS legítimo
    req.headers = {
      "User-Agent":      "FreeFire/1.0 CFNetwork/1492.0.1 Darwin/23.0.0",
      "Accept":          "*/*",
      "Accept-Language": "es-AR,es;q=0.9",
      "Connection":      "keep-alive",
    }

    let inicio = Date.now()
    try { await req.load() } catch(e) {}
    let fin    = Date.now()

    resultado.latencia_ms   = fin - inicio
    resultado.alcanzable    = true
    resultado.server_header = (req.response && req.response.headers) ? req.response.headers["server"] || req.response.headers["Server"] || null : null
    resultado.hsts          = (req.response && req.response.headers) ? req.response.headers["strict-transport-security"] || req.response.headers["Strict-Transport-Security"] || null : null

    if (req.response && req.response.headers) {
      let hdrs = req.response.headers
      for (let h of HEADERS_PROXY_SOSPECHOSOS) {
        // Buscar el header en forma case-insensitive
        let valor = hdrs[h] || hdrs[h.toLowerCase()] || hdrs[h.toUpperCase()] ||
                    Object.keys(hdrs).find(k => k.toLowerCase() === h.toLowerCase())
        if (valor && typeof valor === "string") {
          resultado.headers_proxy.push({ header: h, valor: typeof valor === "string" ? valor : "presente" })
        }
      }
    }

    // Análisis de sospecha
    let motivos = []

    if (resultado.headers_proxy.length > 0) {
      motivos.push("Headers de proxy detectados: " + resultado.headers_proxy.map(h => h.header).join(", "))
    }

    if (resultado.latencia_ms > LATENCIA_UMBRAL_MS) {
      motivos.push("Latencia anómala: " + formatearLatencia(resultado.latencia_ms) + " (overhead de proxy sospechoso)")
    }

    // mitmproxy típicamente se identifica como "mitmdump" o cambia el header server
    if (resultado.server_header) {
      let sv = resultado.server_header.toLowerCase()
      if (sv.includes("mitm") || sv.includes("proxy") || sv.includes("nginx") || sv.includes("apache")) {
        motivos.push("Header 'server' inusual para Garena: " + resultado.server_header)
      }
    }

    // Ausencia de HSTS en endpoints que siempre lo envían
    if (!resultado.hsts) {
      motivos.push("HSTS ausente — posible stripping por proxy")
    }

    if (motivos.length > 0) {
      resultado.sospechoso = true
      resultado.motivo     = motivos.join(" | ")
    }

  } catch(e) {
    resultado.alcanzable = false
    resultado.motivo     = "No alcanzable: " + String(e)
  }

  return resultado
}

// ─────────────────────────────────────────────────────────────
//  MÓDULO 2 — ANÁLISIS DE LATENCIA COMPARATIVA
// ─────────────────────────────────────────────────────────────
//
//  Un proxy MITM activo siempre agrega latencia porque el
//  tráfico viaja: dispositivo → servidor proxy → Garena → proxy → dispositivo
//  En lugar de:             dispositivo → Garena → dispositivo
//
//  Si la latencia promedio a endpoints de Garena supera el umbral
//  Y hay consistencia entre todos los endpoints (todos lentos),
//  es una señal fuerte de proxy intermedio.
// ─────────────────────────────────────────────────────────────

function analizarLatencias(resultadosTLS) {
  let medibles = resultadosTLS.filter(r => r.alcanzable && r.latencia_ms !== null)
  if (medibles.length === 0) return { sospechoso: false, promedio: null, detalle: "No hay endpoints alcanzables" }

  let promedio = Math.round(medibles.reduce((s, r) => s + r.latencia_ms, 0) / medibles.length)
  let todosAltos = medibles.every(r => r.latencia_ms > LATENCIA_UMBRAL_MS)
  let algunoAlto = medibles.some(r => r.latencia_ms > LATENCIA_UMBRAL_MS)

  return {
    sospechoso: todosAltos,
    promedio:   promedio,
    detalle:    todosAltos
      ? "Todos los endpoints con latencia elevada (" + formatearLatencia(promedio) + " promedio) — indicativo de proxy intermedio"
      : algunoAlto
        ? "Latencia mixta — algunos endpoints lentos"
        : "Latencia normal (" + formatearLatencia(promedio) + " promedio)"
  }
}

// ─────────────────────────────────────────────────────────────
//  MÓDULO 3 — ANÁLISIS DEL APP PRIVACY REPORT
// ─────────────────────────────────────────────────────────────
//
//  Lee el reporte de privacidad de apps (.ndjson) y filtra
//  las entradas de actividad de red de Free Fire.
//
//  LÓGICA CENTRAL: Free Fire SOLO debería conectarse a dominios
//  de Garena. Si el reporte muestra conexiones desde Free Fire
//  a dominios externos desconocidos, esos dominios son el
//  servidor del proxy o la infraestructura del cheat.
//
//  Esta técnica es agnóstica al servidor: no importa quién
//  opera el proxy ni desde qué IP — cualquier dominio no-Garena
//  en el tráfico de Free Fire es evidencia directa del cheat.
// ─────────────────────────────────────────────────────────────

function analizarReportePrivacidad(entries) {
  let resultados = {
    dominiosAnomalos:    [],
    infraCheatConocida:  [],
    totalConexionesFF:   0,
    dominiosLegitimos:   [],
    sospechoso:          false,
  }

  // Filtrar entradas de red de Free Fire
  let conexionesFF = entries.filter(e =>
    e.type === "networkActivity" &&
    e.bundleID && FF_BUNDLE_IDS.has(e.bundleID) &&
    e.domain
  )

  resultados.totalConexionesFF = conexionesFF.length

  if (conexionesFF.length === 0) return resultados

  let dominiosVistos = new Map()

  for (let conexion of conexionesFF) {
    let dominio = extraerDominio(conexion.domain)
    if (!dominio) continue

    let hits = conexion.hits || 1
    let actual = dominiosVistos.get(dominio) || { dominio, hits: 0, timestamps: [] }
    actual.hits += hits
    if (conexion.timeStamp) actual.timestamps.push(conexion.timeStamp)
    dominiosVistos.set(dominio, actual)
  }

  for (let [dominio, info] of dominiosVistos) {
    let esLegitimo = esDominioLegitimo(dominio)

    if (esLegitimo) {
      resultados.dominiosLegitimos.push(dominio)
      continue
    }

    // Verificar si es infraestructura de cheat conocida
    let esCheatConocido = false
    for (let [infra, descripcion] of Object.entries(INFRA_CHEAT_CONOCIDA)) {
      if (dominio === infra || dominio.endsWith("." + infra)) {
        resultados.infraCheatConocida.push({
          dominio,
          descripcion,
          hits:       info.hits,
          ultimaVez:  info.timestamps.sort().pop() || "desconocido",
        })
        esCheatConocido = true
        break
      }
    }

    if (!esCheatConocido) {
      resultados.dominiosAnomalos.push({
        dominio,
        hits:      info.hits,
        ultimaVez: info.timestamps.sort().pop() || "desconocido",
        motivo:    "Dominio externo contactado por Free Fire — posible servidor de proxy/cheat",
      })
    }
  }

  resultados.sospechoso = resultados.dominiosAnomalos.length > 0 ||
                          resultados.infraCheatConocida.length > 0

  return resultados
}

// ─────────────────────────────────────────────────────────────
//  CONSTRUCCIÓN DEL REPORTE HTML
// ─────────────────────────────────────────────────────────────

function construirHTML(resultadosTLS, analisisLatencia, analisisReporte, tieneReporte) {

  // Determinar veredicto general
  let señalesPositivas = 0
  let señalesTotal     = 0

  // Señales TLS
  let tlsSospechosos = resultadosTLS.filter(r => r.sospechoso).length
  señalesTotal += resultadosTLS.filter(r => r.alcanzable).length
  señalesPositivas += tlsSospechosos

  // Señal de latencia
  señalesTotal += 1
  if (analisisLatencia.sospechoso) señalesPositivas += 1

  // Señales del reporte
  if (tieneReporte) {
    señalesTotal += 1
    if (analisisReporte.sospechoso) señalesPositivas += 1
  }

  let nivelRiesgo   = "LIMPIO"
  let colorRiesgo   = "#00c853"
  let iconoRiesgo   = "✅"
  let mensajeRiesgo = "No se detectaron señales de proxy MITM activo."

  if (señalesPositivas === 1) {
    nivelRiesgo   = "SOSPECHOSO"
    colorRiesgo   = "#ff9800"
    iconoRiesgo   = "⚠️"
    mensajeRiesgo = "Una señal positiva detectada. Puede ser un falso positivo — revisá los detalles."
  } else if (señalesPositivas >= 2) {
    nivelRiesgo   = "PROXY DETECTADO"
    colorRiesgo   = "#f44336"
    iconoRiesgo   = "🚨"
    mensajeRiesgo = "Múltiples señales positivas. Alta probabilidad de proxy MITM activo."
  }

  // Construir filas de la tabla TLS
  let filasTLS = resultadosTLS.map(r => {
    let estado  = !r.alcanzable ? "⛔ Sin acceso" :
                  r.sospechoso  ? "🚨 Sospechoso" : "✅ Normal"
    let color   = !r.alcanzable ? "#888" :
                  r.sospechoso  ? "#f44336" : "#00c853"
    let latTxt  = r.latencia_ms !== null ? formatearLatencia(r.latencia_ms) : "—"
    let motivoTxt = r.motivo ? `<div style="font-size:11px;color:#ff8a65;margin-top:4px;">${r.motivo}</div>` : ""
    return `
      <tr>
        <td style="padding:8px 12px;font-size:12px;color:#ccc;">${r.nombre}</td>
        <td style="padding:8px 12px;font-size:12px;color:${color};">${estado}${motivoTxt}</td>
        <td style="padding:8px 12px;font-size:12px;color:${r.latencia_ms > LATENCIA_UMBRAL_MS ? "#ff9800" : "#aaa"};">${latTxt}</td>
      </tr>`
  }).join("")

  // Construir sección de dominios anómalos
  let seccionDominios = ""
  if (tieneReporte) {
    if (analisisReporte.infraCheatConocida.length > 0) {
      let filas = analisisReporte.infraCheatConocida.map(d => `
        <div style="background:#3b0000;border-left:3px solid #f44336;border-radius:4px;padding:10px 12px;margin-bottom:8px;">
          <div style="color:#ff5252;font-size:13px;font-weight:bold;">${d.dominio}</div>
          <div style="color:#ff8a65;font-size:11px;margin-top:3px;">${d.descripcion}</div>
          <div style="color:#888;font-size:10px;margin-top:3px;">Conexiones: ${d.hits} · Última vez: ${d.ultimaVez.slice(0,19).replace("T"," ")}</div>
        </div>`).join("")
      seccionDominios += `
        <h3 style="color:#ff5252;margin:20px 0 10px;">🚨 Infraestructura de cheat conocida detectada en tráfico de Free Fire</h3>
        ${filas}`
    }

    if (analisisReporte.dominiosAnomalos.length > 0) {
      let filas = analisisReporte.dominiosAnomalos.map(d => `
        <div style="background:#1a1a00;border-left:3px solid #ff9800;border-radius:4px;padding:10px 12px;margin-bottom:8px;">
          <div style="color:#ffd740;font-size:13px;font-weight:bold;">${d.dominio}</div>
          <div style="color:#ffab40;font-size:11px;margin-top:3px;">${d.motivo}</div>
          <div style="color:#888;font-size:10px;margin-top:3px;">Conexiones: ${d.hits} · Última vez: ${d.ultimaVez.slice(0,19).replace("T"," ")}</div>
        </div>`).join("")
      seccionDominios += `
        <h3 style="color:#ffd740;margin:20px 0 10px;">⚠️ Dominios desconocidos en tráfico de Free Fire</h3>
        ${filas}`
    }

    if (!analisisReporte.sospechoso) {
      seccionDominios = `
        <div style="background:#0a1f0a;border-left:3px solid #00c853;border-radius:4px;padding:12px;margin-top:12px;">
          <span style="color:#00c853;">✅ Free Fire solo contactó dominios legítimos de Garena (${analisisReporte.dominiosLegitimos.length} dominios verificados)</span>
        </div>`
    }
  } else {
    seccionDominios = `
      <div style="background:#1a1a2e;border-left:3px solid #555;border-radius:4px;padding:12px;margin-top:12px;">
        <span style="color:#888;">ℹ️ No se analizó App Privacy Report. Para análisis completo, exportá el reporte desde Ajustes → Privacidad → Informe de privacidad de apps → Exportar y ejecutá el scanner nuevamente seleccionando el archivo.</span>
      </div>`
  }

  let fechaHora = new Date().toLocaleString("es-AR")

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
  <title>RIP PROXY</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #0d0d1a;
      color: #e0e0e0;
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", sans-serif;
      padding: 20px 16px 40px;
      max-width: 600px;
      margin: 0 auto;
    }
    h1 { font-size: 24px; font-weight: 800; letter-spacing: 2px; }
    h2 { font-size: 15px; font-weight: 600; color: #aaa; margin: 24px 0 12px; text-transform: uppercase; letter-spacing: 1px; }
    h3 { font-size: 13px; font-weight: 600; }
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; font-size: 11px; color: #666; font-weight: 500; padding: 6px 12px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #1e1e2e; }
    tr:nth-child(even) td { background: #0f0f1f; }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
    }
  </style>
</head>
<body>

  <!-- ENCABEZADO -->
  <div style="text-align:center;margin-bottom:24px;">
    <div style="font-size:36px;margin-bottom:6px;">🔍</div>
    <h1 style="color:#7c4dff;">RIP PROXY</h1>
    <div style="color:#555;font-size:11px;margin-top:4px;">Detector de MITM · code by tizi · v${VERSION}</div>
    <div style="color:#444;font-size:10px;margin-top:2px;">${fechaHora}</div>
  </div>

  <!-- VEREDICTO GENERAL -->
  <div style="background:#111124;border:2px solid ${colorRiesgo};border-radius:12px;padding:20px;text-align:center;margin-bottom:24px;">
    <div style="font-size:40px;margin-bottom:8px;">${iconoRiesgo}</div>
    <div style="font-size:22px;font-weight:800;color:${colorRiesgo};letter-spacing:2px;">${nivelRiesgo}</div>
    <div style="color:#aaa;font-size:13px;margin-top:8px;">${mensajeRiesgo}</div>
    <div style="margin-top:12px;">
      <span class="badge" style="background:${colorRiesgo}22;color:${colorRiesgo};">
        ${señalesPositivas} de ${señalesTotal} señales positivas
      </span>
    </div>
  </div>

  <!-- MÓDULO 1: PROBE TLS -->
  <h2>🔐 Probe TLS en vivo</h2>
  <div style="background:#111124;border-radius:8px;overflow:hidden;margin-bottom:8px;">
    <table>
      <thead>
        <tr>
          <th>Endpoint</th>
          <th>Estado</th>
          <th>Latencia</th>
        </tr>
      </thead>
      <tbody>
        ${filasTLS}
      </tbody>
    </table>
  </div>
  <div style="font-size:10px;color:#555;margin-bottom:24px;">
    Umbral de latencia: ${LATENCIA_UMBRAL_MS}ms · Los proxies MITM agregan overhead de red consistente en todos los endpoints
  </div>

  <!-- MÓDULO 2: LATENCIA -->
  <h2>⏱ Análisis de latencia</h2>
  <div style="background:#111124;border-radius:8px;padding:14px;margin-bottom:24px;">
    <div style="color:${analisisLatencia.sospechoso ? "#f44336" : "#00c853"};font-size:13px;">
      ${analisisLatencia.sospechoso ? "🚨" : "✅"} ${analisisLatencia.detalle}
    </div>
    ${analisisLatencia.promedio !== null ? `<div style="color:#555;font-size:11px;margin-top:6px;">Latencia promedio: ${formatearLatencia(analisisLatencia.promedio)}</div>` : ""}
  </div>

  <!-- MÓDULO 3: APP PRIVACY REPORT -->
  <h2>📊 Análisis de tráfico de Free Fire</h2>
  ${seccionDominios}

  <!-- EXPLICACIÓN TÉCNICA -->
  <div style="background:#0d0d1a;border:1px solid #1e1e2e;border-radius:8px;padding:16px;margin-top:28px;">
    <div style="color:#7c4dff;font-size:12px;font-weight:700;margin-bottom:8px;">¿Por qué este método no puede ser evadido?</div>
    <div style="color:#666;font-size:11px;line-height:1.6;">
      Los scanners basados en IPs o hostings conocidos fallan porque el atacante simplemente cambia de servidor.
      RIP PROXY analiza el COMPORTAMIENTO de la conexión: si un proxy MITM está activo,
      físicamente tiene que interceptar el tráfico TLS e inyectar sus propios headers.
      Eso es detectable sin importar quién opera el servidor ni desde qué IP corre.
      El análisis del App Privacy Report detecta además los dominios reales a los que
      Free Fire se conecta — incluyendo el servidor del proxy que no puede ocultarse
      del sistema operativo iOS.
    </div>
  </div>

  <div style="text-align:center;margin-top:28px;color:#333;font-size:10px;">
    RIP PROXY v${VERSION} · code by tizi · UNKNOWN Security Team
  </div>

</body>
</html>`
}

// ─────────────────────────────────────────────────────────────
//  FUNCIÓN PRINCIPAL
// ─────────────────────────────────────────────────────────────

async function main() {

  // Bienvenida
  let alertaInicio = new Alert()
  alertaInicio.title   = "🔍 RIP PROXY"
  alertaInicio.message = "Detector de proxy MITM para Free Fire\ncode by tizi · v" + VERSION + "\n\n¿Querés incluir análisis del App Privacy Report?\n(Configuración → Privacidad → Informe de privacidad de apps → Exportar)"
  alertaInicio.addAction("Sí, seleccionar reporte")
  alertaInicio.addAction("No, solo probe en vivo")
  alertaInicio.addCancelAction("Cancelar")

  let opcion = await alertaInicio.present()
  if (opcion === -1) { Script.complete(); return }

  let tieneReporte    = false
  let analisisReporte = { sospechoso: false, dominiosAnomalos: [], infraCheatConocida: [], totalConexionesFF: 0, dominiosLegitimos: [] }

  // Cargar reporte de privacidad si el usuario lo seleccionó
  if (opcion === 0) {
    let path = await DocumentPicker.openFile()
    if (path) {
      let contenido = await leerArchivo(path)
      if (contenido) {
        let entries = parsearNdjson(contenido)
        if (entries && entries.length > 0) {
          analisisReporte = analizarReportePrivacidad(entries)
          tieneReporte    = true
        } else {
          let a = new Alert()
          a.title   = "Archivo no válido"
          a.message = "No se pudo leer el App Privacy Report.\nVerificá que exportaste el archivo correcto."
          a.addAction("Continuar de todos modos")
          await a.present()
        }
      }
    }
  }

  // Mostrar progreso
  let alertaProgreso = new Alert()
  alertaProgreso.title   = "🔍 Analizando..."
  alertaProgreso.message = "Ejecutando probe TLS en vivo contra servidores de Garena.\nEsto puede tardar unos segundos."
  alertaProgreso.addAction("OK")

  // No esperamos — continuamos inmediatamente
  Speech.speak("Analizando, esperá que RIP PROXY termine.")

  // Ejecutar probes TLS en paralelo
  let resultadosTLS = await Promise.all(
    PROBE_ENDPOINTS.map(e => probeTLS(e))
  )

  // Analizar latencias
  let analisisLatencia = analizarLatencias(resultadosTLS)

  // Construir reporte HTML
  let html = construirHTML(resultadosTLS, analisisLatencia, analisisReporte, tieneReporte)

  // Mostrar resultado
  let wv = new WebView()
  await wv.loadHTML(html)
  await wv.present(false)

  Speech.speak("RIP PROXY finalizado. Analizá los resultados.")
  Script.complete()
}

main()
