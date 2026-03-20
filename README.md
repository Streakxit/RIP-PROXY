<div id="top">

<p align="center">
  <em>Desarrollado para la comunidad competitiva de Free Fire, por TIZI.XIT · UNKNOWN Security Team.</em>
</p>

</div>

<img src="https://i.imgur.com/NnWf7Fm.png" alt="line break" width="100%" height="3px">

## Introducción

RIP PROXY es un scanner anti-cheat para dispositivos **iOS** diseñado específicamente para detectar cheats de tipo proxy MITM en Free Fire. A diferencia de otras herramientas que dependen de listas estáticas de IPs y servidores conocidos, RIP PROXY combina análisis de comportamiento TLS en tiempo real con múltiples capas de inspección forense del dispositivo, lo que dificulta significativamente su evasión.

**¿Por qué RIP PROXY?**

* **🔴 Detección por comportamiento:** Analiza cómo se comportan las conexiones TLS en vivo contra los servidores reales de Garena, detectando anomalías que revelan la presencia de un proxy intermedio independientemente de qué servidor lo opere.
* **⚫️ 14 capas de detección:** Combina probe TLS, análisis de ASN/VPS, bundle IDs sospechosos, infraestructura de cheats confirmada, análisis de tráfico de Free Fire, certificados raíz y más.
* **🟣 App Privacy Report:** Lee directamente qué dominios contactó Free Fire según el sistema operativo iOS — información que el cheat no puede ocultar ni falsificar.

<img src="https://i.imgur.com/NnWf7Fm.png" alt="line break" width="100%" height="3px">

## ¿Cómo usar?

#### <img width="2%" src="https://simpleicons.org/icons/apple.svg">&emsp13; Paso 1 — Instalá Scriptable:

| Aplicación | Descripción |
|---|---|
| [Scriptable](https://apps.apple.com/app/scriptable/id1405459188) | App gratuita para automatización iOS con JavaScript |

#### <img width="2%" src="https://simpleicons.org/icons/apple.svg">&emsp13; Paso 2 — Exportá el Informe de Privacidad del iPhone:

Ir a **Configuración → Privacidad y seguridad → Informe de privacidad de apps → Exportar informe de privacidad de apps**

El archivo se guarda en formato `App_Privacy_Report_v4_YYYY-MM-DD...` en iCloud Drive o en la app Archivos. Este archivo es **obligatorio** para ejecutar el scanner.

Opcionalmente, también podés exportar el archivo de uso de apps desde **Configuración → Privacidad → Análisis y mejoras → Datos de análisis**, buscando el archivo `xp_amp_app_usage_dnu*.ips`. Este archivo es opcional pero mejora la detección.

#### <img width="2%" src="https://simpleicons.org/icons/gnometerminal.svg">&emsp13; Paso 3 — Instalá el scanner en Scriptable:

Abrí Scriptable, creá un nuevo script, pegá el siguiente código y guardalo:

```js
const RIP_PROXY_URL = "https://raw.githubusercontent.com/Streakxit/RIP-PROXY/main/RIP_PROXY.js"

let req = new Request(RIP_PROXY_URL)
let code = await req.loadString()

if (!code || code.startsWith("404")) {
  let a = new Alert()
  a.title = "Error"
  a.message = "No se pudo descargar RIP PROXY."
  a.addAction("OK")
  await a.present()
} else {
  eval(code)
}
```

#### <img width="2%" src="https://simpleicons.org/icons/gnometerminal.svg">&emsp13; Paso 4 — Ejecutá el scanner:

Tocá el script en Scriptable para iniciarlo. El scanner te solicitará seleccionar el `App_Privacy_Report.ndjson` exportado en el paso anterior, y opcionalmente el archivo `.ips`. El análisis se ejecuta automáticamente y presenta el resultado con un veredicto final claro: **LIMPIO**, **SOSPECHOSO** o **CHEAT DETECTADO**.

<img src="https://i.imgur.com/NnWf7Fm.png" alt="line break" width="100%" height="3px">

## Capas de Detección

| Capa | Descripción |
|---|---|
| `Probe TLS en vivo` | Hace requests a los servidores reales de Garena y analiza las respuestas buscando headers inyectados por mitmproxy |
| `Headers de proxy` | Detecta headers como `via`, `x-forwarded-for`, `x-real-ip` y otros insertados por proxies intermedios |
| `Latencia anómala` | Detecta overhead de red consistente en todos los endpoints — señal de proxy intermedio activo |
| `HSTS ausente` | Detecta stripping del header de seguridad que Garena siempre envía |
| `Header server inusual` | Detecta cuando un proxy reemplaza el header `server` legítimo de Garena |
| `ASN / VPS / Hosting` | Cruza los IPs de los dominios contactados contra ASNs y proveedores asociados a cheats |
| `rDNS de servidores` | Analiza los registros DNS inversos para identificar infraestructura de hosting sospechosa |
| `Banners HTTP` | Detecta banners de servidor como nginx, apache, mitmproxy en dominios sospechosos |
| `Bundle IDs` | Identifica apps de proxy, jailbreak y sideload instaladas en el dispositivo |
| `Infraestructura conocida` | Cruza el tráfico contra una base de infraestructura de cheats iOS confirmada |
| `Proxy Login FF` | Detecta dominios de login de Free Fire contactados por apps que no son el propio juego |
| `Tráfico externo de FF` | Analiza el App Privacy Report buscando dominios ajenos a Garena en el tráfico de Free Fire |
| `Apps fantasma` | Detecta apps ausentes en el usage file que contactaron dominios sospechosos |
| `Certificados raíz` | Detecta certificados raíz instalados en el dispositivo — señal directa de proxy MITM |
| `TLD y palabras clave` | Identifica extensiones de dominio y términos asociados a cheats y proxies |
| `Clones de Free Fire` | Detecta bundle IDs modificados que imitan la identidad del juego original |

<img src="https://i.imgur.com/NnWf7Fm.png" alt="line break" width="100%" height="3px">

## Contribuciones

Las contribuciones son bienvenidas. Podés contactarme directamente por Discord para reportar bugs, sugerir mejoras o aportar nuevas señales de detección.

* **🐛 [Reportar un problema](https://discord.gg/fRPPWTJyW)** — ¿Encontraste un bug o un falso positivo?
* **💬 [Hacer una sugerencia](https://discord.gg/fRPPWTJyW)** — ¿Tenés ideas para nuevas capas de detección?

<br>

## Agradecimientos

<table>
  <tr>
    <td style="text-align: center; margin-right: 20px;">
      <a href="https://discord.gg/fRPPWTJyW">
        <b>Tizi</b>
      </a>
    </td>
  </tr>
</table>

<img src="https://i.imgur.com/NnWf7Fm.png" alt="line break" width="100%" height="3px">

## 🎗 Licencia

Copyright RIP PROXY © 2026-2030 · UNKNOWN Security Team.

<img src="https://i.imgur.com/NnWf7Fm.png" alt="line break" width="100%" height="3px">
