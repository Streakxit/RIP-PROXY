<div id="top">

<p align="center">
  <img alt="RIP PROXY Logo" src="https://i.imgur.com/QRlCrO3.png" width="60%">
</p>

<p align="center">
  <em>Pensado y desarrollado en beneficio de la comunidad competitiva de Free Fire, por TIZI.XIT.</em>
</p>

</div>

<img src="https://i.imgur.com/NnWf7Fm.png" alt="line break" width="100%" height="3px">

## Introducción

RIP PROXY es un scanner para dispositivos **iOS** que detecta cheats de tipo proxy MITM en Free Fire analizando el comportamiento real de las conexiones TLS y el tráfico de red del dispositivo, sin depender de listas estáticas de IPs o servidores conocidos.

**¿Por qué usar RIP PROXY?**

La mayoría de los scanners detectan cheats comparando contra listas de IPs y hostings conocidos — los cheaters simplemente cambian de servidor y lo evaden. RIP PROXY ataca el problema desde la raíz:

* **🔴 Detección por comportamiento:** Analiza cómo se comportan las conexiones TLS en tiempo real, no qué IP las origina.
* **⚫️ App Privacy Report:** Lee directamente qué dominios contactó Free Fire según el sistema operativo iOS — información que el cheat no puede ocultar.
* **🟣 Sin evasión posible:** No importa si el operador del proxy cambia de servidor, país o hosting — el método de detección sigue funcionando.

<img src="https://i.imgur.com/NnWf7Fm.png" alt="line break" width="100%" height="3px">

## ¿Cómo usar?

#### <img width="2%" src="https://simpleicons.org/icons/apple.svg">&emsp13; Paso 1 — Instalá Scriptable:

| Aplicación | Descripción |
|---|---|
| [Scriptable](https://apps.apple.com/app/scriptable/id1405459188) | App gratuita para automatización iOS con JavaScript |

#### <img width="2%" src="https://simpleicons.org/icons/apple.svg">&emsp13; Paso 2 — Exportá el Informe de Privacidad del iPhone:

Ir a **Configuración → Privacidad y seguridad → Informe de privacidad de apps → Exportar informe de privacidad de apps**

El archivo se guarda en formato `App_Privacy_Report_v4_YYYY-MM-DD...` en iCloud Drive o Archivos.

#### <img width="2%" src="https://simpleicons.org/icons/gnometerminal.svg">&emsp13; Paso 3 — Instalá el scanner en Scriptable:

Abrí Scriptable, creá un nuevo script, pegá el código de abajo y guardá:

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

#### <img width="2%" src="https://simpleicons.org/icons/gnometerminal.svg">&emsp13; Paso 4 — Ejecutá:

Tocá el script para correrlo. El scanner te va a preguntar si querés incluir el App Privacy Report. Seleccioná el archivo exportado en el paso 2 para el análisis completo. El resultado aparece automáticamente con el veredicto final.

<img src="https://i.imgur.com/NnWf7Fm.png" alt="line break" width="100%" height="3px">

## Detecciones

| Detección | Descripción |
|---|---|
| `Probe TLS en vivo` | Hace requests a los servidores reales de Garena y analiza las respuestas buscando headers inyectados por mitmproxy |
| `Headers de proxy` | Detecta headers como `via`, `x-forwarded-for`, `x-real-ip` y otros que mitmproxy inyecta en las respuestas |
| `Análisis de latencia` | Detecta overhead de red consistente en todos los endpoints de Garena — señal de proxy intermedio |
| `HSTS ausente` | Detecta stripping del header de seguridad que Garena siempre envía |
| `Header server inusual` | Detecta cuando mitmproxy reemplaza el header `server` de Garena por uno propio |
| `Dominios anómalos en tráfico de FF` | Analiza el App Privacy Report buscando dominios externos contactados por Free Fire que no pertenecen a Garena |
| `Infraestructura de cheat conocida` | Cruza dominios del reporte contra infraestructura de cheats iOS confirmada |
| `Validación del archivo` | Verifica que el App Privacy Report sea legítimo y no haya sido manipulado |

<img src="https://i.imgur.com/NnWf7Fm.png" alt="line break" width="100%" height="3px">

## Contribuciones

¡Las contribuciones son bienvenidas! Contactame por Discord en privado.

* **🐛 [Reportar un problema](https://discord.gg/fRPPWTJyW)**: ¿Encontraste un bug? ¡Avisame!
* **💬 [Hacer una sugerencia](https://discord.gg/fRPPWTJyW)**: ¿Tenés ideas o sugerencias? Me encantaría escucharte.

<br>

## Agradecimientos

Un enorme agradecimiento a los miembros de abajo por su trabajo y contribuciones:

<div style="text-align:; font-weight: bold; margin-bottom: 10px;">
  ㅤTiziㅤ
</div>

<table>
  <tr>
    <td style="text-align: center; margin-right: 20px;">
      <a href="https://discord.gg/fRPPWTJyW">
        <img src="https://i.imgur.com/25Qrvbh.png" alt="Tizi" style="width: 50px; height: 50px;">
      </a>
    </td>
  </tr>
</table>

<img src="https://i.imgur.com/NnWf7Fm.png" alt="line break" width="100%" height="3px">

## 🎗 Licencia

Copyright RIP PROXY © 2026-2030.

<img src="https://i.imgur.com/NnWf7Fm.png" alt="line break" width="100%" height="3px">
