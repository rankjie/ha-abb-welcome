# ABB Welcome para Home Assistant — con soporte para paneles WiFi

Integración de Home Assistant para videoporteros **ABB Welcome / Busch-Jaeger**
que añade compatibilidad con los **paneles interiores WiFi**: vídeo, audio de
bajada y audio de subida (talkback) sobre la conexión SIP/RTP local del
portero, sin nube.

> Esta es una versión modificada del proyecto original
> [rankjie/ha-abb-welcome](https://github.com/rankjie/ha-abb-welcome).
> Los cambios se limitan a la ruta de medios de los paneles WiFi.

---

## Por qué existe esta versión

Los paneles WiFi de ABB anuncian su flujo como `RTP/AVP` normal en el SDP,
pero **no envían RTP en claro**. Cada carga útil RTP va así:

```
[2 bytes big-endian: longitud real][AES-128-ECB, relleno con ceros a múltiplo de 16]
```

La clave son los bytes en crudo del `a=crypto` del SDP:

```
a=crypto:1 AES_CM_128_HMAC_SHA1_32 inline:WERYelBoeWxkbTRrdUtneA==
```

Ese base64 decodifica a exactamente 16 bytes ASCII y se usa **tal cual** como
clave AES-128. No es SRTP: no hay keystream AES-CM, ni salt, ni etiqueta de
autenticación, ni ROC.

Esto afecta **igual al audio y al vídeo**, y explica por qué los decodificadores
convencionales no encuentran SPS/PPS en el flujo: sí están, pero cifrados. Lo
que parecían cabeceras NAL con tipos imposibles (0, 2, 3, 4 con `nri=0`) era en
realidad el byte alto del prefijo de longitud — un paquete de 802 bytes empieza
por `0x03 0x13` porque la longitud real es `0x0313` = 787.

El mismo esquema, aplicado a la inversa, es lo que permite **enviar** audio al
portero.

---

## Qué funciona

| Función | Estado |
|---|---|
| Vídeo H.264 del panel WiFi | Funciona (640x480, Constrained Baseline) |
| Audio del portero hacia HA | Funciona (PCMA/8000) |
| Talkback desde HA hacia el portero | Funciona (vía servicios) |
| Backchannel ONVIF para WebRTC | Implementado; requiere HTTPS y tarjeta compatible |
| Apertura de puerta, timbre, sensores | Del proyecto original |

---

## Requisitos

- Home Assistant **2024.11 o superior** (usa la API WebRTC nativa y el go2rtc
  integrado).
- Un gateway ABB Welcome accesible en la red local/ Panel interior wifi.
- Las dependencias `cryptography` y `requests` las instala Home Assistant
  automáticamente desde el manifiesto.

---

## Instalación

### Manual

1. Copia la carpeta `custom_components/abb_welcome/` dentro de tu
   `config/custom_components/` de Home Assistant.
2. Reinicia Home Assistant.
3. Ve a **Ajustes → Dispositivos y servicios → Añadir integración** y busca
   **ABB Welcome**.

### HACS (repositorio personalizado)

1. En HACS, menú de tres puntos → **Repositorios personalizados**.
2. Añade la URL de tu repositorio con categoría **Integración**.
3. Instala **ABB Welcome** y reinicia.

---

## Configuración

Durante el alta se piden la IP del gateway/panel wifi y las credenciales. Después, en
**Configurar**, están las opciones relevantes para paneles WiFi:

| Opción | Por defecto | Para qué sirve |
|---|---|---|
| `panel_audio` | Activado | Publica el audio del portero en el flujo local. Desactívalo si go2rtc se comporta mal con el audio y prefieres vídeo solo. |
| `device_type` | Autodetectado | Marca la estación como panel WiFi, lo que activa la ruta de descifrado. |
| `allow_pickup` | — | Permite descolgar la llamada desde HA. |
| `lan_rtsp_host` / `lan_rtsp_port` | — | Proxy RTSP en la LAN para Scrypted, HomeKit o un NVR. |

---

## Uso

### Ver la cámara

La entidad de cámara aparece como `camera.puerta_<id_estacion>`. El flujo se
abre bajo demanda: cuando llaman al timbre, o cuando armas el streaming
manualmente con el interruptor de la estación o con el servicio
`abb_welcome.arm_streaming`.

### Abrir la puerta

**El botón de abrir puerta no funciona hasta que suene el timbre por primera
vez.** Esto es esperado, no es un fallo de configuración.

Los gateways IP normales publican la lista de estaciones exteriores, pero los
paneles WiFi no exponen las secciones `outdoorstation_*`, así que la
integración no tiene forma de saber a qué dirección SIP hay que mandar la orden
de apertura hasta que el propio panel se identifica.

Qué ocurre exactamente:

1. Tras el alta, aparece un botón **Abrir puerta** provisional. Si lo pulsas,
   no abre nada: lanza un aviso pidiéndote que toques el timbre primero.
2. En la primera llamada entrante, la integración lee la dirección SIP de la
   estación de la cabecera `From` del INVITE y la guarda de forma permanente.
3. Cinco segundos después termina la llamada, la integración se recarga sola y
   el botón provisional se sustituye por el definitivo, ya con el nombre real
   de la estación: **Puerta (100000001)**.

La espera de cinco segundos es deliberada, para no cortar el vídeo ni el audio
en mitad de la llamada que acaba de disparar el descubrimiento.

A partir de ahí el botón queda operativo para siempre, también fuera de
llamada. El dato sobrevive a reinicios; solo se volvería a perder si eliminas y
vuelves a añadir la integración.

En el registro lo confirmas con:

```
WiFi panel: discovered outdoor station from incoming call: uri=... user=100000001 clean_address=sip:100000001@...
```

### Hablar por el portero (sin HTTPS)

Esta es la ruta que funciona en cualquier instalación, incluida HTTP. Requiere
que el flujo de la cámara esté abierto.

**Tono de prueba** — lo más rápido para verificar que el altavoz responde:

```yaml
service: abb_welcome.talk_tone
data:
  entity_id: camera.puerta_100000001
  duration_ms: 1200
  frequency_hz: 880
  amplitude: 0.35
```

**Enviar audio propio** (por ejemplo, un mensaje de TTS):

```yaml
- service: abb_welcome.talk_start
  data:
    entity_id: camera.puerta_100000001

- service: abb_welcome.talk_pcm16le
  data:
    entity_id: camera.puerta_100000001
    pcm16le: !secret audio_en_base64   # PCM 16 bits little-endian, 8 kHz mono

- service: abb_welcome.talk_stop
  data:
    entity_id: camera.puerta_100000001
```

El audio debe ser **PCM 16 bits little-endian, mono, 8000 Hz**, codificado en
base64. Para convertir un fichero:

```bash
ffmpeg -i mensaje.mp3 -ar 8000 -ac 1 -f s16le - | base64 -w0
```

### Hablar desde la tarjeta de cámara (requiere HTTPS)

La integración expone un **backchannel ONVIF** (`Require:
www.onvif.org/ver20/backchannel`) en su servidor RTSP interno, que es
exactamente lo que go2rtc espera para el audio bidireccional. Cuando un cliente
lo pide, el SDP incluye una tercera sección de medios marcada `a=sendonly`.

Para usarlo hacen falta dos cosas que **no dependen de esta integración**:

1. **Acceso a Home Assistant por HTTPS.** Los navegadores no dan acceso al
   micrófono en conexiones sin cifrar, y esto incluye la aplicación móvil. Es
   una restricción del navegador, no hay forma de saltársela.
2. **Una tarjeta con botón de micrófono.** Las tarjetas nativas de Home
   Assistant no soportan audio bidireccional. Opciones conocidas:

```yaml
# Opción A: WebRTC Camera (AlexxIT), vía HACS
type: custom:webrtc-camera
url: abb_100000001        # nombre del stream en go2rtc, NO la entidad
mode: webrtc
media: video,audio,microphone
ui: true
```

```yaml
# Opción B: Advanced Camera Card
type: custom:advanced-camera-card
cameras:
  - camera_entity: camera.puerta_100000001
live_provider: go2rtc
go2rtc:
  modes: [webrtc]
menu:
  buttons:
    microphone:
      enabled: true
```

El nombre del stream en go2rtc es `abb_<id_estacion>`; aparece en el registro
como `registered go2rtc stream abb_100000001`.

---

## Servicios disponibles

| Servicio | Descripción |
|---|---|
| `abb_welcome.talk_start` | Abre el canal de subida hacia el portero. |
| `abb_welcome.talk_stop` | Cierra el canal de subida. |
| `abb_welcome.talk_pcm16le` | Envía audio PCM 16 bits LE, 8 kHz mono, en base64. |
| `abb_welcome.talk_tone` | Envía un tono generado, para pruebas. |
| `abb_welcome.arm_streaming` | Arma el streaming durante una ventana de tiempo. |
| `abb_welcome.refresh_doors` | Relee la lista de estaciones desde el gateway. |
| `abb_welcome.export_credentials` | Vuelca credenciales a un JSON. **Contiene secretos.** |

---

## Diagnóstico

Activa el registro detallado:

```yaml
logger:
  logs:
    custom_components.abb_welcome: debug
```

Líneas que confirman que todo va bien:

```
video payload decryption active
audio leg pt=8 codec=PCMA/8000 encrypted=True
talkback RTP leg ready -> 192.168.1.16:50688 pt=8 encrypted=True
media stats ... audio pkts=10973 pts={8: 10973} decrypted=10973 dropped_pts={}
NAL summary ... SPS=True PPS=True IDR=True decrypted=3880 decrypt_failed=0
```

Y para el backchannel:

```
DESCRIBE returning SDP ... backchannel_requested=True backchannel_offered=True
SETUP ... url=.../trackID=2 backchannel=True bc_channel=4
backchannel audio started pt=8
```

Si ves `backchannel_offered=True` pero nunca un `SETUP` del `trackID=2`,
significa que el cliente no pidió el canal: casi siempre porque el navegador no
tiene micrófono disponible por falta de HTTPS.

### Problemas frecuentes

**El botón de abrir puerta da error.** Si el mensaje dice que no se ha
descubierto la estación exterior, toca el timbre una vez y espera unos segundos
a que la integración se recargue sola. Ver la sección «Abrir la puerta».

**No hay imagen y `decrypt_failed` es alto.** La clave del SDP no coincide.
Revisa la línea `a=crypto` en el registro.

**El audio se oye acelerado o entrecortado.** Comprueba `dropped_pts` en las
estadísticas: si aparecen tipos distintos del negociado, el panel está
intercalando otro códec.

**Chasquido al inicio del talkback.** Son los `underrun_packets` mientras se
llena el búfer. Es normal en los primeros paquetes.

---

## Limitaciones conocidas

- El talkback se probó con tono generado y con PCM corto. La voz continua puede
  comportarse distinto; los contadores `underrun_packets` y `dropped_frames` de
  `talkback stats` son el sitio donde mirar.
- El backchannel ONVIF está verificado contra un cliente RTSP simulado que
  reproduce la secuencia de go2rtc, pero no contra un navegador real con
  micrófono.
- El descubrimiento del cifrado se validó en un panel concreto. Otros modelos
  podrían usar una variante distinta.

---

## Créditos

Trabajo original de [@rankjie](https://github.com/rankjie/ha-abb-welcome). El
análisis del cifrado RTP de los paneles WiFi y la ruta de audio bidireccional
son añadidos de esta versión.

## Licencia

MIT, la misma que el proyecto original. El fichero `LICENSE` conserva el aviso
de copyright de rankjie, como exige la propia licencia.
