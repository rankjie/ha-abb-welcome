# Changelog

Todas las versiones documentadas aquí corresponden al soporte añadido para
paneles exteriores WiFi.

## 1.11.0

### Añadido
- **Backchannel ONVIF** en el servidor RTSP interno. Cuando el cliente envía
  `Require: www.onvif.org/ver20/backchannel` en el DESCRIBE, el SDP incluye una
  tercera sección de medios `a=sendonly` con control `trackID=2`, según la
  sección 5.3 de la especificación de streaming de ONVIF.
- Lectura de datos entrantes en el socket RTSP: el framing interleaved
  `$<canal><len16><datos>` se distingue de las peticiones de texto mirando el
  primer byte.
- `_PCMATalkSender.feed_pcma()`: acepta PCMA ya codificado y lo reencuadra sin
  decodificar ni recodificar, ya que go2rtc negocia el mismo códec que quiere
  el panel.
- Temporizador de inactividad de 1 segundo que devuelve el enlace de subida a
  su flujo de silencio cuando el cliente deja de enviar. Los clientes WebRTC no
  envían marcador de fin al soltar el botón.
- Cabecera `Supported: www.onvif.org/ver20/backchannel` en la respuesta a
  OPTIONS.

### Corregido
- El anuncio del backchannel **no** depende de `talkback_ready`. El DESCRIBE de
  go2rtc llega unos 230 ms antes de que la sesión SIP termine de montar el
  enlace RTP de subida, así que condicionarlo habría ocultado el backchannel en
  todas las llamadas.
- Los paquetes RTCP que llegan en el canal impar ya no se reenvían como audio.

### Notas
- Una sesión de talkback iniciada por servicio tiene prioridad sobre el
  backchannel: el micrófono del navegador no puede pisarla.
- Los clientes que no piden backchannel siguen viendo el SDP de dos tracks de
  siempre, sin cambios de comportamiento.

## 1.10.0

### Añadido
- **Audio bidireccional.** El audio de bajada del panel se publica en el flujo
  RTSP local con el códec realmente negociado (PCMA/8000, PT 8), tomado del SDP
  del panel en lugar de estar fijado en el código.
- Cifrado del enlace de subida: `make_abb_payload_encryptor()` aplica la
  inversa exacta del formato del panel — prefijo de longitud de 2 bytes,
  relleno a múltiplo de 16 y AES-128-ECB.
- Nueva opción `panel_audio` para publicar o no el audio del portero.
- El receptor descarta los payload types no negociados (telephone-event, G729,
  G723), que antes hacían que go2rtc cerrara el productor.
- La respuesta SIP 200 OK refleja las líneas `a=crypto` del panel, de forma que
  la clave anunciada y la usada coinciden.

### Corregido
- El reloj RTP del emisor avanza por número de muestras, no por longitud de los
  bytes cifrados. Con el relleno, lo segundo habría acelerado el audio.
- El talkback ya no se desactiva incondicionalmente en paneles WiFi.

## 1.9.0

### Añadido
- **Descifrado de la carga útil RTP.** Descubrimiento del formato de los
  paneles WiFi: prefijo de longitud de 2 bytes big-endian seguido de
  AES-128-ECB con relleno de ceros. La clave son los 16 bytes ASCII que salen
  de decodificar el base64 del `a=crypto` del SDP, usados directamente.
- Captura de SPS/PPS del flujo descifrado, incluido el formato STAP-A, y
  construcción del `sprop-parameter-sets` real en lugar del valor fijo.
- Puerta de entrada que descarta paquetes hasta ver el primer SPS, con límite
  de 8 segundos.

### Corregido
- La captura de RTP en crudo hacía entrada/salida de fichero bloqueante dentro
  del bucle de eventos. Desactivada.
- El `profile-level-id` se tomaba del SPS real (`42401e`) en vez del valor
  fijado a mano (`42e01f`).
