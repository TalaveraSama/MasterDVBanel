# Newcamd: protocolo Astra y conexión por canal

Fecha: 2026-10-12. Estado de la revisión de framing, asignaciones por canal y
configuración del fork Astra. Este documento distingue los resultados locales
de lo que todavía requiere el motor y el OSCam reales.

## Referencia exacta del fork

Se inspeccionó el repositorio público del usuario
[`TalaveraSama/forkcastra-master`](https://github.com/TalaveraSama/forkcastra-master),
`main`, commit `6c990ea99d918498cc6e78db17fe0ffa02f63ba8` (GPL-3.0), en lugar de
inferir el comportamiento únicamente del espejo de Astra.

Archivos relevantes:

- [`modules/softcam/cam/newcamd.c`](https://github.com/TalaveraSama/forkcastra-master/blob/6c990ea99d918498cc6e78db17fe0ffa02f63ba8/modules/softcam/cam/newcamd.c)
- [`modules/softcam/module_cam.h`](https://github.com/TalaveraSama/forkcastra-master/blob/6c990ea99d918498cc6e78db17fe0ffa02f63ba8/modules/softcam/module_cam.h)
- [`scripts/stream.lua`](https://github.com/TalaveraSama/forkcastra-master/blob/6c990ea99d918498cc6e78db17fe0ffa02f63ba8/scripts/stream.lua)

## Protocolo Newcamd

El cliente C de este fork arma y cifra la trama completa con este layout:

```
[0..1 longitud TCP][2..3 msg_id][4..5 provider/PNR][6..11 cabecera]
[12 tipo][13..14 longitud del payload][15.. payload][padding][XOR][IV]
```

Los dos primeros bytes quedan en claro. El cifrado y descifrado comienzan en el
offset 2; Astra escribe la longitud TCP final en `[0..1]` tras añadir padding,
checksum XOR e IV. El login usa el tipo `0xE0`, usuario, NUL y contraseña
`md5_crypt`. El fork lee los 14 bytes iniciales del servidor para derivar la
clave de sesión. La implementación actual en `tbs-webui/app/services/newcamd_client.py`
y `newcamd_crypto.py` envía y recibe la trama completa; el wrapper nativo
conserva la variante OSCam (`doPC1`/`EuroDes`), no sustituye su cifrado por el
DES estándar de Astra.

La causa concreta corregida en el cambio anterior era un framing desplazado:
Python quitaba/añadía el prefijo TCP de forma incompatible con los offsets del
C. Los tests usan un OSCam/Newcamd simulado para verificar los offsets; **no**
prueban la autenticación en el OSCam del usuario.

## Qué significa «una conexión por canal» en este fork

`stream.lua` parsea `cam=<nombre>` como `_G[nombre]:cam()` y entrega ese objeto a
`decrypt`. En `module_cam.h`, `module_cam_attach_decrypt` llama a `connect()` al
asociar el primer descifrador a un objeto CAM; `module_cam_detach_decrypt`
llama a `disconnect()` al retirar el último. Por tanto:

- reutilizar el mismo objeto Newcamd global en varios canales comparte un socket;
- declarar un objeto Newcamd distinto para cada canal da una instancia CAM y un
  socket TCP independientes, incluso si comparten el mismo perfil/credenciales.

La generación actual sigue ese contrato: cada asignación usa el alias estable
`newcamd_service_<Service.id>` y genera su propio `newcamd({...})` y
`make_channel({...})`. El ID de fila, y no solo el PNR, evita colisiones cuando
un PNR se repite en otro transponder.

`stream.lua` también requiere que `dvb://<alias>` resuelva a un objeto global DVB
ya declarado. El esquema `Service` no tenía esa relación y los escaneos no
persistían una fuente DVB de Astra. Para no inventar `tuner_1`, adaptador,
frontend ni transponder, ahora se guarda `engine_input_name` por canal; la UI
lo presenta como **Fuente DVB Astra**. La generación/revisión de configuración
rechaza asignaciones sin ese alias o con perfil deshabilitado. Tampoco se crea
un puerto UDP de salida por defecto.

## Archivos del panel que implementan el cambio

- `tbs-webui/app/services/newcamd_profiles.py`: alias único por canal, clonación
de una instancia Newcamd por servicio, validación del alias DVB y generación
sin salida inventada.
- `tbs-webui/app/models.py`, `app/database.py`, `app/schemas.py` y
  `app/routers/_common.py`: persistencia, migración automática y API de
  `engine_input_name`.
- `tbs-webui/app/routers/newcamd.py`: la asignación devuelve el nombre CAM único;
  `/config` y `/config/apply` incorporan los canales asignados y no confirman una
  generación incompleta.
- `tbs-webui/app/web/js/forkskin.js`: campo **Fuente DVB Astra** y llamada `PUT`
  correcta para guardar asignaciones (el método anterior era `POST`, distinto
  del método definido por el endpoint).
- `tbs-webui/app/config.py`, `.env.example` y
  `deploy/tbs-webui.env.example`: opción `TBS_ENGINE_CONFIG_PATH`; por defecto
  se escribe `<TBS_DATA_DIR>/newcamd-generated.lua` con permisos `0600`.

El fragmento debe incluirse desde el `stream.lua` principal de Astra **después**
de declarar las fuentes DVB, por ejemplo:

```lua
dofile("/var/lib/tbs-webui/newcamd-generated.lua")
```

`POST /api/newcamd/config/apply` solo escribe ese fragmento; no reinicia ni
recarga Astra y no valida que el alias pertenezca al transponder esperado. No se
ha confirmado en este entorno cuál es el archivo principal/ruta de Astra del
homeserver del usuario. El fragmento no define salida de vídeo; el fork mantiene
su analizador de la entrada, pero el destino final de distribución sigue sin
configurar.

## Evidencia previa del homeserver

La sesión anterior observó `version: 1.0.3`, `mock: false`, cuatro adaptadores y
systemd ejecutando el directorio extraído de `v1.0.3`. OSCam escuchaba en TCP
5000; dos conexiones `nc` recibieron 14 bytes iniciales diferentes. Eso confirma
el saludo del servidor, no un login correcto. El registro del panel mostró
«El servidor cerró la conexión»; un intento antiguo contra 50001 mostró
`Connection refused`, que es un fallo distinto.

La DES key indicada por el usuario se toma como correcta; el síntoma por sí solo
no justifica cambiarla. No se deben atribuir entradas históricas de SQLite o de
la biblioteca nativa a un intento nuevo sin marca de tiempo concordante.

## Verificación y límites

- `make -C tbs-webui/native clean all test`: compilación y autoprueba del wrapper
  nativo correcta (`OK: cifrado y descifrado son inversas`).
- `.venv/bin/python -m pytest -q` desde `tbs-webui`: **466 pasaron, 3 omitidas**;
  las omitidas requieren hardware DVB o tablas opcionales. Se ejecutó con la
  biblioteca Newcamd nativa compilada.
- Las pruebas de este cambio comprueban la serialización de dos servicios con
  el mismo perfil a **dos objetos** `newcamd` distintos, el alias DVB explícito,
  la persistencia/migración y el rechazo de mapeos ausentes. No sustituyen una
  prueba con el motor Astra cargando el fragmento ni una sesión real de OSCam.

Para cerrar la verificación operativa hay que incluir el fragmento en la
configuración Astra del homeserver, recargar el motor y revisar en el log del
panel y en OSCam una sesión por canal asignado. No compartir contraseñas ni DES
keys.

## Seguridad

Usar Newcamd solamente con servidores propios o autorizados. Las credenciales y
DES key que aparecen dentro del fragmento son necesarias para el motor; mantener
el fichero con permisos restrictivos, ejecutarlo bajo el usuario esperado y no
subirlo al repositorio.
