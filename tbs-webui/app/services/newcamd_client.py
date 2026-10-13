"""Cliente del protocolo Newcamd (CS378x / newcamd) para servidores CAS propios.

AVISO LEGAL: Newcamd es un protocolo de *card sharing*. Usalo **solo** con
servidores de tu propiedad o para los que tengas autorizacion expresa (por
ejemplo tu propio OSCam sirviendo a tu tarjeta, o el servidor de tu operador).
Este proyecto no incluye ni distribuye claves ni servicios de terceros.

Protocolo implementado segun la referencia de Astra/cesbo
(`modules/softcam/cam/newcamd.c`), que es la implementacion correcta de CS378x:

1. El servidor envia **14 bytes** de clave inicial (``server_key``).
2. La clave de cifrado se calcula asi:
   - ``tmp[0..13] = deskey[0..13] XOR server_key[0..13]`` (XOR ciclico),
   - esos 14 bytes (112 bits) se expanden a 16 bytes de key schedule con
     ``DES_set_odd_parity`` => **DES-EDE2** (dos claves DES de 8 bytes).
3. El login se envia en un paquete Newcamd:
   - cabecera de 12 B, en la que ``buffer[12] = 0xE0`` (LOGIN), el usuario y la
     contrasena van a continuacion,
   - relleno aleatorio hasta multiplo de 8, checksum XOR en el ultimo byte,
   - **cifrado DES-EDE2-CBC con IV aleatorio** que se anexa al final,
   - longitud del paquete (2 B) al principio.
4. El servidor responde con un paquete cifrado igual; ``buffer[12]`` es
   ``0xE1`` (LOGIN_ACK) si el login es correcto y ``0xE2`` (LOGIN_NAK) si no.
5. Despues del login se piden los datos de tarjeta (``0xE4``) y el servidor
   devuelve CAID, UA y la lista de providers.
6. Cada ECM se envia como paquete ``0x80..0x8F`` y la respuesta contiene los
   control words (2 x 8 bytes).

`pycryptodome` aporta el triple DES del protocolo y el cifrado de las
contrasenas guardadas en la base de datos.
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from .md5crypt import newcamd_password
from .newcamd_crypto import CryptoUnavailable, load_library

logger = logging.getLogger(__name__)

MSG_LOGIN = 0xE0
MSG_LOGIN_ACK = 0xE1
MSG_LOGIN_NAK = 0xE2
MSG_CARD_DATA_REQ = 0xE4
MSG_CARD_DATA = 0xE5
MSG_KEEPALIVE = 0xFD

HEADER_SIZE = 12
NATIVE_FRAME_PREFIX_SIZE = HEADER_SIZE + 3
KEY_SIZE = 14

DEFAULT_PORT = 50001
MAX_PACKET = 4096

STATE_DISCONNECTED = "disconnected"
STATE_CONNECTING = "connecting"
STATE_LOGGED_IN = "logged_in"
STATE_ERROR = "error"


class NewcamdError(Exception):
    """Error de protocolo o de red del cliente Newcamd."""


class NewcamdAuthError(NewcamdError):
    """El servidor rechazo el usuario/contrasena."""


@dataclass
class NewcamdAccount:
    """Datos de conexion de una cuenta Newcamd."""

    name: str
    host: str
    port: int = DEFAULT_PORT
    username: str = ""
    password: str = ""
    deskey: str = "0102030405060708091011121314"  # 14 bytes en hexadecimal
    enabled: bool = True
    id: int | None = None
    # Formato de la contrasena en el login: "md5" (md5_crypt, lo que usa
    # newcamd/CS378x), "plain" (algunos servidores) o "auto" (prueba md5 y, si el
    # servidor lo rechaza, reintenta en claro).
    password_format: str = "auto"
    # Usa la biblioteca nativa (criptografia real de newcamd, la que entiende
    # OSCam). Si esta a False se usa el camino Python (solo DES estandar).
    use_native_crypto: bool = True

    def deskey_bytes(self) -> bytes:
        cleaned = (self.deskey or "").strip().replace(" ", "").replace(":", "")
        if len(cleaned) != 28:
            raise NewcamdError("La deskey debe tener 28 digitos hexadecimales (14 bytes)")
        try:
            return bytes.fromhex(cleaned)
        except ValueError as exc:
            raise NewcamdError(f"deskey no valida: {exc}") from exc


@dataclass
class NewcamdStatus:
    """Estado de la conexion (lo que muestra la interfaz)."""

    state: str = STATE_DISCONNECTED
    message: str = ""
    connected_at: float | None = None
    last_error: str | None = None
    ecm_sent: int = 0
    cw_received: int = 0
    last_ecm_at: float | None = None
    last_cw_at: float | None = None
    last_cw: str | None = None
    bytes_in: int = 0
    bytes_out: int = 0
    caid: int | None = None
    providers: int = 0

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "message": self.message,
            "connected_at": self.connected_at,
            "last_error": self.last_error,
            "ecm_sent": self.ecm_sent,
            "cw_received": self.cw_received,
            "last_ecm_at": self.last_ecm_at,
            "last_cw_at": self.last_cw_at,
            "last_cw": self.last_cw,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "caid": self.caid,
            "providers": self.providers,
        }


# ---------------------------------------------------------------------------
# Clave del handshake (DES-EDE2) — replica triple_des_set_key() de Astra
# ---------------------------------------------------------------------------
def derive_triple_des_key(deskey: bytes, server_key: bytes) -> bytes:
    """Deriva la clave de 16 bytes del DES-EDE2.

    ``tmp = deskey XOR server_key`` (XOR ciclico sobre 14 bytes) y luego la
    expansion de 7->8 bytes por bloque con bit de paridad (como DES_set_odd_parity
    de OpenSSL, que solo ajusta el LSB de cada byte).
    """
    if len(deskey) != KEY_SIZE:
        raise NewcamdError("La deskey debe tener 14 bytes")
    if not server_key:
        raise NewcamdError("Falta la clave inicial del servidor")

    tmp = bytearray(KEY_SIZE)
    for index in range(KEY_SIZE):
        tmp[index] = deskey[index] ^ server_key[index % len(server_key)]

    def expand(block: bytes) -> bytes:
        out = bytearray(8)
        out[0] = (block[0] >> 1) & 0xFE
        out[1] = (((block[0] << 7) & 0xFF) | (block[1] >> 1)) & 0xFE
        out[2] = (((block[1] << 6) & 0xFF) | (block[2] >> 2)) & 0xFE
        out[3] = (((block[2] << 5) & 0xFF) | (block[3] >> 3)) & 0xFE
        out[4] = (((block[3] << 4) & 0xFF) | (block[4] >> 4)) & 0xFE
        out[5] = (((block[4] << 3) & 0xFF) | (block[5] >> 5)) & 0xFE
        out[6] = (((block[5] << 2) & 0xFF) | (block[6] >> 6)) & 0xFE
        out[7] = (block[6] << 1) & 0xFF
        # DES_set_odd_parity: ajusta el bit menos significativo a paridad impar.
        for index in range(8):
            value = out[index]
            if bin(value).count("1") % 2 == 0:
                out[index] = value ^ 0x01
        return bytes(out)

    return expand(bytes(tmp[0:7])) + expand(bytes(tmp[7:14]))


def xor_sum(data: bytes) -> int:
    """Checksum XOR de un bloque (usado por el protocolo)."""
    checksum = 0
    for byte in data:
        checksum ^= byte
    return checksum


def build_packet(message_type: int, payload: bytes, key: bytes, msg_id: int = 0, provider: int = 0) -> bytes:
    """Construye un paquete Newcamd cifrado (cabecera + payload + pad + CRC + IV)."""
    from Crypto.Cipher import DES3

    # Estructura (igual que `on_newcamd_ready` de Astra):
    #   [0..1]  longitud (2 B, big endian)  -> se rellena al final
    #   [2..3]  message id
    #   [4..5]  provider
    #   [6..11] relleno
    #   [12]    tipo de mensaje
    #   [13..14] longitud del payload
    #   [15..]  payload + relleno, y el ultimo byte es el checksum XOR
    body = bytearray()
    body.append(message_type)
    body.append((len(payload) >> 8) & 0x0F)
    body.append(len(payload) & 0xFF)
    body.extend(payload)

    packet_size = HEADER_SIZE + len(body)
    pad_len = (8 - ((packet_size - 1) % 8)) % 8
    body.extend(b"\x00" * pad_len)
    packet_size += pad_len

    header = bytearray(HEADER_SIZE)
    header[2] = (msg_id >> 8) & 0xFF
    header[3] = msg_id & 0xFF
    header[4] = (provider >> 8) & 0xFF
    header[5] = provider & 0xFF

    frame = bytearray(header) + body
    # El checksum va en la posicion packet_size (la trama mide exactamente eso)
    frame.append(xor_sum(frame[2:packet_size]))
    packet_size += 1

    # Cifrado con DES-EDE2-CBC desde el byte 2, con IV aleatorio anexado
    iv = os.urandom(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    encrypted = cipher.encrypt(bytes(frame[2:packet_size]))

    length = (packet_size - 2) + len(iv)
    out = bytearray(struct.pack(">H", length)) + bytearray(encrypted) + bytearray(iv)
    return bytes(out)


def parse_packet(raw_packet: bytes, key: bytes) -> tuple[int, bytes, bytes, int]:
    """Descifra y valida un paquete Newcamd.

    Devuelve ``(tipo, payload, cuerpo, msg_id)``:
      * ``tipo``    -> tipo de mensaje (p. ej. 0xE0, 0xE1),
      * ``payload`` -> datos utiles (sin cabecera ni relleno ni checksum),
      * ``cuerpo``  -> cuerpo completo desde el tipo (tipo + longitud + payload),
      * ``msg_id``  -> identificador de mensaje.
    """
    from Crypto.Cipher import DES3

    if len(raw_packet) < HEADER_SIZE + 8 + 2:
        raise NewcamdError("Paquete Newcamd demasiado corto")
    length = struct.unpack(">H", raw_packet[0:2])[0]
    total = length + 2
    if total > len(raw_packet):
        total = len(raw_packet)

    frame = bytearray(raw_packet[:total])
    payload_size = total - 2
    if payload_size % 8 != 0 or payload_size <= HEADER_SIZE + 3:
        # Mensajes cortos (keepalive) pueden venir en claro
        body = bytes(frame[2:])
        if not body:
            raise NewcamdError("Paquete vacio")
        declared = ((body[1] & 0x0F) << 8) | body[2] if len(body) > 2 else 0
        return (body[0] if body else 0), bytes(body[3 : 3 + declared]), body, 0

    iv = bytes(frame[total - 8 : total])
    encrypted = bytes(frame[2 : total - 8])
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted = bytearray(cipher.decrypt(encrypted))

    # `decrypted` corresponde a los bytes originales desde el offset 2
    if xor_sum(bytes(decrypted)) != 0:
        raise NewcamdError("Checksum del paquete Newcamd incorrecto")

    msg_id = struct.unpack(">H", bytes(decrypted[0:2]))[0]
    body = bytes(decrypted[HEADER_SIZE - 2 :])
    declared = ((body[1] & 0x0F) << 8) | body[2] if len(body) > 2 else 0
    payload = bytes(body[3 : 3 + declared])
    return body[0] if body else 0, payload, body, msg_id


@dataclass
class EcmRequest:
    """Peticion ECM (tipo 0x80..0x8F)."""

    service_id: int
    ca_system_id: int = 0x0100
    ecm: bytes = b""
    provid: int = 0

    def payload(self) -> bytes:
        ecm = bytes(self.ecm)
        if len(ecm) < 3:
            raise NewcamdError("El ECM debe tener al menos 3 bytes")
        # El cuerpo empieza con el propio ECM (3 B de cabecera + datos)
        return ecm


# ---------------------------------------------------------------------------
# Cliente
# ---------------------------------------------------------------------------
class NewcamdClient:
    """Cliente Newcamd con hilo de recepcion y callback de control words."""

    def __init__(
        self,
        account: NewcamdAccount,
        timeout: float = 8.0,
        on_control_word: Callable[[bytes, bytes], None] | None = None,
    ) -> None:
        self.account = account
        self.timeout = timeout
        self.on_control_word = on_control_word
        self.status = NewcamdStatus()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._key: bytes | None = None
        self._crypto: Any | None = None
        self._msg_id = 0

    # -- cifrado nativo y framing de Astra/OSCam -----------------------------
    @staticmethod
    def _native_frame(
        message_type: int, payload: bytes = b"", msg_id: int = 0, provider: int = 0
    ) -> bytes:
        """Monta la trama completa: longitud + cabecera 12 B + mensaje.

        El layout sigue `modules/softcam/cam/newcamd.c` de Astra. Los dos
        primeros bytes se rellenan con la longitud al cifrar; msg_id y provider
        ocupan los offsets 2..5, y el mensaje empieza en el offset 12.
        """
        if len(payload) > 0x0FFF:
            raise NewcamdError("El payload Newcamd excede 4095 bytes")
        if not 0 <= int(msg_id) <= 0xFFFF or not 0 <= int(provider) <= 0xFFFF:
            raise NewcamdError("msg_id/provider fuera de rango")
        frame = bytearray(NATIVE_FRAME_PREFIX_SIZE)
        frame[2:4] = int(msg_id).to_bytes(2, "big")
        frame[4:6] = int(provider).to_bytes(2, "big")
        frame[HEADER_SIZE] = int(message_type) & 0xFF
        frame[HEADER_SIZE + 1] = (len(payload) >> 8) & 0x0F
        frame[HEADER_SIZE + 2] = len(payload) & 0xFF
        frame.extend(payload)
        return bytes(frame)

    def _native_login(self, crypto: Any, password_mode: str) -> socket.socket:
        """Login nativo; cada variante abre una conexión con un saludo nuevo."""
        sock = socket.create_connection((self.account.host, int(self.account.port)), timeout=self.timeout)
        sock.settimeout(self.timeout)
        try:
            server_key = self._recv_exact(sock, KEY_SIZE)
            if len(server_key) < KEY_SIZE:
                raise NewcamdError("El servidor no envio los 14 bytes de clave inicial")
            key = crypto.login_key(server_key, self.account.deskey_bytes(), KEY_SIZE)
            self._key = key
            self._msg_id = 0

            user = self.account.username.encode("latin-1", "replace")
            password = self._password_field(password_mode)
            payload = user + b"\x00" + password
            frame = self._native_frame(MSG_LOGIN, payload)
            packet = crypto.encrypt(frame, key)
            sock.sendall(packet)
            self.status.bytes_out += len(packet)

            try:
                raw = self._recv_packet(sock)
            except NewcamdError as exc:
                raise NewcamdError(
                    "OSCam cerro la conexion mientras esperaba la respuesta al login Newcamd"
                ) from exc
            message_type, _body, _provider = self._decrypt_native_packet(crypto, raw, key)
            if message_type == MSG_LOGIN_ACK:
                logger.info("Newcamd: login nativo aceptado (formato %s)", password_mode)
                return sock
            if message_type == MSG_LOGIN_NAK:
                raise NewcamdAuthError("Login rechazado (0xE2): revisa usuario y contrasena")
            raise NewcamdAuthError(
                "Respuesta de login inesperada (0x%02X)" % message_type
            )
        except Exception:
            _close(sock)
            raise

    def _decrypt_native_packet(
        self, crypto: Any, framed_packet: bytes, key: bytes
    ) -> tuple[int, bytes, bytes]:
        """Descifra el paquete completo, incluido el prefijo TCP de longitud."""
        try:
            message_type, frame = crypto.decrypt(framed_packet, key)
        except CryptoUnavailable as exc:
            raise NewcamdError(str(exc)) from exc
        if len(frame) < NATIVE_FRAME_PREFIX_SIZE or frame[HEADER_SIZE] != message_type:
            raise NewcamdError("Trama Newcamd descifrada con encabezado invalido")
        return message_type, frame[HEADER_SIZE:], frame[4:6]

    @staticmethod
    def _native_payload(body: bytes) -> bytes:
        """Extrae payload de `[tipo][longitud 2 B][payload][padding/checksum]`."""
        if len(body) < 3:
            return b""
        declared = ((body[1] & 0x0F) << 8) | body[2]
        return body[3 : 3 + declared]

    def _native_message(self, message_type: int, payload: bytes = b"", provider: int = 0) -> bytes:
        """Monta y cifra un wire packet con el layout del cliente Astra."""
        assert self._crypto is not None
        if 0x80 <= message_type <= 0x8F:
            self._msg_id = (self._msg_id + 1) & 0xFFFF
        frame = self._native_frame(message_type, payload, self._msg_id, provider)
        return self._crypto.encrypt(frame, self._key or b"")

    def _send_command(self, message_type: int, payload: bytes, sock: socket.socket, provider: int = 0) -> None:
        """Envia un comando por la via nativa o la de Python segun corresponda."""
        if self._crypto is not None:
            packet = self._native_message(message_type, payload, provider)
        else:
            self._msg_id = (self._msg_id + 1) & 0xFFFF
            packet = build_packet(message_type, payload, self._key or b"", self._msg_id, provider)
        sock.sendall(packet)

    def _receive_message(self, sock: socket.socket) -> tuple[int, bytes]:
        """Lee un mensaje del servidor por la via nativa o la de Python."""
        raw = self._recv_packet(sock)
        if self._crypto is not None:
            message_type, body, _provider = self._decrypt_native_packet(self._crypto, raw, self._key or b"")
            return message_type, self._native_payload(body)
        message_type, payload, _body, _ = parse_packet(raw, self._key or b"")
        return message_type, payload

    # -- conexion (via Python) ------------------------------------------
    def _password_field(self, mode: str) -> bytes:
        """Campo de contrasena del login segun el modo."""
        if mode == "plain":
            return self.account.password.encode("latin-1", "replace")
        return newcamd_password(self.account.password).encode("latin-1", "replace")

    def _connect_and_login(self, password_field: bytes) -> socket.socket:
        """Abre el socket, hace el handshake y envia el login.

        Devuelve el socket con la sesion iniciada; lanza `NewcamdAuthError` si el
        servidor rechaza las credenciales y `NewcamdError`/`OSError` si falla la
        red o el protocolo.
        """
        sock = socket.create_connection((self.account.host, int(self.account.port)), timeout=self.timeout)
        sock.settimeout(self.timeout)
        try:
            # La referencia de Astra (`newcamd_login_1`) lee **14 bytes** de clave
            # inicial. Leer menos deja el flujo desincronizado y el login falla.
            server_key = self._recv_exact(sock, KEY_SIZE)
            if len(server_key) < KEY_SIZE:
                raise NewcamdError("El servidor no envio los 14 bytes de clave inicial")
            self._key = derive_triple_des_key(self.account.deskey_bytes(), server_key)

            # Login: usuario + '\0' + contrasena (md5_crypt de 34 caracteres)
            payload = self.account.username.encode("latin-1", "replace") + b"\x00" + password_field
            self._msg_id = 0
            sock.sendall(build_packet(MSG_LOGIN, payload, self._key, self._msg_id))
            self.status.bytes_out += len(payload)

            raw = self._recv_packet(sock)
            message_type, _payload, _body, _ = parse_packet(raw, self._key)
            if message_type == MSG_LOGIN_NAK:
                raise NewcamdAuthError("Login rechazado (0xE2): revisa usuario, contrasena y deskey")
            if message_type != MSG_LOGIN_ACK:
                raise NewcamdAuthError(
                    "Respuesta de login inesperada (0x%02X): revisa usuario, contrasena y deskey" % message_type
                )
            return sock
        except Exception:
            _close(sock)
            raise

    def connect(self) -> NewcamdStatus:
        """Conecta, hace el handshake y el login. Devuelve el estado."""
        with self._lock:
            self.disconnect(update_state=False)
            self._key = None
            self._crypto = None
            self._msg_id = 0
            self.status = NewcamdStatus(state=STATE_CONNECTING, message="Conectando...")

        mode = (self.account.password_format or "auto").lower()
        modes = ["md5"] if mode == "md5" else ["plain"] if mode == "plain" else ["md5", "plain"]
        last_error: NewcamdAuthError | None = None
        sock: socket.socket | None = None

        if self.account.use_native_crypto:
            crypto = load_library()
            if crypto is None:
                return self._fail(
                    "Falta la biblioteca nativa de Newcamd (native/tbs_newcamd.so). "
                    "Instala build-essential y ejecuta make -C native desde tbs-webui."
                )
            for candidate in modes:
                try:
                    # Un intento por socket: Astra negocia una única variante de
                    # contraseña por sesión; cada reintento necesita otro saludo.
                    sock = self._native_login(crypto, candidate)
                    self._crypto = crypto
                    self.status.message = "Conectado y autenticado (criptografia nativa)"
                    break
                except NewcamdAuthError as exc:
                    last_error = exc
                    logger.warning("Newcamd: login nativo rechazado con formato %s", candidate)
                except OSError as exc:
                    return self._fail(f"No se pudo conectar a {self.account.host}:{self.account.port}: {exc}")
                except NewcamdError as exc:
                    return self._fail(str(exc))
        else:
            # Este camino usa DES-EDE2 estándar (Astra/NewCS); OSCam requiere
            # la biblioteca nativa de esta aplicación.
            for candidate in modes:
                try:
                    sock = self._connect_and_login(self._password_field(candidate))
                    self.status.message = "Conectado y autenticado"
                    logger.info("Newcamd: login aceptado con contrasena en formato %s", candidate)
                    break
                except NewcamdAuthError as exc:
                    last_error = exc
                    logger.warning("Newcamd: login rechazado con formato %s", candidate)
                except OSError as exc:
                    return self._fail(f"No se pudo conectar a {self.account.host}:{self.account.port}: {exc}")
                except NewcamdError as exc:
                    return self._fail(str(exc))

        if sock is None:
            return self._fail(str(last_error) if last_error else "No se pudo iniciar sesion")

        try:
            # Datos de tarjeta (nos da CAID y providers)
            self._send_command(MSG_CARD_DATA_REQ, b"", sock)
            try:
                message_type, payload = self._receive_message(sock)
                if message_type == MSG_CARD_DATA and len(payload) >= 3:
                    # Astra lee CAID en buffer[4:6], AU en [3] y num. providers
                    # en [14]; payload comienza en buffer[3].
                    self.status.caid = (payload[1] << 8) | payload[2]
                    if len(payload) > 11:
                        self.status.providers = payload[11]
            except (NewcamdError, OSError) as exc:
                logger.debug("Newcamd: sin datos de tarjeta: %s", exc)
        except (NewcamdError, OSError) as exc:
            _close(sock)
            return self._fail(str(exc))

        with self._lock:
            self._socket = sock
            self.status = NewcamdStatus(
                state=STATE_LOGGED_IN,
                message="Conectado y autenticado",
                connected_at=time.time(),
                caid=self.status.caid,
                providers=self.status.providers,
            )
        self._stop.clear()
        self._thread = threading.Thread(target=self._receive_loop, name="newcamd-rx", daemon=True)
        self._thread.start()
        logger.info(
            "Newcamd: sesion iniciada con %s:%s como '%s' (CAID=%s providers=%s)",
            self.account.host,
            self.account.port,
            self.account.username,
            self.status.caid,
            self.status.providers,
        )
        return self.status

    def disconnect(self, update_state: bool = True) -> None:
        """Cierra la conexion y el hilo de recepcion (idempotente)."""
        self._stop.set()
        with self._lock:
            sock, self._socket = self._socket, None
        if sock is not None:
            _close(sock)
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)
        if update_state:
            with self._lock:
                self.status.state = STATE_DISCONNECTED
                self.status.message = "Desconectado"

    @property
    def is_logged_in(self) -> bool:
        return self._socket is not None and self.status.state == STATE_LOGGED_IN

    # -- ECM ------------------------------------------------------------
    def send_ecm(self, ecm: bytes, service_id: int = 0, ca_system_id: int = 0x0100, provid: int = 0) -> bool:
        """Envia un ECM (tipo 0x80) y espera el control word de forma asincrona."""
        with self._lock:
            sock = self._socket
            key = self._key
        if sock is None or key is None:
            raise NewcamdError("No hay conexion Newcamd activa")

        request = EcmRequest(service_id=service_id, ca_system_id=ca_system_id, ecm=ecm, provid=provid)
        if self._crypto is not None:
            packet = self._native_message(0x80, request.payload(), provider=service_id)
        else:
            with self._lock:
                self._msg_id = (self._msg_id + 1) & 0xFFFF
                msg_id = self._msg_id
            packet = build_packet(0x80, request.payload(), key, msg_id, provider=service_id)
        try:
            sock.sendall(packet)
        except OSError as exc:
            self._fail(f"Error enviando el ECM: {exc}")
            return False
        with self._lock:
            self.status.ecm_sent += 1
            self.status.last_ecm_at = time.time()
            self.status.bytes_out += len(packet)
        return True

    # -- recepcion ------------------------------------------------------
    def _receive_loop(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                sock, key = self._socket, self._key
            if sock is None or key is None:
                break
            try:
                raw = self._recv_packet(sock)
                with self._lock:
                    self.status.bytes_in += len(raw)
                if self._crypto is not None:
                    message_type, body, provider = self._decrypt_native_packet(self._crypto, raw, key)
                    payload = self._native_payload(body)
                    self._handle_packet(message_type, payload, body, provider)
                else:
                    message_type, payload, body, _ = parse_packet(raw, key)
                    self._handle_packet(message_type, payload, body)
            except socket.timeout:
                continue
            except (OSError, NewcamdError) as exc:
                if self._stop.is_set():
                    break
                self._fail(f"Conexion perdida: {exc}")
                break
        if not self._stop.is_set():
            with self._lock:
                if self.status.state == STATE_LOGGED_IN:
                    self.status.state = STATE_DISCONNECTED
                    self.status.message = "El servidor cerro la conexion"

    def _handle_packet(
        self, message_type: int, payload: bytes, body: bytes = b"", service_id_bytes: bytes = b""
    ) -> None:
        """Procesa respuestas Newcamd siguiendo el payload del módulo Astra."""
        if message_type == MSG_KEEPALIVE:
            return
        if 0x80 <= message_type <= 0x8F:
            # Astra recibe el par de CW como 16 bytes de payload; si una mitad
            # está a cero (p. ej. NDS), conserva la otra para el diagnóstico.
            if len(payload) >= 16:
                paridad_0, paridad_1 = payload[:8], payload[8:16]
                cw = paridad_0 if any(paridad_0) else paridad_1
                if not any(cw):
                    logger.debug("Newcamd: respuesta ECM con CW vacio")
                    return
                with self._lock:
                    self.status.cw_received += 1
                    self.status.last_cw_at = time.time()
                    self.status.last_cw = cw.hex()
                logger.debug("Newcamd: control word recibido (%s)", cw.hex())
                if self.on_control_word is not None:
                    try:
                        self.on_control_word(cw, service_id_bytes)
                    except Exception:  # pragma: no cover
                        logger.exception("Error en el callback de control word")
            elif payload:
                logger.debug("Newcamd: respuesta ECM sin par de CW (len=%d)", len(payload))
            return
        logger.debug("Newcamd: paquete no reconocido tipo=0x%02X len=%d", message_type, len(body))

    # -- utilidades -----------------------------------------------------
    def _recv_packet(self, sock: socket.socket) -> bytes:
        """Lee un paquete completo (2 B de longitud + cuerpo)."""
        header = self._recv_exact(sock, 2)
        if len(header) < 2:
            raise NewcamdError("El servidor cerro la conexion")
        length = struct.unpack(">H", header)[0]
        if length <= 0 or length + 2 > MAX_PACKET:
            raise NewcamdError(f"Longitud de paquete invalida: {length}")
        body = self._recv_exact(sock, length)
        if len(body) < length:
            raise NewcamdError("Paquete incompleto")
        return header + body

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        buffer = bytearray()
        while len(buffer) < size:
            try:
                chunk = sock.recv(size - len(buffer))
            except socket.timeout:
                raise
            except OSError as exc:
                raise NewcamdError(str(exc)) from exc
            if not chunk:
                break
            buffer.extend(chunk)
        return bytes(buffer)

    def _fail(self, message: str, state: str = STATE_ERROR) -> NewcamdStatus:
        logger.warning("Newcamd (%s): %s", self.account.name, message)
        with self._lock:
            self.status.state = state
            self.status.message = message
            self.status.last_error = message
        return self.status


def _close(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Parseo de secciones ECM del flujo DVB (para conectar el escaneo con Newcamd)
# ---------------------------------------------------------------------------
def parse_ecm_section(section: bytes) -> tuple[int, int, bytes]:
    """Extrae (ca_system_id, service_id, ecm) de una seccion ECM 0x80/0x81."""
    if len(section) < 8:
        raise NewcamdError("Seccion ECM demasiado corta")
    table_id = section[0]
    if table_id not in (0x80, 0x81, 0x82):
        raise NewcamdError(f"table_id 0x{table_id:02x} no es una seccion ECM")
    section_length = ((section[1] & 0x0F) << 8) | section[2]
    total = min(len(section), 3 + section_length)
    ecm = bytes(section[:total])
    ca_system_id = struct.unpack(">H", section[3:5])[0]
    service_id = struct.unpack(">H", section[total - 4 : total - 2])[0] if total >= 8 else 0
    return ca_system_id, service_id, ecm
