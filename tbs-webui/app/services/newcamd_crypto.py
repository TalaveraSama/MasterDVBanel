"""Puente a `libtbsnewcamd.so`: la criptografia real del protocolo Newcamd.

OSCam **no** usa DES estandar (aplica `doPC1()` y su propio `EuroDes`), asi que
el login solo funciona si se cifra con este codigo. El instalador compila y
prueba la biblioteca; en una instalación manual se crea con `make -C native`
desde la raíz de `tbs-webui` (fuente en `native/tbs_newcamd.c`).

Uso desde el cliente:

    crypto = load_library()          # None si no esta compilada
    if crypto is None:
        # aviso: sin la biblioteca no se puede autenticar contra OSCam
        ...
    key = crypto.login_key(server_key, deskey, len(deskey))
    wire_packet = crypto.encrypt(frame, key)  # frame incluye 2 bytes de longitud
    tipo, trama = crypto.decrypt(wire_packet, key)
"""

from __future__ import annotations

import ctypes
import logging
import os
from ctypes import POINTER, c_int, c_ubyte
from pathlib import Path

logger = logging.getLogger(__name__)

LIB_NAME = "tbs_newcamd.so"
ENV_VAR = "TBS_NEWCAMD_LIB"

# El framing sigue modules/softcam/cam/newcamd.c de Astra:
# [2 bytes de longitud][10 bytes de cabecera][tipo][longitud payload][payload].
NEWCAMD_HEADER_SIZE = 12
NEWCAMD_FRAME_PREFIX_SIZE = NEWCAMD_HEADER_SIZE + 3

# Rutas donde se busca la biblioteca, en orden
SEARCH_DIRS = (
    Path(__file__).resolve().parents[2] / "native",  # tbs-webui/native
    Path("/usr/local/lib"),
    Path("/usr/lib"),
)

__all__ = ["NewcamdCrypto", "load_library", "library_path", "is_available", "CryptoUnavailable"]


class CryptoUnavailable(RuntimeError):
    """La biblioteca nativa de Newcamd no esta compilada o no se puede cargar."""


class NewcamdCrypto:
    """Envoltorio de la biblioteca C (criptografia Newcamd de OSCam)."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        try:
            self._lib = ctypes.CDLL(self.path)
        except OSError as exc:  # pragma: no cover - depende del sistema
            raise CryptoUnavailable(f"No se pudo cargar {self.path}: {exc}") from exc

        self._lib.nc_login_key_get.restype = c_int
        self._lib.nc_login_key_get.argtypes = [
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_int,
            POINTER(c_ubyte),
        ]
        self._lib.nc_encrypt.restype = c_int
        self._lib.nc_encrypt.argtypes = [POINTER(c_ubyte), c_int, POINTER(c_ubyte)]
        self._lib.nc_decrypt.restype = c_int
        self._lib.nc_decrypt.argtypes = [POINTER(c_ubyte), c_int, POINTER(c_ubyte)]

    # -- API ------------------------------------------------------------
    def login_key(self, server_key: bytes, client_key: bytes, length: int | None = None) -> bytes:
        """Deriva la clave Newcamd de 16 bytes para el saludo de 14 bytes."""
        if len(server_key) != 14:
            raise CryptoUnavailable("La clave inicial del servidor debe tener 14 bytes")
        if len(client_key) != 14:
            raise CryptoUnavailable("La deskey debe tener 14 bytes")
        size = 14 if length is None else int(length)
        if not 0 <= size <= 14:
            raise CryptoUnavailable("La longitud de la deskey debe estar entre 0 y 14")
        salida = (c_ubyte * 16)()
        servidor = (c_ubyte * 14).from_buffer_copy(server_key)
        cliente = (c_ubyte * 14).from_buffer_copy(client_key)
        resultado = self._lib.nc_login_key_get(servidor, cliente, size, salida)
        if resultado != 0:
            raise CryptoUnavailable("nc_login_key_get devolvio error")
        return bytes(bytearray(salida))

    def encrypt(self, frame: bytes, key: bytes) -> bytes:
        """Cifra una trama Astra/Newcamd completa y devuelve el wire packet.

        ``frame`` incluye los dos bytes iniciales reservados para longitud,
        la cabecera Newcamd de 12 bytes y el encabezado de mensaje de 3 bytes.
        La C cifra desde el offset 2; aquí se escribe la longitud final que
        Astra pone en esos dos bytes después de añadir padding, checksum e IV.
        """
        if len(key) != 16:
            raise CryptoUnavailable("La clave de sesion debe tener 16 bytes")
        if len(frame) < NEWCAMD_FRAME_PREFIX_SIZE:
            raise CryptoUnavailable("La trama debe incluir cabecera Newcamd y encabezado de mensaje")
        buffer = (c_ubyte * (len(frame) + 32))()
        for index, byte in enumerate(frame):
            buffer[index] = byte
        # Astra reserva el prefijo y lo escribe después del cifrado.
        buffer[0] = 0
        buffer[1] = 0
        clave = (c_ubyte * 16).from_buffer_copy(key)
        tamano = self._lib.nc_encrypt(buffer, len(frame), clave)
        if tamano <= 0:
            raise CryptoUnavailable(f"nc_encrypt devolvio {tamano}")
        longitud = tamano - 2
        if longitud > 0xFFFF:
            raise CryptoUnavailable("La trama Newcamd excede la longitud TCP permitida")
        buffer[0] = (longitud >> 8) & 0xFF
        buffer[1] = longitud & 0xFF
        return bytes(bytearray(buffer)[:tamano])

    def decrypt(self, packet: bytes, key: bytes) -> tuple[int, bytes]:
        """Descifra el wire packet completo y devuelve ``(tipo, trama)``.

        El prefijo TCP de dos bytes se pasa a C, no se elimina: la rutina de
        Astra/OSCam cifra y descifra desde el offset 2. ``trama`` conserva los
        12 bytes de cabecera, luego tipo/longitud/payload, padding y checksum.
        """
        if len(key) != 16:
            raise CryptoUnavailable("La clave de sesion debe tener 16 bytes")
        if len(packet) < NEWCAMD_FRAME_PREFIX_SIZE + 11:
            raise CryptoUnavailable("Paquete demasiado corto")
        longitud = int.from_bytes(packet[:2], "big")
        if longitud + 2 != len(packet):
            raise CryptoUnavailable("La longitud TCP no coincide con el paquete Newcamd")
        buffer = (c_ubyte * (len(packet) + 8))()
        for index, byte in enumerate(packet):
            buffer[index] = byte
        clave = (c_ubyte * 16).from_buffer_copy(key)
        tamano = self._lib.nc_decrypt(buffer, len(packet), clave)
        if tamano < NEWCAMD_FRAME_PREFIX_SIZE or tamano > len(packet) - 8:
            raise CryptoUnavailable("nc_decrypt: checksum incorrecto o tamano invalido")
        datos = bytes(bytearray(buffer)[:tamano])
        if len(datos) < NEWCAMD_FRAME_PREFIX_SIZE:
            raise CryptoUnavailable("Trama Newcamd descifrada demasiado corta")
        return datos[NEWCAMD_HEADER_SIZE], datos

    def self_test(self) -> bool:
        """Valida una trama con los offsets de red definidos por Astra."""
        key = self.login_key(bytes(14), bytes.fromhex("0102030405060708091011121314"))
        payload = b"astra\x00" + b"$1$abcdefgh$lU.OJ3dCh8uiqm.kfyIdF."
        frame = bytearray(NEWCAMD_FRAME_PREFIX_SIZE)
        frame[NEWCAMD_HEADER_SIZE] = 0xE0
        frame[NEWCAMD_HEADER_SIZE + 1 : NEWCAMD_HEADER_SIZE + 3] = len(payload).to_bytes(2, "big")
        frame.extend(payload)
        packet = self.encrypt(bytes(frame), key)
        message_type, decoded = self.decrypt(packet, key)
        payload_start = NEWCAMD_FRAME_PREFIX_SIZE
        return (
            message_type == 0xE0
            and decoded[NEWCAMD_HEADER_SIZE] == 0xE0
            and decoded[payload_start : payload_start + len(payload)] == payload
        )


def library_path() -> Path | None:
    """Ruta de la biblioteca compilada, o None si no se encuentra."""
    override = os.environ.get(ENV_VAR)
    if override:
        candidate = Path(override)
        return candidate if candidate.is_file() else None
    for directory in SEARCH_DIRS:
        candidate = directory / LIB_NAME
        if candidate.is_file():
            return candidate
    return None


_cache: NewcamdCrypto | None = None
_cache_error: str | None = None


def load_library(force: bool = False) -> NewcamdCrypto | None:
    """Carga la biblioteca (None si no esta disponible). Silenciosa por diseno."""
    global _cache, _cache_error
    if _cache is not None and not force:
        return _cache
    path = library_path()
    if path is None:
        _cache_error = (
            f"No se encontro {LIB_NAME}. Compilala con: make -C native "
            "(requiere build-essential; ver README, seccion 6.2)."
        )
        logger.debug("Newcamd nativo no disponible: %s", _cache_error)
        return None
    try:
        _cache = NewcamdCrypto(path)
        _cache_error = None
        logger.info("Criptografia Newcamd nativa cargada desde %s", path)
        return _cache
    except CryptoUnavailable as exc:
        _cache_error = str(exc)
        logger.warning("No se pudo cargar la criptografia Newcamd nativa: %s", exc)
        return None


def is_available() -> bool:
    """True si la biblioteca nativa esta compilada y se puede usar."""
    return load_library() is not None


def unavailable_reason() -> str | None:
    """Motivo por el que la biblioteca no esta disponible (None si si lo esta)."""
    load_library()
    return _cache_error
