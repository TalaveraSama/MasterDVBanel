"""Perfiles Newcamd: validacion, secretos cifrados y generacion de configuracion.

Este modulo implementa el lado **Python** de la arquitectura recomendada:

    Panel/API Python  ->  administra perfiles, servicios y configuracion
    Motor nativo (Astra/Forkcastra)  ->  cliente Newcamd, ECM/EMM, FFdecsa y salida UDP

Es decir, Python **no** descifra MPEG-TS ni implementa el protocolo: valida los
datos, guarda los secretos cifrados y **genera el script Lua** que el motor
ejecuta (`newcamd({...})` + `make_channel({...})`).

Reglas de seguridad que se aplican aqui:

  * la contrasena y la DES key se guardan **cifradas con AES-GCM** (autenticado);
  * la clave maestra vive en un fichero aparte con permisos 0600;
  * la API nunca devuelve secretos: solo `password_configured` / `des_key_configured`;
  * los valores que van al Lua se escapan y se rechazan caracteres de control;
  * la configuracion se escribe de forma atomica (temporal + `os.replace`) y se
    guarda una copia para poder revertir.
"""

from __future__ import annotations

import base64
import ipaddress
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Validacion (los mismos limites que documenta la arquitectura)
# ---------------------------------------------------------------------------
PROFILE_NAME = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,47}$")
DES_KEY = re.compile(r"^[0-9a-fA-F]{28}$")
HOSTNAME = re.compile(r"^[A-Za-z0-9._-]{1,253}$")

MAX_USERNAME = 128
MAX_PASSWORD = 256
MASTER_KEY_BYTES = 32
NONCE_BYTES = 12

# Astra resuelve `dvb://<alias>` mediante `_G[alias]`. No se presupone ningun
# alias ni se inventa un dispositivo cuando se genera la configuracion.
DVB_SOURCE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")


class ProfileError(ValueError):
    """Datos de perfil o de servicio invalidos."""


@dataclass(frozen=True)
class NewcamdProfile:
    """Perfil Newcamd tal como lo consume el motor nativo."""

    name: str
    host: str
    port: int
    username: str
    password: str
    des_key: str
    timeout: int = 8
    disable_emm: bool = True

    def validate(self) -> None:
        """Comprueba todos los campos (lanza `ProfileError` si algo no vale)."""
        if not PROFILE_NAME.fullmatch(self.name or ""):
            raise ProfileError(
                "Nombre de perfil invalido: debe empezar por letra y usar solo letras, digitos, '_' o '-' (max. 48)"
            )
        if not _valid_host(self.host):
            raise ProfileError("Host invalido: usa una IP o un nombre DNS valido")
        if not 1 <= int(self.port) <= 65535:
            raise ProfileError("Puerto invalido: debe estar entre 1 y 65535")
        if not self.username or len(self.username) > MAX_USERNAME:
            raise ProfileError(f"Usuario invalido (1-{MAX_USERNAME} caracteres)")
        if not self.password or len(self.password) > MAX_PASSWORD:
            raise ProfileError(f"Contrasena invalida (1-{MAX_PASSWORD} caracteres)")
        if not DES_KEY.fullmatch(self.des_key or ""):
            raise ProfileError("La DES key debe contener exactamente 28 caracteres hexadecimales")
        if not 1 <= int(self.timeout) <= 60:
            raise ProfileError("Timeout invalido: debe estar entre 1 y 60 segundos")

    def public_dict(self) -> dict[str, Any]:
        """Representacion **sin secretos** (lo que devuelve la API)."""
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password_configured": bool(self.password),
            "des_key_configured": bool(self.des_key),
            "timeout": self.timeout,
            "disable_emm": self.disable_emm,
        }


def _valid_host(host: str) -> bool:
    """Acepta IPv4/IPv6 o un nombre DNS (no solo direcciones IP)."""
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME.fullmatch(host)) and not host.startswith("-")


# ---------------------------------------------------------------------------
# Secretos: AES-GCM con clave maestra en fichero 0600
# ---------------------------------------------------------------------------
def master_key_path(settings: Any) -> Path:
    """Ruta de la clave maestra (por defecto `<data_dir>/master.key`)."""
    override = os.environ.get("TBS_MASTER_KEY_FILE")
    if override:
        return Path(override)
    data_dir = Path(getattr(settings, "data_dir", None) or ".")
    return data_dir / "master.key"


def load_master_key(settings: Any) -> bytes:
    """Carga (o crea) la clave maestra de 32 bytes con permisos 0600."""
    path = master_key_path(settings)
    if path.is_file():
        data = path.read_bytes()
        if len(data) >= MASTER_KEY_BYTES:
            return data[:MASTER_KEY_BYTES]
        logger.warning("La clave maestra %s es demasiado corta; se regenera", path)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(MASTER_KEY_BYTES)
    temp = path.with_suffix(".tmp")
    temp.write_bytes(key)
    try:
        os.chmod(temp, 0o600)
    except OSError:  # pragma: no cover - Windows
        pass
    os.replace(temp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - Windows
        pass
    logger.info("Clave maestra de secretos creada en %s (0600)", path)
    return key


def encrypt_secret(plain: str, settings: Any) -> str:
    """Cifra un secreto con AES-GCM. Devuelve base64(nonce || ciphertext || tag)."""
    if not plain:
        return ""
    from Crypto.Cipher import AES

    aes = AES.new(load_master_key(settings), AES.MODE_GCM, nonce=os.urandom(NONCE_BYTES))
    ciphertext, tag = aes.encrypt_and_digest(plain.encode("utf-8"))
    return base64.b64encode(aes.nonce + ciphertext + tag).decode("ascii")


def decrypt_secret(blob: str, settings: Any) -> str:
    """Descifra un secreto de AES-GCM (devuelve '' si no es valido)."""
    if not blob:
        return ""
    from Crypto.Cipher import AES

    try:
        raw = base64.b64decode(blob, validate=True)
    except Exception:  # noqa: BLE001 - blob corrupto
        return ""
    if len(raw) < NONCE_BYTES + 16:
        return ""
    nonce = raw[:NONCE_BYTES]
    tag = raw[-16:]
    ciphertext = raw[NONCE_BYTES:-16]
    try:
        aes = AES.new(load_master_key(settings), AES.MODE_GCM, nonce=nonce)
        return aes.decrypt_and_verify(ciphertext, tag).decode("utf-8")
    except Exception:  # noqa: BLE001 - clave distinta o dato manipulado
        logger.warning("No se pudo descifrar un secreto (clave maestra distinta o dato alterado)")
        return ""


# ---------------------------------------------------------------------------
# Generacion de la configuracion del motor (Lua)
# ---------------------------------------------------------------------------
def lua_string(value: str) -> str:
    """Escapa una cadena para Lua y rechaza caracteres de control."""
    if any(char in value for char in ("\x00", "\n", "\r")):
        raise ProfileError("Caracteres no permitidos en la configuracion")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def service_cam_name(service_id: int) -> str:
    """Alias Lua estable y exclusivo para la instancia Newcamd de un canal.

    Se usa la clave primaria de `services`, no el PNR, porque el mismo PNR
    puede repetirse en transponders distintos. En Astra cada alias `newcamd`
    tiene su propio objeto CAM y, por tanto, su propio socket OSCam.
    """
    try:
        value = int(service_id)
    except (TypeError, ValueError) as exc:
        raise ProfileError("Id de canal invalido para crear la instancia Newcamd") from exc
    if not 1 <= value <= 9_223_372_036_854_775_807:
        raise ProfileError("Id de canal fuera de rango")
    return f"newcamd_service_{value}"


def _lua_global_lhs(name: str) -> str:
    """Referencia asignable a `_G`, incluso para nombres de perfil con guion."""
    if not PROFILE_NAME.fullmatch(name or ""):
        raise ProfileError("Nombre de instancia Newcamd invalido")
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        return name
    return f"_G[{lua_string(name)}]"


def render_newcamd(profile: NewcamdProfile, instance_name: str | None = None) -> str:
    """Genera una instancia nativa Newcamd con alias Lua propio.

    Si varios canales comparten un perfil, se llama una vez por canal con un
    `instance_name` distinto: el fork Astra no comparte el socket entre objetos.
    """
    profile.validate()
    name = instance_name or profile.name
    lhs = _lua_global_lhs(name)
    return (
        f"{lhs} = newcamd({{\n"
        f"    name = {lua_string(name)},\n"
        f"    host = {lua_string(profile.host)},\n"
        f"    port = {int(profile.port)},\n"
        f"    user = {lua_string(profile.username)},\n"
        f"    pass = {lua_string(profile.password)},\n"
        f"    key = {lua_string(profile.des_key.lower())},\n"
        f"    timeout = {int(profile.timeout)},\n"
        f"    disable_emm = {1 if profile.disable_emm else 0},\n"
        f"}})"
    )


def render_service(
    name: str,
    tuner_name: str,
    pnr: int,
    output_url: str | None = None,
    profile: str | None = None,
) -> str:
    """Genera `make_channel` usando un alias DVB real y, opcionalmente, salida.

    No hay fallback a `tuner_1` ni a un puerto UDP inventado. El alias debe
    corresponder a un objeto DVB declarado por la configuracion Astra existente.
    Sin `output_url`, el fork mantiene su analizador de entrada; no se crea una
    salida de red que pueda colisionar con otros servicios.
    """
    if not 1 <= int(pnr) <= 65535:
        raise ProfileError("PNR invalido: debe estar entre 1 y 65535")
    if not DVB_SOURCE_NAME.fullmatch(tuner_name or ""):
        raise ProfileError("Falta un alias DVB de Astra valido para el canal")
    opciones = [f"pnr={int(pnr)}"]
    if profile:
        if not PROFILE_NAME.fullmatch(profile):
            raise ProfileError("Instancia Newcamd invalida")
        opciones.append(f"cam={profile}")
    input_url = f"dvb://{tuner_name}#" + "&".join(opciones)
    lineas = [
        "make_channel({",
        f"    name = {lua_string(name)},",
        f"    input = {{ {lua_string(input_url)} }},",
    ]
    if output_url:
        lineas.append(f"    output = {{ {lua_string(output_url)} }},")
    lineas.append("})")
    return "\n".join(lineas)


# ---------------------------------------------------------------------------
# Bloque `cam` del motor y asignacion por canal
# (mismo modelo que ya funciona en el panel anterior: softcams con nombre que
#  el agente pasa a `newcamd({...})` y a `decrypt({ cam = ... })`)
# ---------------------------------------------------------------------------
def cam_block(profile: NewcamdProfile, instance_name: str | None = None) -> dict[str, Any]:
    """Bloque `cam` nativo con alias por canal (no comparte el objeto CAM).

    Los campos de conexión provienen del perfil; `softcam` identifica la
    instancia Newcamd exclusiva que la configuración Lua debe crear para ese
    canal.
    """
    alias = instance_name or profile.name
    if not PROFILE_NAME.fullmatch(alias):
        raise ProfileError("Instancia Newcamd invalida")
    cam: dict[str, Any] = {
        "host": profile.host,
        "port": int(profile.port),
        "user": profile.username,
        "softcam": alias,
    }
    if profile.password:
        cam["pass"] = profile.password
    if profile.des_key:
        cam["key"] = profile.des_key.upper()
    if profile.disable_emm:
        cam["disable_emm"] = 1
    return cam


def apply_cam_to_service(service: dict[str, Any], cam: dict[str, Any] | None) -> dict[str, Any]:
    """Pone (o quita, con `cam=None`) el CAM en las entradas DVB del servicio.

    Regla aprendida del panel que funciona: **nunca** se fija `ecm_pid`, porque
    el motor se saltaria la PMT y no encontraria el CAID.
    """
    copia = dict(service)
    entradas = []
    for entrada in service.get("inputs") or []:
        if not isinstance(entrada, dict):
            entradas.append(entrada)
            continue
        if str(entrada.get("type", "")).lower() != "dvb":
            entradas.append(entrada)
            continue
        opciones = dict(entrada.get("options") or {})
        opciones.pop("ecm_pid", None)
        if cam is None:
            opciones.pop("cam", None)
        else:
            opciones["cam"] = dict(cam)
        entradas.append({**entrada, "options": opciones})
    copia["inputs"] = entradas
    return copia


def service_dvb_url(service: dict[str, Any]) -> str | None:
    """URL `dvb://` del servicio con sus opciones (pnr, cam...), si es DVB."""
    for entrada in service.get("inputs") or []:
        if not isinstance(entrada, dict):
            continue
        if str(entrada.get("type", "")).lower() != "dvb":
            continue
        tuner = (
            entrada.get("engine_input_name")
            or entrada.get("tuner")
            or entrada.get("device")
            or entrada.get("name")
        )
        if not isinstance(tuner, str) or not DVB_SOURCE_NAME.fullmatch(tuner):
            return None
        opciones = entrada.get("options") or {}
        partes = [f"{clave}={valor}" for clave, valor in opciones.items() if not isinstance(valor, dict)]
        if isinstance(opciones.get("cam"), dict):
            partes.append("cam=" + str(opciones["cam"].get("softcam") or "cam"))
        sufijo = ("#" + "&".join(partes)) if partes else ""
        return f"dvb://{tuner}{sufijo}"
    return None


def render_config(profiles: list[NewcamdProfile], services: list[dict[str, Any]]) -> str:
    """Lua para Astra: un objeto Newcamd distinto por servicio asignado.

    `services` debe contener el id de fila (`id`), PNR, `tuner_name` (alias DVB
    ya declarado en el script principal) y `newcamd_profile`. No se generan
    rutas de salida por defecto. Con lista vacia se emiten perfiles sin asignar,
    que son plantillas inactivas y no abren conexiones por si solas.
    """
    lineas = [
        "-- Generado por TBS WebUI. NO editar a mano: se sobrescribe al aplicar.",
        f"-- Fecha: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    perfiles = {profile.name: profile for profile in profiles}
    if not services:
        for profile in profiles:
            lineas.append(render_newcamd(profile))
            lineas.append("")
        return "\n".join(lineas).rstrip() + "\n"

    lineas.extend(
        [
            "-- Cada canal usa una instancia Newcamd propia (una sesion OSCam por servicio).",
            "-- Los alias DVB deben existir en la configuracion Astra incluida antes de este fragmento.",
            "",
        ]
    )
    usados: set[str] = set()
    for service in services:
        service_id = service.get("id")
        instance_name = service.get("cam_instance") or service_cam_name(service_id)
        if instance_name in usados:
            raise ProfileError(f"Instancia Newcamd duplicada: {instance_name}")
        usados.add(instance_name)
        profile_name = service.get("newcamd_profile") or service.get("cam_name")
        profile = perfiles.get(profile_name)
        if profile is None:
            raise ProfileError(f"El canal {service_id} referencia un perfil no habilitado: {profile_name}")
        tuner_name = service.get("tuner_name") or service.get("engine_input_name")
        pnr = service.get("pnr") or service.get("service_id")
        lineas.append(f"-- Servicio #{service_id}: {service.get('name') or 'Canal'}")
        lineas.append(render_newcamd(profile, instance_name=instance_name))
        lineas.append(
            render_service(
                name=service.get("name") or "Canal",
                tuner_name=tuner_name,
                pnr=int(pnr or 0),
                output_url=service.get("output_url"),
                profile=instance_name,
            )
        )
        lineas.append("")
    return "\n".join(lineas).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Aplicacion atomica con rollback
# ---------------------------------------------------------------------------
def atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    """Escribe un fichero de forma atomica y con permisos restrictivos."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(content, encoding="utf-8")
    try:
        os.chmod(temp, mode)
    except OSError:  # pragma: no cover - Windows
        pass
    os.replace(temp, path)


@dataclass
class ApplyResult:
    """Resultado de aplicar la configuracion al motor."""

    ok: bool
    path: str
    backup: str | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "path": self.path, "backup": self.backup, "detail": self.detail}


def apply_config(config_path: Path, content: str, backup_path: Path | None = None) -> ApplyResult:
    """Instala la configuracion guardando antes una copia de seguridad.

    No reinicia el motor (eso lo hace el ayudante privilegiado o el operador);
    deja la configuracion lista y la copia para poder revertir.
    """
    copia: str | None = None
    if backup_path is None:
        backup_path = config_path.with_suffix(config_path.suffix + ".bak")
    if config_path.is_file():
        try:
            shutil.copy2(config_path, backup_path)
            copia = str(backup_path)
        except OSError as exc:  # pragma: no cover - permisos
            logger.warning("No se pudo guardar la copia de la configuracion: %s", exc)
    try:
        atomic_write(config_path, content)
    except OSError as exc:
        return ApplyResult(ok=False, path=str(config_path), backup=copia, detail=f"No se pudo escribir: {exc}")
    return ApplyResult(
        ok=True,
        path=str(config_path),
        backup=copia,
        detail="Fragmento Lua escrito; incluye el archivo y recarga Astra para aplicarlo",
    )


def rollback_config(config_path: Path, backup_path: Path | None = None) -> ApplyResult:
    """Restaura la configuracion anterior desde la copia de seguridad."""
    if backup_path is None:
        backup_path = config_path.with_suffix(config_path.suffix + ".bak")
    if not backup_path.is_file():
        return ApplyResult(ok=False, path=str(config_path), detail="No hay copia de seguridad para revertir")
    try:
        shutil.copy2(backup_path, config_path)
    except OSError as exc:
        return ApplyResult(ok=False, path=str(config_path), backup=str(backup_path), detail=f"No se pudo revertir: {exc}")
    return ApplyResult(ok=True, path=str(config_path), backup=str(backup_path), detail="Configuracion anterior restaurada")


# ---------------------------------------------------------------------------
# Comprobacion de conectividad (solo TCP: no expone credenciales)
# ---------------------------------------------------------------------------
def test_tcp_connection(host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
    """Comprueba si host:puerto acepta conexiones TCP.

    Importante: esto **solo** valida la red. No confirma login Newcamd, ni
    tarjeta disponible, ni CAID compatible, ni ECM aceptado. Esa validacion
    completa la hace el motor nativo.
    """
    import socket

    if not _valid_host(host):
        return {"reachable": False, "error": "host invalido"}
    if not 1 <= int(port) <= 65535:
        return {"reachable": False, "error": "puerto invalido"}

    started = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return {
                "reachable": True,
                "latency_ms": int((time.monotonic() - started) * 1000),
                "detail": "TCP accesible (el login lo valida el motor nativo)",
            }
    except OSError as error:
        return {"reachable": False, "error": str(error), "latency_ms": int((time.monotonic() - started) * 1000)}
