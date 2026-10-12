"""Exportación de canales a M3U y channels.conf (dvbv5)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import PlainTextResponse

from ..deps import DbSession
from ..services import channels_service, exporters

router = APIRouter(prefix="/export", tags=["export"])


def _filters(q: str | None, type: str | None, fta: bool | None, scrambled: bool | None, transponder_id: int | None):
    return {
        "q": q,
        "service_type": type,
        "fta": fta,
        "scrambled": scrambled,
        "transponder_id": transponder_id,
    }


@router.get("/m3u", response_class=PlainTextResponse)
def export_m3u(
    db: DbSession,
    q: str | None = None,
    type: str | None = Query(default=None, description="TV | Radio | Data | HDTV"),
    fta: bool | None = None,
    scrambled: bool | None = None,
    transponder_id: int | None = None,
    radio: bool = Query(default=True, description="Incluir canales de radio"),
    tsdecrypt: bool = Query(default=True, description="URL tsdecrypt:// (descifrador en C) en vez de dvb://"),
) -> PlainTextResponse:
    """Descarga la lista de canales en formato M3U."""
    _, items = channels_service.list_channels(db, limit=2000, **_filters(q, type, fta, scrambled, transponder_id))
    if not items:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No hay canales que exportar")
    body = exporters.to_m3u(items, include_radio=radio, tsdecrypt=tsdecrypt)
    return PlainTextResponse(
        content=body,
        media_type="audio/x-mpegurl",
        headers={"Content-Disposition": 'attachment; filename="canales.m3u"'},
    )


@router.get("/channels.conf", response_class=PlainTextResponse)
def export_channels_conf(
    db: DbSession,
    q: str | None = None,
    type: str | None = Query(default=None, description="TV | Radio | Data | HDTV"),
    fta: bool | None = None,
    scrambled: bool | None = None,
    transponder_id: int | None = None,
) -> PlainTextResponse:
    """Descarga los canales en formato channels.conf (dvbv5-zap)."""
    _, items = channels_service.list_channels(db, limit=2000, **_filters(q, type, fta, scrambled, transponder_id))
    if not items:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No hay canales que exportar")

    services_by_transponder: dict[int, list] = {}
    transponders = {}
    for service in items:
        parent = getattr(service, "transponder", None)
        if parent is None:
            continue
        transponders[parent.id] = parent
        services_by_transponder.setdefault(parent.id, []).append(service)

    body = exporters.to_channels_conf(
        sorted(transponders.values(), key=lambda row: row.frequency_khz), services_by_transponder
    )
    return PlainTextResponse(
        content=body,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="channels.conf"'},
    )


@router.get("/tsdecrypt.conf", response_class=PlainTextResponse)
def export_tsdecrypt_conf(
    db: DbSession,
    cam_id: int | None = Query(default=None, description="Perfil Newcamd a usar (por defecto el primero habilitado)"),
    adapter: int = Query(default=0, ge=0, le=31),
    output_port: int = Query(default=1234, ge=1, le=65535),
    output_host: str = Query(default="127.0.0.1", max_length=64),
    q: str | None = None,
    transponder_id: int | None = None,
) -> PlainTextResponse:
    """Configuracion de `tsdecrypt`: el descifrador en C que habla Newcamd.

    `tsdecrypt` se conecta al servidor Newcamd por su cuenta y descifra con
    libdvbcsa, asi que el panel no implementa ni el protocolo ni el descifrado:
    solo genera el fichero con el CAM y los PNR de cada canal escaneado.
    """
    from sqlalchemy import select

    from ..models import NewcamdAccount as NewcamdAccountModel
    from ..services import newcamd_profiles as perfiles

    _, items = channels_service.list_channels(db, limit=2000, **_filters(q, None, None, None, transponder_id))
    if not items:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No hay canales que exportar")

    consulta = select(NewcamdAccountModel).where(NewcamdAccountModel.enabled.is_(True))
    if cam_id is not None:
        consulta = select(NewcamdAccountModel).where(NewcamdAccountModel.id == cam_id)
    fila = db.execute(consulta.order_by(NewcamdAccountModel.id)).scalars().first()
    if fila is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No hay ningún perfil Newcamd disponible para el CAM",
        )

    perfil = _perfil_para_export(fila, perfiles)
    cam = perfiles.cam_block(perfil)

    services_by_transponder: dict[int, list] = {}
    transponders = {}
    for service in items:
        parent = getattr(service, "transponder", None)
        if parent is None:
            continue
        transponders[parent.id] = parent
        services_by_transponder.setdefault(parent.id, []).append(service)

    body = exporters.to_tsdecrypt_conf(
        sorted(transponders.values(), key=lambda row: row.frequency_khz),
        services_by_transponder,
        cam=cam,
        adapter=adapter,
        output_port=output_port,
        output_host=output_host,
    )
    return PlainTextResponse(
        content=body,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="tsdecrypt.conf"'},
    )


def _perfil_para_export(fila, perfiles):
    """Perfil con secretos descifrados para generar la configuracion."""
    contrasena = _descifrar(fila.password_enc)
    deskey = _descifrar(getattr(fila, "deskey_enc", "") or "") or (fila.deskey or "")
    return perfiles.NewcamdProfile(
        name=fila.name,
        host=fila.host,
        port=int(fila.port),
        username=fila.username or "",
        password=contrasena,
        des_key=deskey,
        timeout=int(getattr(fila, "timeout_s", 8) or 8),
        disable_emm=bool(getattr(fila, "disable_emm", True)),
    )


def _descifrar(blob: str) -> str:
    """Descifra un secreto con la clave maestra del panel."""
    from ..config import get_settings
    from ..services import newcamd_profiles as perfiles

    return perfiles.decrypt_secret(blob, get_settings()) if blob else ""
