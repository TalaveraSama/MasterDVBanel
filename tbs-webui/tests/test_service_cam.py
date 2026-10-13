"""Tests de asignacion de perfil Newcamd (softcam) a cada canal."""

from __future__ import annotations

import itertools

from app.database import get_sessionmaker
from app.models import Service, Transponder

_CONTADOR = itertools.count()


def _perfil(**cambios) -> dict:
    base = {
        "name": f"cam_{next(_CONTADOR)}",
        "host": "192.168.1.50",
        "port": 15000,
        "username": "usuario",
        "password": "secreto",
        "deskey": "0102030405060708091011121314",
        "timeout_s": 8,
        "disable_emm": True,
        "enabled": True,
        "auto_connect": False,
    }
    base.update(cambios)
    return base


def _canal(service_id: int = 101) -> int:
    """Crea un transponder con un canal y devuelve el id del canal."""
    sesion = get_sessionmaker()()
    try:
        tp = (
            sesion.query(Transponder)
            .filter_by(delivery_system="DVB-S2", frequency_khz=10970000, polarization="V", symbol_rate_ksps=27900)
            .one_or_none()
        )
        if tp is None:
            tp = Transponder(delivery_system="DVB-S2", frequency_khz=10970000, polarization="V", symbol_rate_ksps=27900)
            sesion.add(tp)
            sesion.flush()
        canal = Service(
            transponder_id=tp.id,
            service_id=service_id,
            name="A&E HD" if service_id == 101 else f"Canal {service_id}",
            provider="Prov",
            service_type=25,
            service_type_label="HDTV",
            is_fta=False,
            scrambled=True,
        )
        sesion.add(canal)
        sesion.commit()
        return canal.id
    finally:
        sesion.close()


def test_asignar_perfil_a_canal(admin_client):
    perfil = admin_client.post("/api/newcamd/profiles", json=_perfil()).json()
    canal_id = _canal()

    respuesta = admin_client.put(
        f"/api/newcamd/services/{canal_id}/cam",
        json={"cam_name": perfil["name"], "engine_input_name": "panel_dvb_1"},
    )
    assert respuesta.status_code == 200, respuesta.text
    cuerpo = respuesta.json()
    assert cuerpo["ok"] is True
    assert cuerpo["cam_instance"] == f"newcamd_service_{canal_id}"
    assert cuerpo["cam"]["softcam"] == cuerpo["cam_instance"]
    assert cuerpo["cam"]["host"] == "192.168.1.50"
    assert cuerpo["cam"]["port"] == 15000
    assert cuerpo["cam"]["disable_emm"] == 1
    assert "password" not in cuerpo["cam"] or cuerpo["cam"].get("pass") == "secreto"
    assert cuerpo["runtime_ready"] is True
    assert cuerpo["dvb_url"] == (
        f"dvb://panel_dvb_1#pnr=101&cam=newcamd_service_{canal_id}"
    )


def test_asignacion_sin_fuente_no_fabrica_tuner(admin_client):
    perfil = admin_client.post("/api/newcamd/profiles", json=_perfil()).json()
    canal_id = _canal()
    respuesta = admin_client.put(
        f"/api/newcamd/services/{canal_id}/cam", json={"cam_name": perfil["name"]}
    )
    assert respuesta.status_code == 200
    assert respuesta.json()["dvb_url"] is None
    assert respuesta.json()["runtime_ready"] is False
    assert respuesta.json()["engine_input_name"] is None


def test_fuente_dvb_valida_se_guarda_sin_cambiar_perfil(admin_client):
    perfil = admin_client.post("/api/newcamd/profiles", json=_perfil()).json()
    canal_id = _canal()
    admin_client.put(f"/api/newcamd/services/{canal_id}/cam", json={"cam_name": perfil["name"]})
    respuesta = admin_client.put(
        f"/api/newcamd/services/{canal_id}/cam", json={"engine_input_name": "astra_dvb_2"}
    )
    assert respuesta.status_code == 200
    assert respuesta.json()["cam_name"] == perfil["name"]
    assert respuesta.json()["runtime_ready"] is True
    assert "dvb://astra_dvb_2#pnr=101&cam=" in respuesta.json()["dvb_url"]


def test_fuente_dvb_invalida_se_rechaza(admin_client):
    canal_id = _canal()
    respuesta = admin_client.put(
        f"/api/newcamd/services/{canal_id}/cam", json={"engine_input_name": "dvb#0&cam=evil"}
    )
    assert respuesta.status_code == 422


def test_quitar_perfil_de_canal(admin_client):
    perfil = admin_client.post("/api/newcamd/profiles", json=_perfil()).json()
    canal_id = _canal()
    admin_client.put(f"/api/newcamd/services/{canal_id}/cam", json={"cam_name": perfil["name"]})

    quitado = admin_client.put(f"/api/newcamd/services/{canal_id}/cam", json={"cam_name": None})
    assert quitado.status_code == 200
    assert quitado.json()["cam"] is None
    assert admin_client.get("/api/newcamd/services/cam").json()["total"] == 0


def test_apply_no_omite_silenciosamente_fuente_dvb_faltante(admin_client):
    perfil = admin_client.post("/api/newcamd/profiles", json=_perfil()).json()
    canal_id = _canal()
    admin_client.put(f"/api/newcamd/services/{canal_id}/cam", json={"cam_name": perfil["name"]})
    respuesta = admin_client.post("/api/newcamd/config/apply")
    assert respuesta.status_code == 422
    assert "alias de la fuente DVB" in respuesta.json()["detail"]


def test_apply_genera_una_sesion_newcamd_por_canal(admin_client):
    perfil = admin_client.post("/api/newcamd/profiles", json=_perfil()).json()
    ids = [_canal(101), _canal(102)]
    for canal_id in ids:
        respuesta = admin_client.put(
            f"/api/newcamd/services/{canal_id}/cam",
            json={"cam_name": perfil["name"], "engine_input_name": "astra_sat_source"},
        )
        assert respuesta.status_code == 200, respuesta.text

    preview = admin_client.get("/api/newcamd/config")
    assert preview.status_code == 200, preview.text
    lua = preview.json()["lua"]
    assert lua.count("= newcamd({") == 2
    assert f"newcamd_service_{ids[0]} = newcamd({{" in lua
    assert f"newcamd_service_{ids[1]} = newcamd({{" in lua
    assert f"cam=newcamd_service_{ids[0]}" in lua
    assert f"cam=newcamd_service_{ids[1]}" in lua
    assert "output =" not in lua

    aplicado = admin_client.post("/api/newcamd/config/apply")
    assert aplicado.status_code == 200, aplicado.text
    with open(aplicado.json()["path"], encoding="utf-8") as handle:
        assert handle.read().count("= newcamd({") == 2


def test_listar_canales_con_cam(admin_client):
    perfil = admin_client.post("/api/newcamd/profiles", json=_perfil()).json()
    canal_id = _canal()
    admin_client.put(f"/api/newcamd/services/{canal_id}/cam", json={"cam_name": perfil["name"]})

    datos = admin_client.get("/api/newcamd/services/cam").json()
    assert datos["total"] == 1
    item = datos["items"][0]
    assert item["id"] == canal_id
    assert item["cam_name"] == perfil["name"]
    assert item["cam_instance"] == f"newcamd_service_{canal_id}"
    assert item["runtime_ready"] is False
    assert item["engine_input_name"] is None
    assert item["name"] == "A&E HD"
    assert item["scrambled"] is True


def test_perfil_inexistente(admin_client):
    canal_id = _canal()
    respuesta = admin_client.put(f"/api/newcamd/services/{canal_id}/cam", json={"cam_name": "no_existe"})
    assert respuesta.status_code == 404


def test_canal_inexistente(admin_client):
    assert (
        admin_client.put("/api/newcamd/services/999999/cam", json={"cam_name": "x"}).status_code == 404
    )


def test_nombre_de_perfil_invalido(admin_client):
    canal_id = _canal()
    respuesta = admin_client.put(f"/api/newcamd/services/{canal_id}/cam", json={"cam_name": "1 malo"})
    assert respuesta.status_code == 422


def test_requiere_sesion(client):
    assert client.put("/api/newcamd/services/1/cam", json={"cam_name": "x"}).status_code == 401
    assert client.get("/api/newcamd/services/cam").status_code == 401


def test_perfil_incompleto_no_se_asigna(admin_client):
    """Un perfil sin contrasena guardada no se puede asignar a un canal."""
    from app.models import NewcamdAccount

    creado = admin_client.post("/api/newcamd/profiles", json=_perfil()).json()
    sesion = get_sessionmaker()()
    try:
        fila = sesion.query(NewcamdAccount).filter(NewcamdAccount.id == creado["id"]).one()
        fila.password_enc = ""
        sesion.commit()
    finally:
        sesion.close()

    canal_id = _canal()
    respuesta = admin_client.put(
        f"/api/newcamd/services/{canal_id}/cam", json={"cam_name": creado["name"]}
    )
    assert respuesta.status_code == 422
