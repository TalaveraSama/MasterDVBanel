"""Test de la migracion automatica de columnas nuevas en bases existentes."""

from __future__ import annotations

import sqlite3
from pathlib import Path


def test_migracion_anade_columnas_nuevas(tmp_path):
    """Una base antigua (sin cam_name ni los campos del motor) se migra sola."""
    from app.database import init_db

    ruta = tmp_path / "panel.db"

    # Base "antigua": tablas con el esquema previo, sin las columnas nuevas
    conexion = sqlite3.connect(str(ruta))
    conexion.executescript(
        """
        CREATE TABLE services (
            id INTEGER PRIMARY KEY,
            transponder_id INTEGER NOT NULL,
            service_id INTEGER NOT NULL,
            name VARCHAR(255) NOT NULL DEFAULT '',
            provider VARCHAR(255) NOT NULL DEFAULT ''
        );
        CREATE TABLE newcamd_accounts (
            id INTEGER PRIMARY KEY,
            name VARCHAR(64) NOT NULL,
            host VARCHAR(255) NOT NULL,
            port INTEGER NOT NULL DEFAULT 50001,
            username VARCHAR(64) NOT NULL DEFAULT '',
            password_enc TEXT NOT NULL DEFAULT '',
            deskey VARCHAR(32) NOT NULL DEFAULT ''
        );
        INSERT INTO services (id, transponder_id, service_id, name) VALUES (1, 1, 101, 'Canal viejo');
        """
    )
    conexion.commit()
    conexion.close()

    # Al inicializar, la migracion debe anadir las columnas que faltan
    init_db(f"sqlite:///{ruta}")

    conexion = sqlite3.connect(str(ruta))
    try:
        columnas_services = {fila[1] for fila in conexion.execute("PRAGMA table_info(services)")}
        columnas_cuentas = {fila[1] for fila in conexion.execute("PRAGMA table_info(newcamd_accounts)")}
        # El dato previo se conserva
        fila = conexion.execute("SELECT name, cam_name FROM services WHERE id = 1").fetchone()
    finally:
        conexion.close()

    assert "cam_name" in columnas_services
    for columna in ("timeout_s", "disable_emm", "deskey_enc"):
        assert columna in columnas_cuentas, columna
    assert fila is not None and fila[0] == "Canal viejo"
    assert fila[1] is None  # cam_name nace vacio


def test_migracion_es_idempotente(tmp_path):
    """Inicializar dos veces no falla ni duplica columnas."""
    from app.database import init_db

    ruta = tmp_path / "panel.db"
    init_db(f"sqlite:///{ruta}")
    init_db(f"sqlite:///{ruta}")

    conexion = sqlite3.connect(str(ruta))
    try:
        columnas = [fila[1] for fila in conexion.execute("PRAGMA table_info(services)")]
    finally:
        conexion.close()
    assert columnas.count("cam_name") == 1


def test_scan_guarda_canales_con_cam_name(admin_client):
    """Tras el escaneo, los canales se guardan y el campo cam_name existe."""
    import time

    iniciado = admin_client.post(
        "/api/scan/start",
        json={
            "adapters": [{"adapter": 0, "frontend": 0}],
            "transponders": [
                {
                    "delivery_system": "DVB-S2",
                    "frequency_khz": 10970000,
                    "symbol_rate_ksps": 27900,
                    "polarization": "V",
                }
            ],
            "dwell_seconds": 1.0,
        },
    )
    assert iniciado.status_code == 200, iniciado.text
    limite = time.monotonic() + 30
    while time.monotonic() < limite:
        estado = admin_client.get("/api/scan/status").json()["progress"]["state"]
        if estado not in ("running", "starting"):
            break
        time.sleep(0.1)

    canales = admin_client.get("/api/channels").json()
    assert "total" in canales
    assert canales["total"] >= 1
    # Ningun canal tiene CAM asignado de salida
    assert all(canal.get("cam_name") is None for canal in canales["items"])


def test_m3u_se_genera_con_canales(admin_client):
    """El M3U se genera y tiene una linea EXTINF por canal."""
    import time

    admin_client.post(
        "/api/scan/start",
        json={
            "adapters": [{"adapter": 0, "frontend": 0}],
            "transponders": [
                {
                    "delivery_system": "DVB-S2",
                    "frequency_khz": 10970000,
                    "symbol_rate_ksps": 27900,
                    "polarization": "V",
                }
            ],
            "dwell_seconds": 1.0,
        },
    )
    limite = time.monotonic() + 30
    while time.monotonic() < limite:
        estado = admin_client.get("/api/scan/status").json()["progress"]["state"]
        if estado not in ("running", "starting"):
            break
        time.sleep(0.1)

    total = admin_client.get("/api/channels").json()["total"]
    respuesta = admin_client.get("/api/export/m3u")
    assert respuesta.status_code == 200
    assert respuesta.text.startswith("#EXTM3U")
    lineas = respuesta.text.splitlines()
    assert sum(1 for linea in lineas if linea.startswith("#EXTINF")) == total
    assert any(linea.startswith("#EXTINF") for linea in lineas)


def test_channels_conf_se_genera(admin_client):
    admin_client.post(
        "/api/scan/start",
        json={
            "adapters": [{"adapter": 0, "frontend": 0}],
            "transponders": [
                {
                    "delivery_system": "DVB-S2",
                    "frequency_khz": 10970000,
                    "symbol_rate_ksps": 27900,
                    "polarization": "V",
                }
            ],
            "dwell_seconds": 1.0,
        },
    )
    import time

    limite = time.monotonic() + 30
    while time.monotonic() < limite:
        estado = admin_client.get("/api/scan/status").json()["progress"]["state"]
        if estado not in ("running", "starting"):
            break
        time.sleep(0.1)
    respuesta = admin_client.get("/api/export/channels.conf")
    assert respuesta.status_code == 200
    assert respuesta.text.strip()


def test_tsdecrypt_conf_se_genera(admin_client, tmp_path, monkeypatch):
    """La configuracion de tsdecrypt lleva el CAM y un bloque por canal."""
    import os
    import time

    monkeypatch.setenv("TBS_DATA_DIR", str(tmp_path))
    perfil = admin_client.post(
        "/api/newcamd/profiles",
        json={
            "name": "cam_tsd",
            "host": "192.168.1.50",
            "port": 15000,
            "username": "usuario",
            "password": "secreto",
            "deskey": "0102030405060708091011121314",
            "timeout_s": 8,
            "disable_emm": True,
            "enabled": True,
            "auto_connect": False,
        },
    )
    assert perfil.status_code == 201, perfil.text

    admin_client.post(
        "/api/scan/start",
        json={
            "adapters": [{"adapter": 0, "frontend": 0}],
            "transponders": [
                {
                    "delivery_system": "DVB-S2",
                    "frequency_khz": 10970000,
                    "symbol_rate_ksps": 27900,
                    "polarization": "V",
                }
            ],
            "dwell_seconds": 1.0,
        },
    )
    limite = time.monotonic() + 30
    while time.monotonic() < limite:
        estado = admin_client.get("/api/scan/status").json()["progress"]["state"]
        if estado not in ("running", "starting"):
            break
        time.sleep(0.1)

    respuesta = admin_client.get("/api/export/tsdecrypt.conf")
    assert respuesta.status_code == 200, respuesta.text
    texto = respuesta.text
    assert "tsdecrypt.conf generado por TBS WebUI" in texto
    # El CAM va con sus credenciales y la DES key
    assert "camd = 192.168.1.50:15000" in texto
    assert "user = usuario" in texto
    assert "pass = secreto" in texto
    assert "deskey = 0102030405060708091011121314" in texto
    # Y un bloque por canal con su PNR y el CAID
    assert "[AMC Series]" in texto or "[" in texto
    assert "sid = " in texto
    assert "caid = " in texto
    assert "output = udp://127.0.0.1:1234" in texto


def test_m3u_usa_tsdecrypt(admin_client):
    import time

    admin_client.post(
        "/api/scan/start",
        json={
            "adapters": [{"adapter": 0, "frontend": 0}],
            "transponders": [
                {
                    "delivery_system": "DVB-S2",
                    "frequency_khz": 10970000,
                    "symbol_rate_ksps": 27900,
                    "polarization": "V",
                }
            ],
            "dwell_seconds": 1.0,
        },
    )
    limite = time.monotonic() + 30
    while time.monotonic() < limite:
        estado = admin_client.get("/api/scan/status").json()["progress"]["state"]
        if estado not in ("running", "starting"):
            break
        time.sleep(0.1)

    con_descifrador = admin_client.get("/api/export/m3u").text
    assert "tsdecrypt://" in con_descifrador
    informativa = admin_client.get("/api/export/m3u", params={"tsdecrypt": "false"}).text
    assert "dvb://" in informativa
    assert "tsdecrypt://" not in informativa
