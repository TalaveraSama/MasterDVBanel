#!/usr/bin/env python3
"""Escaneo real + comprobacion de canales guardados y exportacion M3U."""

from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.getcwd())
import httpx

BASE = os.environ.get("TBS_BASE", "http://127.0.0.1:9000")
PASSWORD = os.environ.get("TBS_ADMIN_PASSWORD", "prueba-servicio-2026")

cliente = httpx.Client(base_url=BASE, timeout=180.0)
entrada = cliente.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
if entrada.status_code != 200:
    print("login fallo:", entrada.status_code)
    sys.exit(1)
cabeceras = {"X-CSRF-Token": entrada.json()["csrf_token"]}
print("sesion iniciada")

inicio = cliente.post(
    "/api/scan/start",
    json={
        "adapters": [{"adapter": 0, "frontend": 0}],
        "current_only": True,
        "dwell_seconds": 8,
        "lock_timeout_s": 8,
    },
    headers=cabeceras,
)
print("scan/start:", inicio.status_code, inicio.text[:140])
if inicio.status_code != 200:
    sys.exit(1)

limite = time.monotonic() + 120
ultimo = ""
while time.monotonic() < limite:
    cuerpo = cliente.get("/api/scan/status").json()
    progreso = cuerpo["progress"]
    if progreso.get("message") != ultimo:
        ultimo = progreso.get("message") or ""
        print(f"   [{progreso['state']}] {ultimo[:110]}")
    if progreso["state"] not in ("running", "starting"):
        break
    time.sleep(0.8)

print("\n=== LOG DEL ESCANEO ===")
for linea in cuerpo.get("log", []):
    print("   ", linea["level"], "|", linea["msg"][:120])

print("\n=== CANALES GUARDADOS ===")
canales = cliente.get("/api/channels", params={"limit": 500}).json()
print("total en la base de datos:", canales["total"])
for canal in canales["items"][:12]:
    print(
        f"   {canal.get('display_name') or canal['name']}",
        f"| PNR {canal['service_id']}",
        f"| {canal.get('service_type_label')}",
        f"| {'FTA' if canal.get('is_fta') else 'cifrado'}",
        f"| CAM {canal.get('cam_name') or '-'}",
    )

print("\n=== EXPORTACION M3U ===")
m3u = cliente.get("/api/export/m3u")
print("GET /api/export/m3u ->", m3u.status_code)
lineas = [l for l in m3u.text.splitlines() if l.strip()]
print("cabecera:", lineas[0] if lineas else "(vacia)")
print("lineas totales:", len(lineas))
for linea in lineas[1:7]:
    print("   ", linea[:140])
print("   ...")
print("canales en el M3U:", sum(1 for l in lineas if l.startswith("#EXTINF")))

print("\n=== EXPORTACION channels.conf ===")
conf = cliente.get("/api/export/channels.conf")
print("GET /api/export/channels.conf ->", conf.status_code)
for linea in conf.text.splitlines()[:5]:
    print("   ", linea[:140])

cliente.post("/api/auth/logout", headers=cabeceras)
