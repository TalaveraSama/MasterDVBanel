"""Tests del cliente Newcamd (protocolo CS378x) contra un servidor simulado.

El servidor simulado implementa el protocolo real de Astra/OSCam:

1. Envia 14 bytes de clave inicial.
2. Deriva la clave DES-EDE2 con `derive_triple_des_key`.
3. Descifra el login (DES-EDE2-CBC), valida usuario/contrasena y responde 0xE1
   (ACK) o 0xE2 (NAK).
4. Responde a CARD_DATA_REQ con CAID y providers.
5. Responde a los ECM (0x80) con los control words.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

from app.config import get_settings
from app.services.newcamd_client import (
    MSG_CARD_DATA,
    MSG_CARD_DATA_REQ,
    MSG_LOGIN,
    MSG_LOGIN_ACK,
    MSG_LOGIN_NAK,
    NewcamdAccount,
    NewcamdClient,
    NewcamdError,
    build_packet,
    derive_triple_des_key,
    parse_packet,
    xor_sum,
)
from app.services.md5crypt import newcamd_password
from app.services.newcamd_crypto import load_library
from app.services.newcamd_manager import decrypt_password, encrypt_password

USER = "astra"
PASSWORD = "astra"
DESKEY = bytes.fromhex("0102030405060708091011121314")
SERVER_KEY = bytes.fromhex("00112233445566778899AABBCCDD")  # 14 bytes, como Astra
CW = bytes.fromhex("1122334455667788")


class FakeNewcamdServer(threading.Thread):
    """Servidor Newcamd minimo (protocolo real) para tests."""

    def __init__(
        self, accept_login: bool = True, send_cw: bool = False, use_native_crypto: bool = True
    ) -> None:
        super().__init__(daemon=True)
        self.accept_login = accept_login
        self.send_cw = send_cw
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self._listener.settimeout(5.0)
        self.port = self._listener.getsockname()[1]
        self._stopped = threading.Event()
        self.key = derive_triple_des_key(DESKEY, SERVER_KEY)
        # Si la biblioteca nativa esta compilada (Linux) el cliente usa la
        # criptografia real de newcamd; el servidor simulado habla la misma
        # variante para que la conversacion sea valida en ambos casos.
        self.crypto = load_library() if use_native_crypto else None
        if self.crypto is not None:
            self.key = self.crypto.login_key(SERVER_KEY, DESKEY, 14)
        self.received_user = ""
        self.received_password = ""
        self.received_ecm = 0

    # -- paquetes (nativos o Python) -------------------------------------
    def build(self, message_type: int, payload: bytes = b"") -> bytes:
        """Monta un wire packet con cabecera Newcamd de 12 bytes."""
        if self.crypto is not None:
            # Mismo layout que Astra: prefijo de longitud, cabecera de 10 B,
            # luego [tipo][longitud payload][payload]. El wrapper C escribe len.
            frame = bytearray(15)
            frame[12] = message_type
            frame[13:15] = len(payload).to_bytes(2, "big")
            frame.extend(payload)
            return self.crypto.encrypt(bytes(frame), self.key)
        return build_packet(message_type, payload, self.key, 0)

    def parse(self, packet: bytes) -> tuple[int, bytes]:
        """Lee el mensaje y devuelve (tipo, payload), como el parser de Astra."""
        if self.crypto is not None:
            message_type, frame = self.crypto.decrypt(packet, self.key)
            if len(frame) < 15 or frame[12] != message_type:
                raise NewcamdError("Trama simulada invalida")
            declared = ((frame[13] & 0x0F) << 8) | frame[14]
            payload = frame[15 : 15 + declared]
            return message_type, payload
        _tipo, payload, _body, _msg = parse_packet(packet, self.key)
        return _tipo, payload

    def run(self) -> None:
        try:
            while not self._stopped.is_set():
                try:
                    conn, _ = self._listener.accept()
                except (socket.timeout, OSError):
                    continue
                threading.Thread(target=self._serve, args=(conn,), daemon=True).start()
        finally:
            try:
                self._listener.close()
            except OSError:
                pass

    def _serve(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5.0)
            conn.sendall(SERVER_KEY)
            packet = self._read_packet(conn)
            if packet is None:
                return
            message_type, payload = self.parse(packet)
            if message_type != MSG_LOGIN:
                return
            user, _, password = payload.partition(b"\x00")
            self.received_user = user.decode("latin-1")
            # El protocolo envia md5_crypt(pass, "$1$abcdefgh$"), no la clave en claro
            self.received_password = password.decode("latin-1")
            ok = (
                self.accept_login
                and self.received_user == USER
                and self.received_password == newcamd_password(PASSWORD)
            )
            conn.sendall(self.build(MSG_LOGIN_ACK if ok else MSG_LOGIN_NAK))
            if not ok:
                return

            packet = self._read_packet(conn)
            if packet is None:
                return
            message_type, _payload = self.parse(packet)
            if message_type == MSG_CARD_DATA_REQ:
                # Payload Astra: AU, CAID[2], UA[8], provider_count.
                data = bytearray(12)
                data[0] = 1
                data[1:3] = bytes.fromhex("1802")
                data[3:11] = b"USERADDR"
                data[11] = 1
                conn.sendall(self.build(MSG_CARD_DATA, bytes(data)))

            while not self._stopped.is_set():
                packet = self._read_packet(conn)
                if packet is None:
                    break
                message_type, _payload = self.parse(packet)
                if 0x80 <= message_type <= 0x8F:
                    self.received_ecm += 1
                    if self.send_cw:
                        conn.sendall(self.build(message_type, CW + CW[::-1]))
        except (OSError, NewcamdError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _read_packet(conn: socket.socket):
        header = bytearray()
        while len(header) < 2:
            chunk = conn.recv(2 - len(header))
            if not chunk:
                return None
            header.extend(chunk)
        length = int.from_bytes(header, "big")
        body = bytearray()
        while len(body) < length:
            chunk = conn.recv(length - len(body))
            if not chunk:
                return None
            body.extend(chunk)
        return bytes(header + body)

    def stop(self) -> None:
        self._stopped.set()
        try:
            self._listener.close()
        except OSError:
            pass
        self.join(timeout=2.0)


@pytest.fixture()
def server():
    instance = FakeNewcamdServer()
    instance.start()
    time.sleep(0.1)
    yield instance
    instance.stop()


@pytest.fixture()
def cw_server():
    instance = FakeNewcamdServer(send_cw=True)
    instance.start()
    time.sleep(0.1)
    yield instance
    instance.stop()


# ---------------------------------------------------------------------------
# Clave y paquetes
# ---------------------------------------------------------------------------
def test_derive_key_xor_is_cyclic():
    key = derive_triple_des_key(DESKEY, SERVER_KEY)
    zero_key = derive_triple_des_key(DESKEY, bytes(14))
    assert len(key) == 16
    assert key != zero_key


def test_derive_key_rejects_bad_deskey():
    with pytest.raises(NewcamdError):
        derive_triple_des_key(b"\x01\x02", SERVER_KEY)


def test_odd_parity_of_expanded_key():
    key = derive_triple_des_key(DESKEY, SERVER_KEY)
    for index in range(16):
        assert bin(key[index]).count("1") % 2 == 1, f"byte {index} sin paridad impar"


def test_packet_roundtrip():
    key = derive_triple_des_key(DESKEY, SERVER_KEY)
    packet = build_packet(MSG_LOGIN, b"user\x00pass", key, msg_id=7)
    message_type, payload, body, msg_id = parse_packet(packet, key)
    assert message_type == MSG_LOGIN
    assert body[0] == MSG_LOGIN
    assert payload[0:4] == b"user"
    assert msg_id == 7


def test_native_wire_layout_matches_astra_reference():
    crypto = load_library()
    if crypto is None:
        pytest.skip("requiere compilar native/tbs_newcamd.so")
    payload = b"astra\x00" + newcamd_password(PASSWORD).encode("ascii")
    frame = NewcamdClient._native_frame(MSG_LOGIN, payload, msg_id=0x1234, provider=0x1802)
    assert frame[:2] == b"\x00\x00"
    assert frame[2:4] == b"\x12\x34"
    assert frame[4:6] == b"\x18\x02"
    assert frame[12] == MSG_LOGIN
    assert frame[13:15] == len(payload).to_bytes(2, "big")
    assert frame[15:] == payload

    packet = crypto.encrypt(frame, crypto.login_key(SERVER_KEY, DESKEY, 14))
    assert int.from_bytes(packet[:2], "big") == len(packet) - 2
    message_type, decoded = crypto.decrypt(packet, crypto.login_key(SERVER_KEY, DESKEY, 14))
    assert message_type == MSG_LOGIN
    assert decoded[2:6] == b"\x12\x34\x18\x02"
    assert decoded[12] == MSG_LOGIN
    assert decoded[13:15] == len(payload).to_bytes(2, "big")
    assert decoded[15 : 15 + len(payload)] == payload


def test_packet_checksum_detects_corruption():
    key = derive_triple_des_key(DESKEY, SERVER_KEY)
    packet = bytearray(build_packet(MSG_LOGIN, b"user\x00pass", key))
    packet[20] ^= 0xFF
    with pytest.raises(NewcamdError):
        parse_packet(bytes(packet), key)


def test_xor_sum():
    assert xor_sum(b"") == 0
    assert xor_sum(b"\x01\x02\x03") == 0
    assert xor_sum(b"\xff\x0f") == 0xF0


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
def test_login_ok(server):
    account = NewcamdAccount(
        name="test", host="127.0.0.1", port=server.port, username=USER, password=PASSWORD, deskey=DESKEY.hex(),
        use_native_crypto=load_library() is not None,
    )
    client = NewcamdClient(account)
    try:
        status = client.connect()
        assert status.state == "logged_in", status.message
        assert client.is_logged_in
        assert server.received_user == USER
        assert server.received_password == newcamd_password(PASSWORD)
        assert status.caid == 0x1802
        assert status.providers == 1
    finally:
        client.disconnect()
    assert not client.is_logged_in
    assert client.status.state == "disconnected"


def test_login_rejected():
    # A native server has a different wire format from the standard-DES fallback;
    # keep this rejection case explicitly on the pure-Python protocol path.
    bad = FakeNewcamdServer(accept_login=False, use_native_crypto=False)
    bad.start()
    time.sleep(0.1)
    account = NewcamdAccount(
        name="test", host="127.0.0.1", port=bad.port, username=USER, password="mala", deskey=DESKEY.hex(),
        use_native_crypto=False,
    )
    client = NewcamdClient(account)
    try:
        status = client.connect()
        assert status.state == "error"
        assert "rechazado" in (status.message or "").lower()
    finally:
        client.disconnect()
        bad.stop()


def test_connection_refused_is_reported():
    account = NewcamdAccount(name="test", host="127.0.0.1", port=1, username="x", password="y", use_native_crypto=False)
    client = NewcamdClient(account, timeout=2.0)
    status = client.connect()
    assert status.state == "error"
    assert status.last_error
    client.disconnect()


def test_send_ecm_and_receive_cw(cw_server):
    received: list[bytes] = []
    account = NewcamdAccount(
        name="test", host="127.0.0.1", port=cw_server.port, username=USER, password=PASSWORD, deskey=DESKEY.hex(),
        use_native_crypto=load_library() is not None,
    )
    client = NewcamdClient(account, on_control_word=lambda cw, sid: received.append(cw))
    try:
        assert client.connect().state == "logged_in"
        assert client.send_ecm(bytes.fromhex("8030123456789abcdef0"), service_id=1) is True
        deadline = time.monotonic() + 4
        while not received and time.monotonic() < deadline:
            time.sleep(0.05)
        assert received, "no se recibio ningun control word"
        assert received[0] == CW
        assert client.status.cw_received >= 1
        assert client.status.ecm_sent == 1
        assert client.status.last_cw == CW.hex()
    finally:
        client.disconnect()
    assert cw_server.received_ecm >= 1


def test_ecm_without_connection_raises():
    account = NewcamdAccount(name="test", host="127.0.0.1", port=1, use_native_crypto=False)
    client = NewcamdClient(account)
    with pytest.raises(NewcamdError):
        client.send_ecm(b"\x80\x30\x01")


# ---------------------------------------------------------------------------
# Cifrado de la contrasena en reposo
# ---------------------------------------------------------------------------
def test_password_encryption_roundtrip():
    settings = get_settings()
    blob = encrypt_password("secreto-del-servidor", settings)
    assert blob and "secreto" not in blob
    assert decrypt_password(blob, settings) == "secreto-del-servidor"


def test_password_encryption_is_not_deterministic():
    settings = get_settings()
    first = encrypt_password("misma-clave", settings)
    second = encrypt_password("misma-clave", settings)
    assert first != second
    assert decrypt_password(first, settings) == decrypt_password(second, settings) == "misma-clave"


def test_empty_password():
    settings = get_settings()
    assert encrypt_password("", settings) == ""
    assert decrypt_password("", settings) == ""
