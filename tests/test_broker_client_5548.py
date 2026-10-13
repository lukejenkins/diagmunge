"""diagbroker client handshake: SUB out, OK line stripped, stream intact.

A broker client sends ``SUB {json}\\n``, reads ``OK {json}\\n`` and treats the
rest as raw HDLC. The broker may send its first frame in the same TCP segment
as the OK line. The handshake reads only up to the newline, so those bytes stay
in the kernel buffer: diaggulp's capture loops wait on ``select()`` over the
socket fd and read the transport directly, so no userspace buffer would reach them.
"""
from __future__ import annotations

import json
import socket
import threading

import pytest

from diagmunge.transport import BrokerError, DiagClient, broker_subscribe

FRAME = b"\x7e\x10\x00\x01\x02\x7e"


def fake_broker(reply: bytes, *, delay_first: float = 0.0):
    """A listening socket that records the client's first line and sends ``reply``."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    got: dict = {}

    def run():
        c, _ = srv.accept()
        buf = b""
        while b"\n" not in buf:
            chunk = c.recv(4096)
            if not chunk:
                break
            buf += chunk
        got["line"] = buf
        if reply:
            c.sendall(reply)
        got["conn"] = c          # keep open until the test ends

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return srv, got, t


def test_sub_line_is_sent_and_ok_is_parsed():
    a, b = socket.socketpair()
    b.sendall(b'OK {"client_id":3,"effective_mask_epoch":7}\n')
    info = broker_subscribe(a, {"name": "t", "log_codes": [5238]})
    assert info == {"client_id": 3, "effective_mask_epoch": 7}
    line = b.recv(4096)
    assert line.startswith(b"SUB ") and line.endswith(b"\n")
    assert json.loads(line[4:]) == {"name": "t", "log_codes": [5238]}


def test_bytes_after_ok_stay_in_the_socket():
    """Same segment as the OK line, and still select()-visible afterwards."""
    import select
    a, b = socket.socketpair()
    b.sendall(b'OK {"client_id":1,"effective_mask_epoch":0}\n' + FRAME)
    broker_subscribe(a, {"log_codes": [5238]})
    assert select.select([a], [], [], 0)[0] == [a]
    assert a.recv(4096) == FRAME


def test_ok_split_across_reads():
    a, b = socket.socketpair()

    def dribble():
        for ch in b'OK {"client_id":1,"effective_mask_epoch":0}\n':
            b.send(bytes([ch]))
    t = threading.Thread(target=dribble)
    t.start()
    info = broker_subscribe(a, {"log_codes": [5238]})
    t.join()
    assert info["client_id"] == 1


def test_err_reply_raises_with_reason():
    a, b = socket.socketpair()
    b.sendall(b"ERR unknown preset 'nope'\n")
    with pytest.raises(BrokerError, match=r"^broker refused the subscription: unknown preset"):
        broker_subscribe(a, {"floor": "nope"})


def test_closed_without_reply_raises():
    a, b = socket.socketpair()
    b.close()
    with pytest.raises(BrokerError, match="closed"):
        broker_subscribe(a, {"log_codes": [5238]})


def test_silence_times_out():
    a, b = socket.socketpair()
    with pytest.raises(BrokerError, match="no reply"):
        broker_subscribe(a, {"log_codes": [5238]}, timeout=0.2)


def test_overlong_line_is_refused():
    a, b = socket.socketpair()
    b.sendall(b"OK " + b"x" * 5000)
    with pytest.raises(BrokerError, match="too long"):
        broker_subscribe(a, {"log_codes": [5238]})


def test_non_ok_reply_is_refused():
    a, b = socket.socketpair()
    b.sendall(FRAME + b"\n")
    with pytest.raises(BrokerError, match="unexpected"):
        broker_subscribe(a, {"log_codes": [5238]})


def test_socket_is_blocking_again_after_success():
    a, b = socket.socketpair()
    b.sendall(b'OK {"client_id":1,"effective_mask_epoch":0}\n')
    broker_subscribe(a, {"log_codes": [5238]}, timeout=1.0)
    assert a.gettimeout() is None


def test_from_tcp_client_with_broker_sub_end_to_end():
    srv, got, th = fake_broker(b'OK {"client_id":9,"effective_mask_epoch":2}\n' + FRAME)
    host, port = srv.getsockname()
    client = DiagClient.from_tcp_client(host, port, broker_sub={"name": "x", "log_codes": [5238]})
    try:
        th.join(5)
        assert got["line"].startswith(b"SUB ")
        assert client.broker_info == {"client_id": 9, "effective_mask_epoch": 2}
        assert client.no_crc
        data = client._transport.read(4096)
        assert data == FRAME
    finally:
        client.close()
        srv.close()


def test_from_tcp_client_without_broker_sends_nothing():
    srv, got, th = fake_broker(b"")
    host, port = srv.getsockname()
    client = DiagClient.from_tcp_client(host, port)
    try:
        assert client.broker_info is None
        th.join(0.3)
        assert "line" not in got          # no SUB line was written
    finally:
        client.close()
        srv.close()
