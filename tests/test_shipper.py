"""Тест shipper'а Cowrie: строки cowrie.json превращаются в GELF-сообщения."""
import json
import socket
import sys
import threading
import time
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import shipper  # noqa: E402


def udp_sink(port, got, stop):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(0.3)
    while not stop.is_set():
        try:
            data, _ = s.recvfrom(65535)
            got.append(json.loads(zlib.decompress(data)))
        except socket.timeout:
            continue
    s.close()


def test_follow_and_send(tmp_path, monkeypatch):
    log_file = tmp_path / "cowrie.json"
    log_file.write_text("")  # shipper стартует с конца файла
    monkeypatch.setattr(shipper, "LOG_FILE", str(log_file))
    monkeypatch.setattr(shipper, "GELF_PORT", 19098)
    monkeypatch.setattr(shipper, "GELF_HOST", "127.0.0.1")

    got, stop = [], threading.Event()
    sink = threading.Thread(target=udp_sink, args=(19098, got, stop), daemon=True)
    sink.start()
    worker = threading.Thread(target=shipper.main, daemon=True)
    worker.start()
    time.sleep(0.5)

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps({"eventid": "cowrie.login.success", "message": "login attempt [root/123456] succeeded",
                            "username": "root", "password": "123456", "src_ip": "1.2.3.4", "src_port": 5555,
                            "dst_port": 2222, "session": "abc", "protocol": "ssh"}) + "\n")
        f.write("битая строка\n")
        f.write(json.dumps({"eventid": "cowrie.command.input", "message": "CMD: id",
                            "input": "id", "src_ip": "1.2.3.4", "session": "abc"}) + "\n")
    time.sleep(2.0)
    stop.set()
    sink.join(2)

    assert len(got) == 2
    login, cmd = got
    assert login["_homelab_app"] == "cowrie" and login["_event"] == "cowrie.login.success"
    assert login["_username"] == "root" and login["_password"] == "123456" and login["_src_ip"] == "1.2.3.4"
    assert login["level"] == 3
    assert cmd["_event"] == "cowrie.command.input" and cmd["_input"] == "id"
