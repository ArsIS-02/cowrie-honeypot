#!/usr/bin/env python3
"""Shipper журнала Cowrie в Graylog (GELF UDP).

Читает cowrie.json (JSON Lines) с конца файла, каждую новую строку шлёт
событием GELF: поля Cowrie становятся полями Graylog, eventid — полем event.
Переживает ротацию файла и битые строки; состояние не хранит — при рестарте
продолжает с конца (история остаётся в самом cowrie.json).

  LOG_FILE   путь к cowrie.json (по умолчанию /logs/cowrie.json)
  GELF_HOST  куда слать (host.containers.internal из контейнера)
  GELF_PORT  вход GELF UDP Graylog (по умолчанию 12206)
"""
from __future__ import annotations

import json
import logging
import os
import socket
import time
import zlib

log = logging.getLogger("shipper")

LOG_FILE = os.environ.get("LOG_FILE", "/logs/cowrie.json")
GELF_HOST = os.environ.get("GELF_HOST", "host.containers.internal")
GELF_PORT = int(os.environ.get("GELF_PORT", "12206"))
HOSTNAME = socket.gethostname()

# важность по типу события (syslog level: 3=Error … 6=Informational)
LEVELS = {
    "cowrie.login.success": 3,
    "cowrie.command.input": 3,
    "cowrie.session.file_download": 3,
    "cowrie.session.file_upload": 3,
    "cowrie.client.fingerprint": 4,
    "cowrie.login.failed": 5,
    "cowrie.direct-tcpip.request": 4,
    "cowrie.session.connect": 6,
}

# скалярные поля Cowrie, которые копируем в Graylog как есть
COPY_FIELDS = ("session", "protocol", "src_ip", "src_port", "dst_ip", "dst_port",
               "username", "password", "input", "url", "outfile", "shasum", "size",
               "duration", "version", "fingerprint", "ttylog", "arch", "key", "type",
               "encCS", "macCS", "kexAlgs", "lang", "sensor")

_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def send(rec: dict) -> None:
    eventid = rec.get("eventid", "cowrie.event")
    msg = {"version": "1.1", "host": HOSTNAME,
           "short_message": (rec.get("message") or eventid)[:250],
           "level": LEVELS.get(eventid, 6),
           "_tool": "cowrie", "_homelab_app": "cowrie", "_event": eventid}
    for k in COPY_FIELDS:
        v = rec.get(k)
        if v is not None and v != "":
            msg[f"_{k}"] = str(v)[:300]
    try:
        _udp.sendto(zlib.compress(json.dumps(msg, ensure_ascii=False).encode()), (GELF_HOST, GELF_PORT))
    except OSError as e:
        log.warning("gelf: %s", e)


def follow(path: str):
    """Генератор строк: хвост файла с конца, переживает ротацию и отсутствие файла."""
    f = None
    inode = None
    while True:
        try:
            if f is None:
                f = open(path, "r", encoding="utf-8", errors="replace")
                f.seek(0, 2)
                inode = os.fstat(f.fileno()).st_ino
                log.info("слежу за %s", path)
            line = f.readline()
            if line:
                yield line
                continue
            try:                                   # ротация: inode сменился или файл ужался
                st = os.stat(path)
                if st.st_ino != inode or st.st_size < f.tell():
                    log.info("ротация %s", path)
                    f.close()
                    f = None
                    continue
            except FileNotFoundError:
                f.close()
                f = None
            time.sleep(1.0)
        except FileNotFoundError:
            log.warning("нет файла %s, жду…", path)
            f = None
            time.sleep(5.0)


def main() -> None:
    for line in follow(LOG_FILE):
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("eventid"):
            send(rec)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    main()
