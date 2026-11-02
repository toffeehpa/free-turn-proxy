# SFU-Канал (`-provider sfu`)

> [!WARNING]
> **Экспериментально.** В приложении включается в настройках, раздел Experimental Features.

Вместо TURN-аллокации трафик идёт видеотреком звонка через SFU VK Calls: клиент и мост (`sfubridge`) сидят в одной комнате, датаграммы ядра упакованы в VP8-кадры. Мост стоит рядом с сервером и отдаёт ему пакеты обычным UDP, как будто их прислал клиент, - сам сервер не меняется.

## Клиент

```bash
./client -provider sfu -links "<call-link>" -peer <vps>:56000 -obf-profile rtpopus3 -obf-key <key>
```

- **Ссылка**: берётся первая из `-links`, та же, что у моста.
- **Потоки**: всегда один, `-n` игнорируется - видеотрек один и лимитов реле нет.
- **`-peer`**: нужен для валидации и логов, сами пакеты до него идут через мост.
- **Captcha** не нужна: в комнату заходим анонимным гостем.
- **`-sfu-fps`** (`1..240`, по умолчанию `120`) и **`-sfu-batch`** (сколько пакетов в одном кадре, по умолчанию `64`) - темп видеотрека в сторону сервера. Обратную сторону задаёт мост своими `-fps` и `-batch`.

Кадр уходит раз в `1/fps`, и пакет ждёт ближайшего: чем выше fps, тем ниже пинг и выше скорость. Меньший batch делает кадры мельче - ровнее пинг под нагрузкой ценой скорости.

## В Приложении

В настройках, раздел Experimental Features:

1. Включите **VK Calls SFU channel** и вставьте ссылку на звонок - ту же, что у моста.
2. Выберите кадров в секунду: **60**, **120** (по умолчанию) или **240** (ниже пинг, мелкие кадры). Это сторона телефона, обратную держит мост.
3. Переподключитесь - настройка применяется со следующего подключения и ко всем серверам. В статусе будет `1/1`.

Обратно на TURN - выключите **VK Calls SFU channel** и переподключитесь, в статусе снова `12/12`.

## Мост на Сервере

```bash
sudo curl -L -o /usr/local/bin/freeturn-sfubridge \
  https://raw.githubusercontent.com/toffeehpa/free-turn-proxy/master/scripts/sfubridge.sh
sudo chmod +x /usr/local/bin/freeturn-sfubridge
sudo install -m 755 ./sfubridge /usr/local/bin/sfubridge
```

`/etc/default/freeturn-sfubridge`:

```bash
SFU_ROOM=https://vk.ru/call/join/<code>   # та же ссылка, что у клиента
SFU_PORT=56000                            # порт server на этом хосте
SFU_WARP=0                                # 1 - в VK через Cloudflare WARP, см. ниже
SFU_EXTRA=                                # доп. флаги sfubridge, напр. -fps 240 -batch 16
```

`/etc/systemd/system/freeturn-sfubridge.service`:

```ini
[Unit]
Description=Free Turn Proxy SFU bridge
After=network-online.target free-turn-proxy.service

[Service]
ExecStart=/usr/local/bin/freeturn-sfubridge run
ExecStopPost=/usr/local/bin/freeturn-sfubridge warp-down
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now freeturn-sfubridge
```

Флаги `sfubridge`: `-room`, `-forward` (адрес server, по умолчанию `127.0.0.1:56000`), `-dns` (по умолчанию `1.1.1.1:53`), `-fps` (`0` - 120 кадров), `-batch` (`0` - 64), `-debug`. Скрипт собирает их сам из конфига.

## `SFU_WARP`

По умолчанию (`0`) мост заходит в звонок с адреса сервера - как и в TURN-режиме, где VK и так видит IP сервера (реле шлёт на него трафик).

`1` прячет сервер за Cloudflare WARP: мост живёт в netns `ft-sfu`, где наружу есть только WARP, и VK видит адрес Cloudflare. Профиль WARP - `/etc/freeturn/wgcf-profile.conf` (свой путь - `SFU_WARP_PROFILE`), его выдаёт [wgcf](https://github.com/ViRb3/wgcf):

```bash
wgcf register --accept-tos && wgcf generate
sudo install -m 600 wgcf-profile.conf /etc/freeturn/wgcf-profile.conf
```

`server` при этом должен слушать не только loopback (`-listen 0.0.0.0:56000`, по умолчанию так) - мост приходит к нему с `10.77.0.2`.

На пинг WARP почти не влияет, но бывают всплески. Маршрутизацию хоста не трогает: интерфейс WireGuard уезжает в netns целиком.

## Ограничения

- Пинг выше, чем у TURN: путь через VK длиннее, плюс кадр уходит раз в `1/fps` и пакет ждёт ближайшего.
- Звонок нужен свой: в чужом участники увидят мост и клиента гостями.
- Мост перезапустился - клиент заметит через ~20 с без ответа на пинг и перезайдёт сам.
- Под белыми списками клиент ходит только в сети VK, но проверялось это эмуляцией (iptables), а не живым оператором.
