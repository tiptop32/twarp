# twarp

`twarp` — Go CLI для macOS. Он управляет внешним sing-box 1.14+ как root-демоном launchd и делит трафик на три потока:

```text
                         ┌─ gateway — домены и CIDR шлюза ── SOCKS-шлюз
macOS → TUN sing-box ────┼─ direct  — .ru/.su/.рф, geo и LAN ── напрямую
                         └─ vpn     — всё остальное ─────────── VLESS Reality
```

sing-box устанавливается отдельно через Homebrew. `twarp` генерирует его конфигурацию, rule-set'ы и launchd plist-файлы. Список IP шлюза можно менять без sudo: sing-box перечитывает `rules/gateway-ip.json` примерно за секунду, без перезапуска TUN.

## Быстрый старт

Остановите прежний VPN-клиент перед установкой. Боевой VLESS URI передавайте только через stdin.

`make install` ставит бинарь в `/usr/local/bin` с владельцем root, а не через `go install`: так его видит `sudo`, а geo-демон от root не запускает файл из каталога, куда пишет пользователь.

```sh
brew install sing-box
git clone https://github.com/tiptop32/twarp.git && cd twarp
make install          # сборка и установка в /usr/local/bin (спросит пароль sudo)
mkdir -p ~/.config/twarp && $EDITOR ~/.config/twarp/twarp.yaml   # по примеру из раздела «Конфигурация»
twarp import < key.txt
twarp gateway add 100.64.10.0/24 --comment "dev network"
sudo twarp install    # один раз; дальше без пароля:
twarp down            # выключить туннель и автозапуск после перезагрузки
twarp up              # включить снова (apply + start)
twarp                 # TUI
twarp status
```

Если хосты шлюза находятся в RFC1918, добавьте их подсети в `gateway.allowed_ranges`, а затем через `twarp gateway add` до `install`.

После установки запустите проверку живой системы:

```sh
scripts/smoke.sh -h
scripts/smoke.sh --gateway-host gateway.example
```

## Конфигурация

Пользовательский конфиг находится в `~/.config/twarp/twarp.yaml`. Минимальный синтетический пример:

```yaml
gateway:
  socks: 100.64.0.10:1080
  domains: [intra.example]
  dns: 100.64.0.53
  allowed_ranges: [100.64.0.0/10]
direct:
  dns: 192.0.2.53
  local_domains: [local.example]
vpn:
  dns: https://198.51.100.53/dns-query
clash_api: 127.0.0.1:9090
log_level: warn
```

`gateway.socks` принимает IP-литерал с портом (`100.64.0.10:1080`, `[2001:db8::10]:1080`) или имя хоста (`proxyhost.local:8080`). Имя резолвится системным резолвером, который видит и mDNS-имена `.local`, при `apply` и затем twarpd при каждой смене сети; берётся первый IPv4-адрес. IPv6-ответы не используются: mDNS первым отдаёт link-local, а типовой шлюз слушает только IPv4. Литерал не резолвится.

`gateway.allowed_ranges` — список диапазонов, в которые разрешено добавлять адреса шлюза. CLI без `--force` и MCP принимают только CIDR, полностью лежащие внутри одного из этих диапазонов. MCP не умеет обходить это ограничение. Значение по умолчанию — `100.64.0.0/10`; его меняет только человек в `twarp.yaml`.

Если SOCKS-шлюз требует логин и пароль, сохраните их через stdin, затем примените: `twarp gateway auth < creds.txt` (первая строка — пользователь, вторая — пароль), `twarp apply`. Креды хранятся в `secrets.yaml` (`gateway_socks_user`, `gateway_socks_password`), `twarp render` маскирует пароль. `twarp gateway auth --clear` удаляет их.

Валидация также отклоняет loopback, link-local, multicast, broadcast, префиксы шире `/16` для IPv4 и `/48` для IPv6, а также префикс, содержащий IP SOCKS-шлюза. Максимум — 256 записей. CIDR с адресом хоста нормализуется, например `100.64.11.149/24` превращается в `100.64.11.0/24` с предупреждением.

Секреты хранятся отдельно в `~/.config/twarp/secrets.yaml` с правами `0600`. Не добавляйте этот файл в git.

После правки `twarp.yaml` или `secrets.yaml` примените изменения: `twarp apply`. Список CIDR шлюза так применять не нужно, он перечитывается сам. Если конфиг изменён после последнего apply, `twarp status` предупредит об этом.

`apply` и `install` проверяют временный `config.json` через `sing-box check` до замены рабочего файла. При ошибке проверки прежний конфиг и запущенный sing-box сохраняются.

## Команды

| Команда | Назначение |
| --- | --- |
| `twarp up` | Включить туннель: apply и start. Без sudo — через twarpd. |
| `twarp down` | Выключить туннель и автозапуск после перезагрузки. Без sudo — через twarpd. |
| `twarp` | Без аргументов в терминале открывает TUI, иначе печатает справку. |
| `twarp import` | Прочитать VLESS URI только из stdin и сохранить секреты. Пример: `twarp import < key.txt`. Не запускать под sudo. |
| `twarp render [--out DIR]` | Вывести замаскированный `config.json` или записать полный конфиг и `rules/gateway-ip.json` в `DIR`. |
| `twarp apply` | Перегенерировать конфиг, проверить его через sing-box, перезагрузить или запустить демон и обновить `/etc/resolver` для `gateway.domains`. Без sudo — через twarpd. |
| `sudo twarp install` | Установить sing-box, geo и twarpd launchd-демоны, rule-set'ы и ротацию логов. Единственная команда, которой нужен пароль. |
| `twarp start` | Включить туннель и автозапуск: загрузить установленный демон или перезапустить упавший. Откажет, если маршрут держит другой VPN. Без sudo идёт через twarpd как `up` (с apply). |
| `twarp stop` | Выключить туннель и автозапуск после перезагрузки, оставив всё установленным; маршрут возвращается к сети. `apply` обновит конфиг, но не запустит туннель. Без sudo — через twarpd. |
| `sudo twarp uninstall` | Остановить и удалить launchd-демоны (включая twarpd и его сокет), plist и настройку ротации. Конфиги и правила сохраняются. |
| `twarp gateway add <cidr> [--comment text] [--force]` | Добавить CIDR шлюза. `--force` снимает только проверку `allowed_ranges` и доступен только в CLI. Не запускать под sudo. |
| `twarp gateway rm <cidr>` | Удалить CIDR шлюза. |
| `twarp gateway ls` | Показать CIDR, автора, дату и комментарий. |
| `twarp gateway auth [--clear]` | Сохранить из stdin (или удалить) логин и пароль SOCKS-шлюза. Не запускать под sudo. |
| `twarp geo update` | Скачать и обновить `geoip-ru.srs` и `geosite-category-ru.srs`. Без sudo — через twarpd. |
| `twarp status [--net]` | Проверить sing-box, шлюз, TUN, CIDR, geo и свежесть конфига. `--net` добавляет проверку внешнего адреса и пути через шлюз. |
| `twarp tui` | Интерактивный дашборд: статус, маршруты, трафик, CIDR шлюза, логи. Не запускать под sudo. |
| `twarp mcp` | Запустить MCP-сервер по stdio. Не запускать под sudo. |

Проверка шлюза в `status` и TUI — SOCKS5-рукопожатие (с логином и паролем, если они заданы), а не просто открытый порт, и идёт на адрес, на котором реально работает sing-box. Если в `twarp.yaml` другой IP-литерал, строка шлюза — WARN с подсказкой `twarp apply`. `--net` (клавиша `n` в TUI) дополнительно делает CONNECT через шлюз на `gateway.dns:53`: ответ `network unreachable` означает, что шлюз жив, но его собственный VPN не поднят.

`gateway add`, `gateway rm` и MCP атомарно обновляют пользовательский state и rule-set, затем дописывают запись в аудит. До `install` изменения только сохраняются; после установки rule-set перечитывается без перезапуска TUN. Доступны MCP-инструменты `gateway_ip_add`, `gateway_ip_remove` и `gateway_ip_list`.

Зарегистрируйте сервер в Claude:

```sh
claude mcp add twarp -- twarp mcp
```

MCP принимает только CIDR. `gateway_ip_list` показывает `allowed_ranges`; используйте их при добавлении адреса.

## TUI

`twarp tui` открывает дашборд: состояние туннеля и TUN, доступность шлюза, VPN, возраст geo-файлов, версия sing-box, сводка маршрутов и число соединений по `gateway`, `direct` и `vpn`. Непройденные проверки `twarp status` показываются под сводкой.

| Клавиша | Действие |
| --- | --- |
| `g` | CIDR шлюза: `+` добавить, `d` удалить, `↑`/`↓` выбрать. Проверка `allowed_ranges` действует всегда, `--force` в TUI нет. |
| `r` | Правила маршрутизации в порядке sing-box. |
| `l` | Хвост `sing-box.log`, обновляется сам. |
| `c` | Активные соединения из Clash API. |
| `n` | Проверить внешний адрес через VPN (обращается к `ifconfig.me`). |
| `R` | Обновить всё. |
| `s` | Включить или выключить туннель (`twarp up` / `down`), с подтверждением. |
| `a` | `twarp apply`. |
| `u` | `twarp geo update`. |
| `esc`, `?`, `q` | Назад, справка, выход. |

TUI работает от пользователя. `s`, `a` и `u` идут через twarpd, не покидая экран. Если twarpd не запущен, TUI сворачивается, запускает тот же бинарь через `sudo` (там спрашивается пароль) и показывает результат. Бинарь и все каталоги над ним должны принадлежать root и не быть доступны на запись группе и остальным, иначе TUI откажется: sudo выполнил бы от root файл, который пользователь может подменить. Ставьте бинарь через `make install`. Если `/usr/local/bin` принадлежит пользователю (Homebrew на Intel), выполняйте эти команды в shell. Правки списка шлюза пишутся в аудит с `actor: tui`.

## Правила маршрутизации

Порядок правил фиксирован и важен:

1. `sniff` определяет протокол и домен.
2. DNS перехватывается (`hijack-dns`).
3. IP SOCKS-шлюза идёт `direct`: сам адрес шлюза не должен попасть в TUN-маршрут.
4. Домены из `gateway.domains` идут через `gateway`.
5. CIDR из `rules/gateway-ip.json` идут через `gateway`.
6. `ip_is_private` и `direct.local_domains` идут `direct`.
7. `.ru`, `.su`, `.рф` и их punycode-форма идут `direct`.
8. `geoip-ru` и `geosite-category-ru` идут `direct`.
9. Остальной трафик идёт через `vpn`.

Правила шлюза стоят раньше `ip_is_private`. Иначе RFC1918-адрес шлюза попадёт в `direct`. Явно добавьте такие подсети и имена в конфиг и список шлюза.

## Как работает twarpd

twarpd — долгоживущий root-демон (`dev.twarp.daemon`, тот же `/usr/local/bin/twarp` в режиме `twarp daemon`), который ставит `sudo twarp install`.

- **Сокет.** `/var/run/twarp/twarpd.sock`, права `0666`. Доступ решает не файл, а ядро: для каждого соединения демон читает uid процесса на другом конце (`LOCAL_PEERCRED`) и отвечает только владельцу, записанному в plist при install, и root. Остальным — `forbidden` и запись в root-аудит.
- **Что демон может.** Только фиксированные операции: `up`, `down`, `apply`, `geo_update`, `status`. От клиента не принимается никаких путей и данных, поэтому через сокет можно сделать не больше, чем владелец сделал бы через `sudo twarp start|stop|apply`. Все операции идут по одной, без параллели.
- **Смена сети.** Демон слушает routing socket (новый адрес, интерфейс, default route; пачка событий за 2 с — одна проверка) и раз в 30 с проверяет на всякий случай. Если `gateway.socks` — имя, оно резолвится заново (вне очереди операций, чтобы `twarp up`/`down` не ждали сеть); если адрес отличается от работающего `config.json`, демон делает `apply` (актор `daemon-net` в аудите) и пишет в `twarpd.log` строку `gateway address changed old=… new=…`. Ошибка резолва не трогает работающий конфиг и видна в `twarp status`. IP-литерал не резолвится.
- **Бинарь.** Демон отказывается стартовать, если бинарь или каталоги над ним может изменить не-root: ставьте его через `make install`.
- **Без демона.** `sudo twarp start|stop|apply|install` работают напрямую, как раньше. Если демон не отвечает, CLI подсказывает `sudo launchctl kickstart system/dev.twarp.daemon`.

Сквозное время восстановления после смены Wi-Fi определяет не только twarpd (новый адрес в `config.json` за секунды), но и сам шлюз: прокси-хосту нужно переподключить свой VPN.

## DNS и ограничения

Конфигурация использует отдельные DNS-потоки:

- DNS шлюза отправляется по TCP через SOCKS-detour `gateway`.
- DNS для `direct` отправляется напрямую.
- `local` использует системный резолвер для `direct.local_domains`.
- Удалённый HTTPS-DNS отправляется через `vpn`.
- `dns.strategy` — `prefer_ipv4`; IPv6 TUN-маршрут сохраняется, чтобы IPv6 не ушёл мимо VPN.

Системный DNS для `gateway.domains` twarp направляет в TUN через `/etc/resolver/<домен>` с `nameserver 172.19.0.2`; там запрос перехватывает sing-box. Без такого файла macOS может отправить запрос DNS-серверу из локальной подсети напрямую, мимо TUN: маршрут к своей подсети точнее маршрутов TUN, и имя шлюза получает NXDOMAIN. `apply`, `install` и `start` создают и обновляют эти файлы, `stop` и `uninstall` удаляют. Свои файлы twarp помечает первой строкой-комментарием и трогает только их. Чужой файл, например от прежнего VPN-клиента, остаётся как есть, а `apply` называет такие домены в выводе; удалите файл, если домен должен вести twarp. Проверяйте резолв через `dscacheutil -q host -a name <имя>`, а не через `dig`: `dig` не читает `/etc/resolver`.

`reverse_mapping` на macOS ненадёжен из-за системного DNS-кэша и не заменяет список CIDR. Несниффаемые протоколы, например SSH и RDP, к имени шлюза маршрутизируются по IP. Если имя резолвится в адрес вне списка шлюза, добавьте его через `twarp gateway add`. Если адрес лежит вне `gateway.allowed_ranges`, сначала расширьте этот список в `twarp.yaml`.

`strict_route` не используется: на macOS он не даёт нужного эффекта. `install` откажется работать, если default route уже держит чужой `utun` или загружен Homebrew-сервис sing-box. Остановите прежний VPN и `brew services stop sing-box`, затем повторите установку.

## Пути и логи

| Что | Путь |
| --- | --- |
| Пользовательский конфиг и секреты | `~/.config/twarp/twarp.yaml`, `~/.config/twarp/secrets.yaml` (`0600`) |
| State шлюза, lock и пользовательский аудит | `~/.config/twarp/gateway-ips.json`, `~/.config/twarp/gateway-ips.lock`, `~/.config/twarp/audit.jsonl` |
| Конфиг sing-box | `/usr/local/etc/twarp/config.json` (`0600`, root) |
| Горячий rule-set шлюза | `/usr/local/etc/twarp/rules/gateway-ip.json` (владелец — пользователь) |
| Geo rule-set'ы | `/usr/local/etc/twarp/geo/*.srs` (root) |
| launchd | `/Library/LaunchDaemons/dev.twarp.singbox.plist`, `/Library/LaunchDaemons/dev.twarp.geo.plist`, `/Library/LaunchDaemons/dev.twarp.daemon.plist` |
| Сокет twarpd | `/var/run/twarp/twarpd.sock` (`TWARP_SOCKET` для тестов) |
| Лог twarpd | `/usr/local/var/log/twarp/twarpd.log` |
| Лог sing-box | `/usr/local/var/log/twarp/sing-box.log` |
| Логи geo updater | `/usr/local/var/log/twarp/geo-update.log`, `/usr/local/var/log/twarp/geo-update.err.log` |
| Root-аудит | `/usr/local/var/log/twarp/audit.jsonl` |
| Ротация логов | `/etc/newsyslog.d/twarp.conf` |
| DNS доменов шлюза | `/etc/resolver/<домен>` (только файлы с меткой twarp) |

`audit.jsonl` растёт без ограничения размера. Если файл стал слишком большим, удалите или заархивируйте его вручную.

Для тестовых каталогов используются `TWARP_HOME`, `TWARP_OUT`, `TWARP_SINGBOX` и `TWARP_LOG_DIR`.

При `install` значение `TWARP_OUT` сохраняется в plist geo-демона, чтобы его плановые обновления попадали в тот же каталог, что и конфигурация sing-box.

## Если что-то не работает

**Хост шлюза открывается через VPN.** Проверьте порядок правил и `twarp gateway ls`. Если хост резолвится в RFC1918, добавьте его подсеть в `allowed_ranges` и CIDR в state. Для SSH или RDP добавляйте IP/CIDR явно: sniffing имени может не сработать.

**Установка сообщает о другом `utun`.** Завершите прежний VPN-клиент, проверьте `route -n get 192.0.2.1`, затем повторите `sudo twarp install`. twarp не забирает default route у чужого VPN автоматически.

**Домен шлюза не резолвится (`Could not resolve host`).** Выполните `twarp apply` и посмотрите, нет ли домена в строке `not managed by twarp`. Затем `cat /etc/resolver/<домен>` должен показать `nameserver 172.19.0.2`, а `dscacheutil -q host -a name <имя>` — адрес.

**DNS не отвечает или утекает.** Проверьте адреса DNS в `twarp.yaml`, доступность DNS шлюза по TCP через SOCKS и вывод `twarp status`. Для проверки на живой машине используйте `sudo scripts/smoke.sh --leak-check`; интерфейс можно задать через `--iface IFACE`, а ISP IPv6-префикс — через `--isp-v6-prefix CIDR`.

**Geo-файлы отсутствуют или устарели.** Выполните `twarp geo update`, затем `twarp status`. `install` скачивает geo-файлы, если их ещё нет.

**`twarpd is not running`.** Запустите демон: `sudo launchctl kickstart system/dev.twarp.daemon`, причины смотрите в `/usr/local/var/log/twarp/twarpd.log`. Если демон не установлен (обновление со старой версии), выполните один раз `sudo twarp install`.

**Шлюз сменил адрес после переключения Wi-Fi.** Используйте имя хоста в `gateway.socks` (например, `proxyhost.local:8080`) — twarpd переприменит конфиг сам. С IP-литералом поправьте `twarp.yaml` и выполните `twarp apply`; `twarp status` покажет, на каком адресе sing-box работает сейчас.

**Нужно увидеть диагностику.** Смотрите `/usr/local/var/log/twarp/sing-box.log`, `/usr/local/var/log/twarp/geo-update.log`, `/usr/local/var/log/twarp/geo-update.err.log` и root-аудит. Изменения списка шлюза смотрите в `~/.config/twarp/audit.jsonl`. Для общего состояния запустите `twarp status`; для проверки маршрута — `scripts/smoke.sh --gateway-host gateway.example`.

## Откат

```sh
sudo twarp uninstall
```

Команда удаляет launchd-демоны и системные файлы интеграции, но оставляет пользовательский конфиг и правила. После неё запустите прежний VPN-клиент.

## Модель угроз

Для однопользовательской macOS-машины принят следующий риск: root-демон sing-box читает user-writable `/usr/local/etc/twarp/rules/gateway-ip.json`, а бинарь берётся из user-writable `/opt/homebrew`. Любой процесс этого пользователя может заменить rule-set напрямую и обойти проверки `twarp` или подменить бинарь через Homebrew.

Geo-файлы и основной `config.json` хранятся в root-каталоге, поэтому пользовательский rule-set не может подменить geo-данные и отправить весь трафик в `direct`. Это не защищает однопользовательскую машину от уже скомпрометированного пользователя: риск принят ради MCP-изменений без sudo.

twarpd открывает владельцу root-операции без пароля. Граница — uid владельца, проверяемый ядром: другой локальный пользователь получает отказ. Процесс самого владельца может включить, выключить и переприменить туннель, но не может передать демону ни пути, ни данные.

Не передавайте ключи в аргументах командной строки и не коммитьте их. Используйте `twarp import` через stdin и синтетические данные в тестах.

## Разработка

Включите pre-commit для клона:

```sh
git config core.hooksPath .githooks
```

CLI, TUI и MCP — тонкие фронтенды над `internal/app`: статус, start/stop/apply, geo, список шлюза, сводка маршрутов, соединения и логи реализованы там один раз. Новую операцию добавляйте в `internal/app`, а не в отдельный фронтенд.

Основные проверки описаны в `CLAUDE.md`. Проверка живой установки — `scripts/smoke.sh`; периодическая MCP-проверка — `make eval`. Сценарий `make eval-launchd-geo` проверяет geo updater от root без `SUDO_USER` и требует сеть и доступ к `sudo`.
