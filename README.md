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

```sh
brew install sing-box
git clone https://github.com/tiptop32/twarp.git && cd twarp
go install ./cmd/twarp
twarp migrate
twarp import < key.txt
sudo twarp install
twarp status
```

Проверьте конфигурацию шлюза после `migrate`. Если его хосты находятся в RFC1918, добавьте соответствующие CIDR в `gateway.allowed_ranges` и в список шлюза до `install`.

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

`gateway.allowed_ranges` — список диапазонов, в которые разрешено добавлять адреса шлюза. CLI без `--force` и MCP принимают только CIDR, полностью лежащие внутри одного из этих диапазонов. MCP не умеет обходить это ограничение. Значение по умолчанию — `100.64.0.0/10`; его меняет только человек в `twarp.yaml`.

Валидация также отклоняет loopback, link-local, multicast, broadcast, префиксы шире `/16` для IPv4 и `/48` для IPv6, а также префикс, содержащий IP SOCKS-шлюза. Максимум — 256 записей. CIDR с адресом хоста нормализуется, например `100.64.11.149/24` превращается в `100.64.11.0/24` с предупреждением.

Секреты хранятся отдельно в `~/.config/twarp/secrets.yaml` с правами `0600`. Не добавляйте этот файл в git.

После правки `twarp.yaml` или `secrets.yaml` примените изменения: `sudo twarp apply`. Список CIDR шлюза так применять не нужно, он перечитывается сам.

## Команды

| Команда | Назначение |
| --- | --- |
| `twarp migrate [--from ~/.warp.yaml] [--force]` | Перенести старый конфиг warp. Без `--force` существующие файлы не перезаписываются. Не запускать под sudo. |
| `twarp import` | Прочитать VLESS URI только из stdin и сохранить секреты. Пример: `twarp import < key.txt`. Не запускать под sudo. |
| `twarp render [--out DIR]` | Вывести замаскированный `config.json` или записать полный конфиг и `rules/gateway-ip.json` в `DIR`. |
| `sudo twarp apply` | Перегенерировать конфиг, проверить его через sing-box и перезагрузить или запустить демон. |
| `sudo twarp install` | Установить sing-box и geo launchd-демоны, rule-set'ы и ротацию логов. |
| `sudo twarp uninstall` | Остановить и удалить launchd-демоны, plist и настройку ротации. Конфиги и правила сохраняются. |
| `twarp gateway add <cidr> [--comment text] [--force]` | Добавить CIDR шлюза. `--force` снимает только проверку `allowed_ranges` и доступен только в CLI. Не запускать под sudo. |
| `twarp gateway rm <cidr>` | Удалить CIDR шлюза. |
| `twarp gateway ls` | Показать CIDR, автора, дату и комментарий. |
| `sudo twarp geo update` | Скачать и обновить `geoip-ru.srs` и `geosite-category-ru.srs`. |
| `twarp status [--net]` | Проверить sing-box, шлюз, TUN, CIDR и geo. `--net` добавляет проверку внешнего адреса. |
| `twarp mcp` | Запустить MCP-сервер по stdio. Не запускать под sudo. |

`gateway add`, `gateway rm` и MCP атомарно обновляют пользовательский state и rule-set, затем дописывают запись в аудит. До `install` изменения только сохраняются; после установки rule-set перечитывается без перезапуска TUN. Доступны MCP-инструменты `gateway_ip_add`, `gateway_ip_remove` и `gateway_ip_list`.

Зарегистрируйте сервер в Claude:

```sh
claude mcp add twarp -- twarp mcp
```

MCP принимает только CIDR. `gateway_ip_list` показывает `allowed_ranges`; используйте их при добавлении адреса.

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

## DNS и ограничения

Конфигурация использует отдельные DNS-потоки:

- DNS шлюза отправляется по TCP через SOCKS-detour `gateway`.
- DNS для `direct` отправляется напрямую.
- `local` использует системный резолвер для `direct.local_domains`.
- Удалённый HTTPS-DNS отправляется через `vpn`.
- `dns.strategy` — `prefer_ipv4`; IPv6 TUN-маршрут сохраняется, чтобы IPv6 не ушёл мимо VPN.

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
| launchd | `/Library/LaunchDaemons/dev.twarp.singbox.plist`, `/Library/LaunchDaemons/dev.twarp.geo.plist` |
| Лог sing-box | `/usr/local/var/log/twarp/sing-box.log` |
| Root-аудит | `/usr/local/var/log/twarp/audit.jsonl` |
| Ротация логов | `/etc/newsyslog.d/twarp.conf` |

`audit.jsonl` растёт без ограничения размера. Если файл стал слишком большим, удалите или заархивируйте его вручную.

Для тестовых каталогов используются `TWARP_HOME`, `TWARP_OUT`, `TWARP_SINGBOX` и `TWARP_LOG_DIR`.

## Если что-то не работает

**Хост шлюза открывается через VPN.** Проверьте порядок правил и `twarp gateway ls`. Если хост резолвится в RFC1918, добавьте его подсеть в `allowed_ranges` и CIDR в state. Для SSH или RDP добавляйте IP/CIDR явно: sniffing имени может не сработать.

**Установка сообщает о другом `utun`.** Завершите прежний VPN-клиент, проверьте `route -n get 192.0.2.1`, затем повторите `sudo twarp install`. twarp не забирает default route у чужого VPN автоматически.

**DNS не отвечает или утекает.** Проверьте адреса DNS в `twarp.yaml`, доступность DNS шлюза по TCP через SOCKS и вывод `twarp status`. Для проверки на живой машине используйте `sudo scripts/smoke.sh --leak-check`; интерфейс можно задать через `--iface IFACE`, а ISP IPv6-префикс — через `--isp-v6-prefix CIDR`.

**Geo-файлы отсутствуют или устарели.** Выполните `sudo twarp geo update`, затем `twarp status`. `install` скачивает geo-файлы, если их ещё нет.

**Нужно увидеть диагностику.** Смотрите `/usr/local/var/log/twarp/sing-box.log` и root-аудит. Изменения списка шлюза смотрите в `~/.config/twarp/audit.jsonl`. Для общего состояния запустите `twarp status`; для проверки маршрута — `scripts/smoke.sh --gateway-host gateway.example`.

## Откат

```sh
sudo twarp uninstall
```

Команда удаляет launchd-демоны и системные файлы интеграции, но оставляет пользовательский конфиг и правила. После неё запустите прежний VPN-клиент или warp.

## Модель угроз

Для однопользовательской macOS-машины принят следующий риск: root-демон sing-box читает user-writable `/usr/local/etc/twarp/rules/gateway-ip.json`, а бинарь берётся из user-writable `/opt/homebrew`. Любой процесс этого пользователя может заменить rule-set напрямую и обойти проверки `twarp` или подменить бинарь через Homebrew.

Geo-файлы и основной `config.json` хранятся в root-каталоге, поэтому пользовательский rule-set не может подменить geo-данные и отправить весь трафик в `direct`. Это не защищает однопользовательскую машину от уже скомпрометированного пользователя: риск принят ради MCP-изменений без sudo.

Не передавайте ключи в аргументах командной строки и не коммитьте их. Используйте `twarp import` через stdin и синтетические данные в тестах.

## Разработка

Включите pre-commit для клона:

```sh
git config core.hooksPath .githooks
```

Основные проверки описаны в `CLAUDE.md`. Проверка живой установки — `scripts/smoke.sh`; периодическая MCP-проверка — `make eval`.
