# twarpd: управление без sudo и автоподхват смены сети

## Overview

Сейчас каждое включение, выключение и применение конфига идёт через `sudo twarp start|stop|apply`, а при смене Wi-Fi адрес SOCKS-шлюза приходится править руками в `twarp.yaml` и не забыть `sudo twarp apply`. При этом `twarp status` пишет `OK gateway`, потому что проверяет адрес из yaml, а не тот, на котором работает демон (реальный случай 2026-10-16: yaml указывал на `.173`, sing-box неделю ходил на `.105`).

Что меняется для пользователя:

- `sudo` нужен один раз, в `sudo twarp install`. Дальше `twarp up`, `twarp down`, `twarp apply`, TUI-клавиши `s`/`a`/`u` работают без пароля.
- Ежедневных команд три: `twarp up`, `twarp down`, `twarp` (без аргументов открывает TUI).
- `gateway.socks` принимает имя хоста (`proxyhost.local:8080`). При смене сети демон сам резолвит имя заново и, если адрес сменился, перегенерирует конфиг и перезагружает sing-box.
- `twarp status` и TUI показывают адрес шлюза, на котором реально работает sing-box, и предупреждают, если `twarp.yaml` или `secrets.yaml` новее работающего конфига.

Измеримый результат:

- число вводов пароля в день: с «каждое вкл/выкл/apply» до 0;
- смена Wi-Fi при `gateway.socks` по имени: 0 ручных действий, переключение за ≤ 10 с (строка `gateway address changed old=… new=…` в `/usr/local/var/log/twarp/twarpd.log` и запись в root audit log);
- ложный `OK gateway` при устаревшем конфиге невозможен: на этот сценарий есть тест.

## Context (from discovery)

- `cmd/twarp/main.go`: диспетчер подкомандий; без аргументов печатает usage.
- `internal/app/lifecycle.go`: `Start`, `Stop`, `Apply`, `GeoUpdate` требуют `euid == 0` и берут владельца из `SUDO_UID`/`SUDO_GID`/`SUDO_USER` (`config.SudoOwner`, `config.resolveHome`).
- `internal/app/status.go`: `checkGateway` проверяет `cfg.Gateway.Socks` из yaml (источник ложного OK).
- `internal/config/config.go:validateConfig`: `gateway.socks` обязан быть IP-литералом.
- `internal/render/render.go`: `parseGatewaySOCKS` берёт IP из конфига для outbound `gateway` и для правила `ip_cidr → direct` (правило 3 в порядке маршрутов).
- `internal/launchd/`: plist для `dev.twarp.singbox` и `dev.twarp.geo`, `Install`/`Uninstall`.
- `cmd/twarp/cmd_tui.go`: `SudoCommand` сворачивает TUI и запускает тот же бинарь через `sudo` для `s`/`a`/`u`; проверяет, что бинарь и каталоги над ним принадлежат root.
- Зависимости уже в `go.mod`: `golang.org/x/sys/unix` (`GetsockoptXucred` для `LOCAL_PEERCRED` на darwin), `golang.org/x/net/route` (разбор сообщений routing socket). Новых модулей не нужно.

## Development Approach

- **testing approach**: Regular (код, затем тесты в той же задаче).
- каждая задача закрывается полностью до следующей; тесты в той же задаче, `make test` зелёный.
- обратная совместимость: `sudo twarp start|stop|apply|install` продолжают работать как сейчас; IP-литерал в `gateway.socks` остаётся валидным и не резолвится.
- инварианты проекта: порядок маршрутов (`gateway` раньше `ip_is_private`), sing-box 1.14+, `route.default_domain_resolver` и `dns.strategy: prefer_ipv4` не трогаем; фикстуры только синтетические (`example`, `100.64.0.0/10`, TEST-NET).
- **CRITICAL: update this plan file when scope changes during implementation**.

## Testing Strategy

- **unit**: каждая новая функция и пакет; системные границы (сокет, routing socket, резолвер, launchctl) за интерфейсами с фейками, как уже сделано в `app.Deps` и `sysexec.Runner`.
- **integration** (`make integration`, `internal/itest`): демон с реальным unix-сокетом во временном каталоге и реальным sing-box: смена адреса шлюза через фейковый резолвер ведёт к перезагрузке и новому адресу в config.json.
- **eval** (`make eval`): MCP-инструменты не меняются, прогон подтверждает отсутствие регрессии.
- e2e UI-тестов в проекте нет; TUI покрывается существующими тестами модели `cmd_tui_test.go`.

## Progress Tracking

- отмечать `[x]` сразу по выполнении;
- новые задачи с префиксом ➕, блокеры с ⚠️;
- план держать в синхроне с фактической работой.

## Solution Overview

Схема как у Tailscale: долгоживущий root-демон и обычный CLI.

```text
twarp up/down/apply ─┐                       ┌─ app.Service.Apply/Start/Stop/GeoUpdate
twarp tui (s/a/u) ───┼─ /var/run/twarp/      │
twarp status ────────┘  twarpd.sock ── twarpd┼─ netwatch: routing socket + тик 30 с
                        (peer uid ==        │     └─ резолв gateway.socks → адрес сменился → Apply
                         владелец или 0)    └─ live state: адрес шлюза в работающем config.json
```

Ключевые решения:

1. **Один бинарь.** Демон — скрытая подкоманда `twarp daemon`, запускается launchd как `dev.twarp.daemon` из `/usr/local/bin/twarp` (root-owned, ставится через `make install`). Отдельного бинаря нет.
2. **Владелец фиксируется при install.** `sudo twarp install` записывает в plist демона `TWARP_OWNER_UID`, `TWARP_OWNER_GID`, `TWARP_OWNER_USER`. `config` получает функцию `Owner(sys)`: сначала `SUDO_*`, затем `TWARP_OWNER_*`. `resolveHome` и `Apply` переходят на неё. Так `app.Service` работает одинаково под sudo и в демоне.
3. **Авторизация по ядру, не по правам файла.** Сокет `0666` в каталоге `/var/run/twarp` (root, `0755`); каждое соединение проверяется через `LOCAL_PEERCRED` (`unix.GetsockoptXucred`): разрешены только uid владельца и 0. Остальным ответ `forbidden` и запись в root audit.
4. **Протокол без аргументов.** Одна строка JSON на запрос и на ответ: `{"v":1,"op":"up"}`. Операции фиксированы: `up`, `down`, `apply`, `geo_update`, `status`. Никаких путей и данных от клиента, поэтому поверхность атаки не шире, чем «владелец может включить и выключить свой VPN». Неизвестная версия или операция → ошибка.
5. **Операции сериализуются.** Один mutex в демоне: `up`, сетевое переприменение и `apply` не идут параллельно.
6. **Смена сети без cgo.** `netwatch` читает `AF_ROUTE` сокет (`RTM_NEWADDR`, `RTM_DELADDR`, `RTM_IFINFO`, `RTM_ADD`/`RTM_DELETE` для default), сглаживает пачку событий (debounce 2 с) и дополнительно тикает раз в 30 с на случай пропущенных событий. На каждое срабатывание демон резолвит хост `gateway.socks`; если IP отличается от адреса в работающем конфиге, вызывает `Apply`. IP-литерал в yaml не резолвится, и переприменение не запускается.
7. **Резолв выбирает IPv4.** Если имя вернуло несколько адресов, берётся первый IPv4 (как `dns.strategy: prefer_ipv4`), иначе первый глобальный или ULA IPv6. Link-local (`fe80::/10`) отбрасывается: mDNS отдаёт его первым, а без зоны интерфейса sing-box не подключится. Ошибка резолва не трогает работающий конфиг: пишется в лог и в status (`WARN gateway: proxyhost.local не резолвится, работаю на 192.0.2.10`).
   - Резолвер только системный (`net.DefaultResolver` в режиме по умолчанию: на darwin он идёт через libSystem и mDNSResponder и с cgo, и без). Чистый Go-резолвер (`GODEBUG=netdns=go`) спрашивает DNS роутера и `.local` не видит: тест фиксирует, что демон не выставляет `netdns=go`.
   - Несуществующее `.local`-имя отвечает таймаутом через 5 с, а не мгновенной ошибкой. Резолв идёт с таймаутом 5 с вне mutex операций, чтобы `twarp up`/`down` не ждали сетевой проверки.
8. **Рендер получает готовый адрес.** `render.Options.GatewaySocks netip.AddrPort` заполняется в `app.renderInputs`; `render` больше не парсит хост из конфига. Правило `ip_cidr <socks>/32 → direct` остаётся третьим.
9. **Честный status.** Демон отвечает на `status` адресом шлюза из работающего `config.json` и его mtime. Без демона CLI сравнивает mtime `twarp.yaml`/`secrets.yaml` с `stat` на `/usr/local/etc/twarp/config.json` (stat доступен без root). Проверка доступности шлюза идёт по живому адресу.
10. **Команды.** `twarp up`: если не установлено, просит один раз `sudo twarp install` и выходит; иначе через сокет `apply` + `start`. `twarp down`: через сокет `stop`. `twarp` без аргументов: TUI, если stdout — терминал, иначе usage. `start`/`stop`/`apply`/`geo update` без sudo идут через сокет; под sudo работают напрямую, как сейчас.

Отвергнуто:

- `sudoers NOPASSWD`: правка `/etc/sudoers.d`, логика остаётся в разовых вызовах, некому следить за сетью.
- SystemConfiguration через cgo: ломает сборку без Xcode CLT ради того, что даёт routing socket.
- Авто-apply при каждой правке `twarp.yaml`: пользователь не выбрал; `twarp up`/`twarp apply` без sudo покрывают это одной командой, а status предупредит об устаревшем конфиге.

## Technical Details

Протокол (`internal/ipc`):

```go
type Request struct {
	V  int    `json:"v"`  // 1
	Op string `json:"op"` // up | down | apply | geo_update | status
}

type Response struct {
	OK      bool        `json:"ok"`
	Summary string      `json:"summary,omitempty"` // та же строка, что печатает CLI под sudo
	Error   string      `json:"error,omitempty"`
	Live    *LiveStatus `json:"live,omitempty"` // только для status
}

type LiveStatus struct {
	GatewayConfigured string    `json:"gateway_configured"` // как в yaml: proxyhost.local:8080
	GatewayLive       string    `json:"gateway_live"`       // из работающего config.json: 192.0.2.10:8080
	ConfigAppliedAt   time.Time `json:"config_applied_at"`
	Stale             bool      `json:"stale"`             // yaml/secrets новее config.json
	LastResolveError  string    `json:"last_resolve_error,omitempty"`
}
```

- Сокет: `/var/run/twarp/twarpd.sock`, переопределяется `TWARP_SOCKET` для тестов.
- Таймауты: клиент 60 с на `up`/`apply` (внутри `sing-box check`), 5 с на `status`; сервер закрывает соединение после одного ответа, лимит запроса 4 KiB.
- Лог демона: `/usr/local/var/log/twarp/twarpd.log`, ротация через существующий newsyslog-конфиг (добавить строку).
- Аудит: каждая операция через сокет пишет в root audit `actor: daemon-cli|daemon-tui|daemon-net`; актор клиента берётся из отдельного поля `actor` в запросе (`cli`/`tui`), значение валидируется по списку.
- Plist `dev.twarp.daemon`: `RunAtLoad`, `KeepAlive`, `ProgramArguments = [/usr/local/bin/twarp, daemon]`, `EnvironmentVariables = TWARP_OWNER_*`. Golden-тест рядом с существующими.
- Демон отказывается стартовать, если бинарь или каталоги над ним доступны на запись не-root (переиспользовать проверку из `cmd_tui.go:SudoCommand`, вынести в `internal/fsutil`).

## What Goes Where

- **Implementation Steps**: код, тесты и документация в этом репозитории.
- **Post-Completion**: проверки на живой машине (Wi-Fi, mDNS, launchd), которые нельзя закрыть юнит-тестами.

## Implementation Steps

Волны для `plan-dispatch`: задачи 1–4 независимы и идут параллельно; 5 после 1–3; 6 после 5; 7 после 3 и 6; 8 после 7; 9–10 в конце.

### Task 1: Владелец без sudo в config

**Files:**
- Modify: `internal/config/paths.go`
- Modify: `internal/config/paths_test.go`
- Modify: `internal/app/lifecycle.go`

- [ ] добавить `config.Owner(sys) (uid, gid int, user string, ok bool)`: сначала `SUDO_UID/GID/USER`, затем `TWARP_OWNER_UID/GID/USER`; `SudoOwner` оставить обёрткой
- [ ] перевести `resolveHome` и `Apply` на `Owner`; текст ошибки без владельца: «run via sudo or through twarpd»
- [ ] тесты: `SUDO_*` приоритетнее `TWARP_OWNER_*`; только `TWARP_OWNER_*` под root даёт home владельца; пусто под root → ошибка; невалидные числа → `ok=false`
- [ ] `make test` зелёный

### Task 2: gateway.socks по имени и резолвер адреса

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`
- Create: `internal/gwaddr/gwaddr.go`, `internal/gwaddr/gwaddr_test.go`
- Modify: `internal/render/render.go`, `internal/render/render_test.go` (+ golden)
- Modify: `internal/app/lifecycle.go` (`renderInputs`)

- [ ] валидация: хост `gateway.socks` — IP или DNS-имя (RFC 1123 метки, без схемы и пути); IP по-прежнему проверяется против loopback/multicast
- [ ] `gwaddr.Resolve(ctx, lookup, hostport) (netip.AddrPort, error)`: IP-литерал без сети; имя → первый IPv4, иначе первый не-link-local IPv6; отказ на loopback/unspecified/link-local результат; таймаут 5 с
- [ ] `render.Options.GatewaySocks netip.AddrPort`; outbound `gateway` и правило `ip_cidr → direct` строятся из него; порядок маршрутов не меняется
- [ ] `renderInputs` резолвит через `Deps.LookupIP`
- [ ] тесты: таблица валидации (IP, IPv6 в скобках, `.local`, мусор, схема), резолв (ответ mDNS `[fe80::…, 192.0.2.10]` → `192.0.2.10`; только link-local → ошибка; только глобальный v6; пусто; таймаут; loopback), golden рендера с адресом из резолвера, тест порядка маршрутов
- [ ] `make test` зелёный

### Task 3: IPC: протокол, сервер с проверкой peer uid, клиент

**Files:**
- Create: `internal/ipc/protocol.go`, `internal/ipc/server.go`, `internal/ipc/peercred_darwin.go`, `internal/ipc/peercred_other.go`, `internal/ipc/client.go`
- Create: `internal/ipc/ipc_test.go`

- [ ] типы `Request`/`Response`/`LiveStatus`, версия 1, список операций и акторов
- [ ] сервер: `Listen(path, allowedUIDs, handler)`; создаёт каталог `0755`, удаляет устаревший сокет, `chmod 0666`; на соединение `GetsockoptXucred` → uid вне списка получает `forbidden`; лимит 4 KiB, один запрос на соединение
- [ ] клиент: `Call(ctx, path, req)`; `ErrDaemonUnavailable` при отсутствии сокета или `ECONNREFUSED`
- [ ] тесты на реальном сокете в `t.TempDir()`: успешный вызов; uid не в списке → forbidden (список без `os.Getuid()`); неизвестная операция и версия; слишком длинный запрос; устаревший файл сокета перезаписывается; клиент без демона → `ErrDaemonUnavailable`
- [ ] `make test` зелёный

### Task 4: netwatch: события смены сети

**Files:**
- Create: `internal/netwatch/netwatch.go`, `internal/netwatch/routesock_darwin.go`, `internal/netwatch/routesock_other.go`
- Create: `internal/netwatch/netwatch_test.go`

- [ ] интерфейс `Source` (канал событий); darwin-реализация читает `AF_ROUTE` и фильтрует `RTM_NEWADDR/DELADDR/IFINFO` и изменения default-маршрута через `golang.org/x/net/route`
- [ ] `Watch(ctx, source, debounce, tick, fn)`: пачка событий за `debounce` → один вызов; плюс вызов раз в `tick`; часы инъектируются
- [ ] тесты с фейковыми источником и часами: 5 событий за 1 с → 1 вызов; тик без событий → вызов; отмена ctx завершает цикл; разбор реального байтового сообщения `RTM_NEWADDR` из фикстуры
- [ ] `make test` зелёный

### Task 5: Демон twarpd

**Files:**
- Create: `internal/daemon/daemon.go`, `internal/daemon/daemon_test.go`
- Create: `cmd/twarp/cmd_daemon.go`, `cmd/twarp/cmd_daemon_test.go`
- Modify: `internal/fsutil/fsutil.go` (проверка root-owned пути, вынесенная из `cmd_tui.go`)
- Modify: `cmd/twarp/main.go`

- [ ] `daemon.Run(ctx, deps)`: поднимает `ipc`-сервер с uid владельца и 0, обработчик маппит операции на `app.Service` (`up` = `Apply` + `Start`, `down` = `Stop`, `apply`, `geo_update`, `status`), все операции под одним mutex
- [ ] цикл netwatch: резолв хоста `gateway.socks` → сравнение с живым адресом → `Apply` с актором `daemon-net`; ошибка резолва сохраняется в `LastResolveError`, конфиг не трогается; IP-литерал пропускается
- [ ] живой адрес читается из работающего `config.json` (outbound `gateway`) при старте и после каждого `Apply`
- [ ] `twarp daemon` (скрытая): требует root, `TWARP_OWNER_*`, root-owned бинарь; пишет в `twarpd.log`
- [ ] тесты с фейковыми Service/резолвером/источником: смена адреса → ровно один Apply; тот же адрес → ни одного; ошибка резолва → нет Apply и есть `LastResolveError`; IP-литерал → нет резолва; параллельные `up` и сетевое событие сериализуются; `status` отдаёт живой адрес и `Stale`
- [ ] `make test` зелёный

### Task 6: launchd: установка демона

**Files:**
- Modify: `internal/launchd/plist.go`, `internal/launchd/plist_test.go` (+ golden `daemon.plist`)
- Modify: `internal/launchd/install.go`, `internal/launchd/install_test.go`
- Modify: newsyslog-конфиг в `plist.go` (строка для `twarpd.log`)

- [ ] `DaemonPlist(executable, owner)` с `RunAtLoad`, `KeepAlive`, `TWARP_OWNER_*`
- [ ] `Install` пишет и бутстрапит `dev.twarp.daemon` после sing-box; повторный install обновляет plist и перезапускает демон; `Uninstall` снимает его и удаляет сокет
- [ ] тесты: golden plist; порядок вызовов install расширен; uninstall идемпотентен; падение бутстрапа демона не останавливает sing-box (как для geo)
- [ ] `make test` зелёный

### Task 7: CLI: up/down, TUI по умолчанию, маршрут через демон

**Files:**
- Create: `cmd/twarp/cmd_updown.go`, `cmd/twarp/cmd_updown_test.go`
- Modify: `cmd/twarp/main.go`, `cmd/twarp/cmd_install.go` (start/stop/apply), `cmd/twarp/cmd_geo.go`
- Modify: `cmd/twarp/main_test.go`

- [ ] `twarp up`, `twarp down`; не установлено → «один раз: sudo twarp install», код 1; демон недоступен → подсказка `sudo launchctl kickstart system/dev.twarp.daemon`
- [ ] `start`/`stop`/`apply`/`geo update` без root идут через `ipc.Call`; под sudo прежний путь
- [ ] `twarp` без аргументов: TUI, если stdout — TTY, иначе usage; `help` печатает usage; список команд в usage: `up`, `down` первыми
- [ ] тесты: up/down через фейковый клиент; без root и без демона; под root прямой путь не трогает сокет; без аргументов с TTY и без
- [ ] `make test` зелёный

### Task 8: Честный status и TUI без sudo

**Files:**
- Modify: `internal/app/status.go`, `internal/app/status_test.go`
- Modify: `cmd/twarp/cmd_status.go`, `cmd/twarp/cmd_tui.go`, `cmd/twarp/cmd_tui_test.go`

- [ ] status: живой адрес шлюза из демона, иначе из `config.json`, если читается; проверка доступности по живому адресу; строка `gateway: configured proxyhost.local:8080 → live 192.0.2.10:8080`
- [ ] `WARN config: twarp.yaml changed after the last apply; run: twarp apply` по `Stale` или по сравнению mtime без демона
- [ ] `WARN gateway: <host> does not resolve; running on <live>` из `LastResolveError`
- [ ] TUI: `s`/`a`/`u` через `ipc.Call` без сворачивания; fallback на sudo, только если демон недоступен; тексты подсказок без «(sudo)»
- [ ] тесты: сценарий 2026-10-16 (yaml `.173`, живой `.105`) даёт FAIL/WARN, а не OK; mtime-fallback; TUI-действия вызывают фейковый клиент; fallback на sudo при `ErrDaemonUnavailable`
- [ ] `make test` зелёный

### Task 9: Интеграционный сценарий смены адреса

**Files:**
- Create: `internal/itest/daemon_test.go`
- Modify: `internal/itest/fixture.go`

- [ ] демон на реальном сокете в temp-каталоге, реальный `sing-box check`, фейковый резолвер и источник событий; `gateway.socks: proxy.example:1080`
- [ ] резолвер меняет `192.0.2.10` → `192.0.2.20`, событие сети → в `config.json` новый адрес, правило direct для `/32` третье, sing-box перечитал конфиг
- [ ] запрос с чужим uid невозможно сымитировать без root: тест помечен `skip` с причиной, проверка остаётся в юнит-тестах Task 3
- [ ] `make integration` зелёный

### Task 10: Verify acceptance criteria

- [ ] каждое требование из Overview проверено тестом или ручным шагом из Post-Completion
- [ ] порядок маршрутов и инварианты sing-box 1.14+ подтверждены тестами рендера
- [ ] `make test`, `make lint`, `make integration`, `make eval`, `make secrets-check`
- [ ] grep по диффу: нет реальных IP/доменов, только `example`, `100.64.0.0/10`, TEST-NET

### Task 11: [Final] Update documentation

- [ ] README: быстрый старт (`sudo twarp install` один раз, затем `twarp up/down`), `gateway.socks` по имени, раздел «Как работает twarpd» (сокет, peer uid, что демон может и не может), команды, клавиши TUI
- [ ] CLAUDE.md: правило «операции под root идут через `app.Service`; демон не принимает аргументов от клиента»
- [ ] переместить план в `docs/plans/completed/`

## Post-Completion

*Требует живой машины, без чекбоксов.*

**Ручная проверка:**
- `make install && sudo twarp install`, затем `twarp down`/`twarp up` без пароля; `ls -l /var/run/twarp/twarpd.sock`.
- `gateway.socks: <имя прокси-хоста>.local:8080`, `twarp apply`; переключить Wi-Fi на другую сеть с тем же прокси-хостом: в `twarpd.log` строка `gateway address changed`, `twarp status` показывает новый live-адрес за ≤ 10 с, `curl` до домена шлюза работает.
- Повторить проверку mDNS уже из root-демона. Проверка 2026-10-16 от пользователя при поднятом TUN (`utun4`, sing-box 1.14.2): `.local`-имя прокси-хоста → `[fe80::…, <IPv4 прокси>]` за 6–13 мс через `net.DefaultResolver` (сборки с cgo и `CGO_ENABLED=0`); с `GODEBUG=netdns=go` → `no such host`; несуществующее имя → таймаут 5 с; `curl --socks5-hostname <имя>.local:8080` → 302. Root ходит в тот же mDNSResponder, поэтому расхождения не ожидается, но оно не проверено.
- Попытка `twarp down` от другого локального пользователя → `forbidden` и запись в root audit.

**Безопасность:**
- отдельное ревью `internal/ipc` и `internal/daemon` (`/security-review`): peer uid, отсутствие клиентских аргументов, root-owned бинарь.

**Миграция:**
- существующая установка без демона: `twarp up` подсказывает выполнить `sudo twarp install` один раз; прежние `sudo twarp start|stop|apply` продолжают работать.
