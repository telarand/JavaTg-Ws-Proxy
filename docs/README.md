# JavaTg-Ws-Proxy

<div align="center">

**🇷🇺 Русский • [🇬🇧 English](./README_EN.md)**

</div>

> [!NOTE]
> ## Благодарность
>
> Данный проект представляет собой перенос на язык Java системы **[tg-ws-proxy]**, изначально написанной на Python автором **[Flowseal]**.
>
> - **Original Repository:** [https://github.com/Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy)
> - **Original License:** MIT
>
> Основная логика и архитектура опираются на оригинальную разработку. Реализация на Java является полностью самостоятельной переработкой.

## Требования
> [!IMPORTANT]
> Собирается и запускается через Gradle (Java 11+).

## Сборка и запуск

Сборка:
```bash
./gradlew build       # Толстый и тонкий клиент
./gradlew shadowJar   # Только толстый клиент
./gradlew jar         # Тонкий клиент (без зависимостей)
./gradlew installDist # Тонкий клиент с зависимостями
```

Запуск:
```bash
./gradlew run --args="--port 1443 -v" # Запуск через Gradle с передачей атрибута
java -jar build\libs\JavaTg-Ws-Proxy-1.0-all.jar --port 1443 -v # Для запуска толстого клиента
build\install\JavaTg-Ws-Proxy\bin\JavaTg-Ws-Proxy.bat --port 1443 -v # Для запуска тонкого клиента Windows
build\install\JavaTg-Ws-Proxy\bin\JavaTg-Ws-Proxy --port 1443 -v # Для запуска тонкого клиента Linux
```

После старта ядро печатает баннер с параметрами и `tg://proxy?...`-ссылкой
(dd-секрет, либо ee-ссылка при включённом Fake TLS).

## Флаги

| Флаг | Описание |
|---|---|
| `--port PORT`| Порт для прослушивания (по умолчанию 1443) |
| `--host HOST`| Хост для прослушивания (по умолчанию 127.0.0.1)|
| `--secret SECRET`| Секретный ключ прокси MTProto (32 шестнадцатеричных символа). Если не указан, генерируется автоматически. |
| `--dc-ip DC:IP`| IP-адрес целевого дата-центра (DC), например --dc-ip 2:149.154.167.220 (параметр можно указывать несколько раз; использование `--dc-ip` без аргументов отключает перенаправления)|
| `-v, --verbose`| Ведение отладочной документации |
| `--log-file PATH`| Запись логов в файл с ротацией (по умолчанию: только в stderr)|
| `--log-max-mb MB`| Максимальный размер файла журнала в МБ до ротации (по умолчанию 5)|
| `--log-backups N`| Количество сохраняемых ротированных лог-файлов (минимум 1)|
| `--buf-kb KB`| Размер буфера отправки/приема сокета в КБ (по умолчанию 256)|
| `--pool-size N`| Размер пула WebSocket-соединений для каждого дата-центра (по умолчанию 4; значение 0 отключает прямые WebSocket-соединения)|
| `--cfproxy-domain DOMAIN`| Задаваемый пользователем домен, проксируемый через Cloudflare, для передачи медиаконтента по протоколу H2 и резервного соединения через WS (можно использовать несколько раз)|
| `--cfproxy-worker-domain DOMAIN`|Домен Cloudflare Worker для резервного соединения через WebSockets (используется до других методов резервного подключения; можно задать несколько раз)|
| `--no-h2`| Отключить мультиплексирование HTTP/2 для медиаконтента через Cloudflare (включено по умолчанию)|
| `--no-cfproxy`| Отключить резервное использование прокси Cloudflare|
| `--no-secure`| Использовать порт 80 для подключений через CF-proxy и CF-worker|
| `--fake-tls-domain DOMAIN`| Включить маскировку Fake TLS (ee-secret) с использованием указанного SNI-домена, например example.com|
| `--force-test-dc`| Принудительно направлять ВЕСЬ трафик в тестовые дата-центры Telegram|
| `--proxy-protocol`| Принимать заголовок PROXY-протокола v1|
| `-h, --help`| Показать это справочное сообщение и выйти|

## Что внутри

- **WS-пул** (`pool/WsPool`): прямые WebSocket-соединения к `kwsN.web.telegram.org/apiws`
  с domain fronting (SNI `sprinthost.ru` + Host `kwsN...`), запоминанием удачного
  режима (fronting-first / direct-first), фоновой ротацией каждые 5 с и
  экспоненциальным backoff пополнения 1 с → 1 ч.
- **CF-пул** (`pool/CfWorkerPool`): fallback через Cloudflare-домены и CF Worker.
- **H2-media** (`net/CfH2Pool`, `net/H2Channel`): медиа-пакеты ходят POST-запросами
  по HTTP/2 (`https://kwsN.<домен>/api`) — выглядит как обычный веб-трафик.
- **Fake TLS** (`net/FakeTls`): ServerHello собирается из ClientHello клиента
  (выбор шифра 0x1301→0x1303→0x1302, зеркало X25519MLKEM768, AppData 64–160 байт,
  replay-кэш против зондирования, задержка ответа 8–24 мс).
- **RawWebSocket** (`net/RawWebSocket`): ClientHello с ALPN (`http/1.1` для WS,
  `h2` для H2-транспорта) — без ALPN DPI глушит соединения («Read timed out»).
- **Bridge** (`bridge/Bridge`): порядок fallback `cf_worker → cf (для media — H2) → tcp`,
  тестовые DC (>= 10000) и `--force-test-dc`, TCP-fallback с backoff 30 с → 1 ч.
- **Домены CF**: встроенный зашифрованный список (20 доменов) + автоподгрузка с
  GitHub раз в час (`Flowseal/tg-ws-proxy/.github/cfproxy-domains.txt`); свои домены
  через `--cfproxy-domain` отключают автоподгрузку.

##  Лицензия
[MIT License](../LICENSE.txt)