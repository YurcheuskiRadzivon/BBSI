# BBSI: подробное описание «хэшчейна» (DAG), хранения и логики

Документ описывает реализацию в кодовой базе проекта **BBSI**: как устроен журнал транзакций в виде **DAG** (направленный ациклический граф), какие используются **криптографические примитивы** (важно: это не «шифрование содержимого документов», а в основном **цифровые подписи ECDSA** и **хэши SHA-256**), где лежит **консенсус-подобная** логика, и как проходят сценарии **выдачи**, **отзыва**, **проверки документа** и **полной валидации цепочки**.

Пути к файлам указаны **от корня репозитория** (например `internal/dag/store.go`).

---

## 1. Общая архитектура процесса

```text
┌─────────────────────────────────────────────────────────────────┐
│                         процесс bbsi                               │
│  cmd/bbsi/main.go: открывает каталог БД, ключи, Store, HTTP API   │
└─────────────────────────────────────────────────────────────────┘
          │                         │
          ▼                         ▼
   db/*.json (диск)          internal/dag/store.go
   authority_keys.json       журнал узлов в памяти + gossip
          │                         │
          └─────────────┬───────────┘
                        ▼
              internal/api/server.go
              REST: issue, revoke, verify (lookup), validate, dag…
```

- **Точка входа:** `cmd/bbsi/main.go`. Каталог БД: переменная окружения `BBSI_DB`, иначе `db`.
- **Журнал цепочки:** структура `dag.Store` (`internal/dag/store.go`) хранит узлы в памяти и синхронизирует их с файлом `nodes.json`.
- **Ключи эмитентов:** `internal/crypto/persist.go` — файл `{БД}/authority_keys.json` (ECDSA P-256 по странам).
- **HTTP:** `internal/api/server.go` — маршруты `/api/...`, статика `web/`.

---

## 2. Как хранится состояние (файловая БД)

Обёртка над каталогом JSON: `internal/db/db.go`, тип `db.Database`. Константы имён файлов — в том же пакете (`FileNodes`, `FileDocuments`, …).

| Файл (относительно каталога БД, по умолчанию `db/`) | Назначение |
|-----------------------------------------------------|------------|
| `nodes.json` | Единый файл графа: массив узлов DAG + журнал gossip-событий + «виртуальные голоса». Читается при старте и после явной перезагрузки (см. ниже). |
| `authority_keys.json` | Приватные ключи ECDSA по кодам стран (PEM в JSON). Без него при каждом запуске ключи менялись бы и все подписи в `nodes.json` стали бы недействительными. |
| `documents.json` | Реестр документов для UI: эталонные payload’ы и хэши выпуска, `last_tx_id`, `last_action` (issue/revoke). **Не** является источником истины для криптографической целостности DAG — источник узлы в `nodes.json`. |
| `types.json`, `emitents.json`, `authorities.json` | Справочники для интерфейса (типы документов, страны, органы). |
| `logs.json` | Операционный лог сообщений (в т.ч. итог `/api/validate`). |
| `attack_logs.json` | Строки журнала симуляций атак (API атак + серверный буфер). |

Формат записи графа на диск задаётся типом `persistedGraph` в `internal/dag/persistence.go`:

- `nodes` — список `DAGNode`;
- `gossip_events` — события из `consensus.GossipState.Events`;
- `gossip_votes` — шаги «виртуального голосования» (`VirtualVoteStep`).

Узел (`internal/dag/node.go`, структура `DAGNode`):

- `transaction` — `model.DocumentTransaction` (`internal/model/types.go`): идентификаторы, хэши содержимого/метаданных, страны, `action` (`issue` | `revoke`), время, подпись;
- `parent_ids` — ссылки на `tx_id` родительских узлов;
- `node_hash` — агрегирующий хэш узла (см. раздел 4).

---

## 3. Загрузка и сохранение графа

| Действие | Файл кода |
|----------|-----------|
| Чтение `nodes.json` при старте | `internal/dag/persistence.go` — `loadFromDisk` → `replacePersistedGraph` |
| Запись графа после изменений | `persistGraph` в том же файле |
| Перечитывание диска без перезапуска (перед validate и verify lookup) | `ReloadChainFromDisk` в `internal/dag/persistence.go` |

**Миграция legacy:** если в старых данных попадались узлы с `action: verify`, при загрузке вызывается `sanitizePersistedGraph`: такие узлы удаляются, родители перепривязываются, `node_hash` пересчитывается (`sanitizePersistedGraph`, `recomputeAllNodeHashes`). В журнале остаются только **issue** и **revoke**.

Сброс данных: `internal/api/server.go` — `handleResetDB`; логика очистки памяти и файлов — `dag.Store.ResetChainAndLogs` (`internal/dag/store.go`), регенерация ключей — `crypto.RegenerateAuthorityKeys` (`internal/crypto/persist.go`).

---

## 4. Криптография и хэши (где что считается)

### 4.1. Терминология

- **Шифрование** содержимого диплома/ПДн в коде **не** реализовано: в цепочке хранятся **хэши** (`document_hash`, `metadata_hash`) и **подпись** транзакции.
- Используется **ECDSA** на кривой **P-256** (`internal/crypto/keys.go`): генерация ключей `ecdsa.GenerateKey(elliptic.P256(), ...)`.
- Подпись: **SHA-256** от канонического тела сообщения, затем **ECDSA SignASN1 / VerifyASN1**.

### 4.2. Каноническое тело транзакции (без подписи)

Файл: `internal/crypto/canonical.go`, функция `CanonicalJSONWithoutSig`.

В подпись и в расчёт «содержательного» хэша входят поля (ключи сортируются, объект сериализуется в JSON):

`action`, `document_hash`, `document_id`, `document_type`, `issuer_authority`, `issuer_country`, `metadata_hash`, `receiver_country`, `timestamp`, `tx_id`.

Поле **`issuer_signature` в канонизацию не входит** — подпись считается по телу без неё.

**Content hash транзакции:** `ContentHash(tx)` = SHA-256(hex от канонического JSON). Используется внутри вычисления `node_hash`.

### 4.3. Подпись транзакции

Файл: `internal/crypto/keys.go`.

- `SignTransaction(tx)` сериализует каноническое тело, считает SHA-256 от байтов тела, подписывает **приватным ключом страны** `tx.IssuerCountry`, записывает подпись в `tx.IssuerSignature` (hex ASN.1).
- `VerifyTransaction(tx)` загружает публичный ключ для `IssuerCountry` и проверяет подпись.

**Важно:** отзыв (`revoke`) тоже подписывается тем же механизмом; допустимость отзыва по бизнес-правилам проверяется в `AddRevoke` (эмитент совпадает с эмитентом выпуска).

### 4.4. Хэши документа и метаданных (payload → SHA-256)

Для пользовательских JSON (document / metadata) используется канонизация произвольного JSON: `internal/crypto/jsoncanon.go` (`canonicalizeJSON`, `HashCanonicalJSON` и др.), чтобы одинаковые данные давали один хэш.

На стороне API хэши подставляются/проверяются в `internal/api/server.go` — функция `applyDocumentAndMetaHashes` (согласование явных хэшей и вычисление из payload).

### 4.5. Хэш узла (`node_hash`) и Merkle по родителям

Файл: `internal/dag/node.go`, функция `ComputeNodeHash`.

Алгоритм:

1. `ContentHash(tx)` — SHA-256 канонической транзакции (см. 4.2).
2. Для каждого `parent_id` берётся **`node_hash` родителя** (не хэш транзакции родителя напрямую, а сохранённое поле узла).
3. По списку хэшей родителей считается **корень Merkle** — `internal/crypto/hash.go`, `MerkleRoot` (листья сортируются на каждом уровне по описанной в коде схеме).
4. Итоговая строка:  
   `SHA256( tx_id "|" contentHash "|" merkleRoot "|" timestamp )`  
   (как строка в `fmt.Sprintf`, затем байты UTF-8 → SHA-256 → hex).

Так узел криптографически «привязан» к родителям и к содержимому транзакции.

### 4.6. Файл ключей

`internal/crypto/persist.go`:

- путь: `{БД}/authority_keys.json`;
- формат: версия + map `private_keys_pem` по кодам стран;
- загрузка: `LoadOrCreateAuthorityKeys`;
- при полном сбросе БД: `RegenerateAuthorityKeys`.

---

## 5. «Консенсус» и gossip (что это в проекте)

Здесь **нет** распределённого протокола консенсуса между независимыми узлами сети (как в Bitcoin/PoS). Всё выполняется **внутри одного процесса**.

Файл: `internal/consensus/gossip.go`.

- При добавлении узла (`appendTransactionLocked` в `internal/dag/store.go`) вызываются:
  - `GossipState.LogGossip` — добавляется запись о событии (seq, время, tx_id, родители, подсказки «peer»);
  - `RunVirtualVote` — **детерминированное упорядочивание** всех узлов: вычисляется «глубина» в DAG, затем сортировка по глубине, timestamp, `tx_id`; результат сохраняется как `VirtualVoteStep` с полем `WinnerTxIDs` и пояснением в `Reason`.

Это **демонстрационная** модель порядка обработки / «голосования», а не согласование нескольких реплик БД. Данные пишутся в `nodes.json` вместе с узлами.

---

## 6. Жизненный цикл транзакций в DAG

Общая точка добавления узла: `appendTransaction` → `appendTransactionLocked` (`internal/dag/store.go`).

Этапы для **каждой** новой транзакции:

1. Проверка: `action` только `issue` или `revoke`.
2. Генерация `tx_id` и при необходимости `timestamp`.
3. Разрешение родителей: если `parent_ids` пустой и граф не пуст — подставляются **tips** (головы DAG), см. `tipsLocked`.
4. Сбор `parent_node_hash` для каждого родителя.
5. **Подпись** `SignTransaction`.
6. **Вычисление** `ComputeNodeHash` и создание `DAGNode`.
7. Запись в `s.nodes`, вызов gossip + RunVirtualVote.
8. **Сохранение** `persistGraph` → `nodes.json`.

Публичные обёртки:

- `AddIssue` — только `action == issue`;
- `AddRevoke` — только `action == revoke`, плюс проверка эмитента через `findIssuerForDoc`.

---

## 7. Выдача документа (issue)

| Этап | Где в коде |
|------|------------|
| HTTP POST | `internal/api/server.go` — `handleIssue`, маршрут `/api/tx/issue` |
| Разбор тел и хэшей | `applyDocumentAndMetaHashes` в том же файле |
| Сборка `DocumentTransaction` с `ActionIssue` | `handleIssue` |
| Добавление в граф | `s.Store.AddIssue` → `internal/dag/store.go` |
| Обновление реестра для UI | `db.UpsertDocument` — `internal/db/documents.go` |

После успешного issue в `documents.json` сохраняются payload’ы и хэши, ссылки на последний узел и действие.

---

## 8. Отзыв документа (revoke)

| Этап | Где в коде |
|------|------------|
| HTTP POST | `internal/api/server.go` — `handleRevoke`, маршрут `/api/tx/revoke` |
| Проверка эмитента до записи | `AddRevoke` → `findIssuerForDoc` — `internal/dag/store.go` |
| Подпись и узел | общий путь `appendTransaction` |
| Реестр | `db.UpsertDocumentLastAction` — `internal/db/documents.go` |

В графе узел **issue не удаляется** — добавляется новый узел **revoke**, обычно с родителями по умолчанию (tips), если клиент не передал своих.

---

## 9. Проверка документа (не узел цепочки)

Операция **не создаёт** транзакцию в DAG.

| Этап | Где в коде |
|------|------------|
| HTTP POST | `internal/api/server.go` — `handleVerifyLookup`, маршрут `/api/verify` |
| Перезагрузка диска | `ReloadChainFromDisk` перед проверкой |
| Логика статуса | `Store.VerifyLookup` — `internal/dag/store.go` |

Кратко:

- По `document_id` ищется **последняя по времени** (с учётом tie-break) транзакция среди **issue** и **revoke** в памяти после загрузки.
- Если последняя — **revoke** → статус «отозван», не ок для «действующего» документа.
- Если последняя — **issue** → сравниваются хэши содержимого и метаданных с переданными в запросе (после `applyDocumentAndMetaHashes`).

---

## 10. Полная проверка цепочки (`/api/validate`)

| Этап | Где в коде |
|------|------------|
| HTTP GET | `internal/api/server.go` — `handleValidate` |
| Перезагрузка с диска | `ReloadChainFromDisk` |
| Проверки | `Store.ValidateAll` — `internal/dag/store.go` |

Порядок проверок в `ValidateAll` (упрощённо):

1. **Для каждого узла:** ECDSA подпись (`VerifyTransaction`) → код `bad_signature`, если не сходится.
2. **Целостность ссылок:** каждый `parent_id` существует; вычисление ожидаемого `ComputeNodeHash`; сравнение с `node_hash` → `missing_parent`, `hash_error`, `node_hash_mismatch`.
3. **Семантика revoke:** для каждого revoke есть соответствующий issue по `document_id`; эмитент revoke совпадает с эмитентом выпуска → иначе `revoke_no_issue`, `illegal_revoke`.
4. **Предупреждения:** если по `document_id` есть issue и более поздний revoke → предупреждение `document_revoked` (не ошибка целостности журнала).

Итог агрегируется в `ValidationResult` (`summary_ru`, `errors`, `warnings`, счётчики). Тексты на русском формируются функциями `validationSummaryRU`, `integrityOverviewLines` в том же файле `store.go`.

Запись в операционный лог: `OpLogInfo` после validate — попадает в `logs.json`.

---

## 11. Прочие API (кратко)

| Маршрут | Назначение | Файл |
|---------|------------|------|
| `/api/config` | Типы, эмитенты, органы для UI | `server.go` |
| `/api/documents` | Список из `documents.json` | `server.go` |
| `/api/dag` | Снимок узлов для визуализации | `handleDAG` |
| `/api/gossip` | События и голоса из Store | обработчик gossip |
| `/api/logs` | Операционный лог | `handleLogs` |
| `/api/merkle/proof/...` | Упрощённое Merkle-доказательство по множеству транзакций (демо) | `handleMerkleProof` |
| `/api/attacks/*` | Симуляции атак в памяти с откатом | `server.go` + методы `Attack*` в `internal/dag/store.go` |

Веб-интерфейс: статические файлы `web/index.html`, `web/js/app.js`, `web/css/style.css`.

---

## 12. Поток данных при типичном запросе issue

```text
Клиент POST /api/tx/issue
    → server.go: JSON → хэши payload
    → DocumentTransaction + AddIssue
    → appendTransactionLocked: SignTransaction, ComputeNodeHash, gossip, persistGraph
    → nodes.json обновлён на диске
    → UpsertDocument → documents.json
```

---

## 13. Зависимости между пакетами (обзор)

- `cmd/bbsi` → `api`, `dag`, `db`, `crypto`
- `internal/api` → `dag`, `db`, `model`, `crypto`
- `internal/dag` → `consensus`, `crypto`, `db`, `model`
- `internal/consensus` — автономный пакет структур и логики порядка
- `internal/model` — типы транзакций и константы стран/действий
- `internal/db` — только файловый JSON и модели файлов

---

## 14. Ограничения и замечания для читателя кода

- Один процесс — нет репликации и сетевого консенсуса между узлами.
- Подписант транзакции определяется полем **`issuer_country`**; для revoke это должен быть эмитент оригинального issue (проверка в `AddRevoke`).
- Содержимое документа в открытом виде в DAG не хранится — только хэши и метаданные для подписи.
- Изменение `nodes.json` на диске при работающем сервере до перезагрузки или до вызова endpoints с `ReloadChainFromDisk` может не совпадать с памятью — для validate/verify lookup реализована перезагрузка с диска.

Этого достаточно, чтобы пройтись по репозиторию от хранения до конкретных функций проверки и выдачи.
