# BBSI: процессы «хэшчейна» (DAG) и где они выполняются в коде

Документ переписан вокруг пяти тем: **консенсус**, **подпись**, **SHA-256**, **построение цепочки и узел**, **выдача и отзыв**. Все пути — от корня репозитория (`internal/...`, `cmd/...`).

---

## Вводное замечание

В проекте нет классического **шифрования** содержимого документов в журнале: хранятся **хэши** содержимого и метаданных и **цифровая подпись ECDSA** транзакции. «Хэшчейн» здесь — это **DAG** из узлов, связанных ссылками на родителей, где каждый узел имеет поле **`node_hash`**, вычисляемое из транзакции и хэшей родительских узлов.

Центральный объект журнала: **`dag.Store`** (`internal/dag/store.go`).

Единая функция добавления узла в граф (после проверок): **`appendTransaction`** → **`appendTransactionLocked`** в **`internal/dag/store.go`**.

Сохранение на диск: **`persistGraph`** в **`internal/dag/persistence.go`** → файл **`{БД}/nodes.json`** (имя файла задаётся **`internal/db/db.go`**, константа **`FileNodes`**).

---

## 1. Консенсус: как здесь устроено и где в коде

### 1.1. Что это означает в BBSI

Здесь **нет** распределённого протокола согласия между независимыми репликами по сети (не Raft/PBFT/Bitcoin). Всё выполняется **в одном процессе** сервера.

После **каждого** добавления узла в DAG выполняются два связанных действия:

1. **Запись «события gossip»** — упрощённая шкала «новый узел и его родители».
2. **«Виртуальное голосование»** — детерминированное **упорядочивание всех узлов графа** по правилам глубины в DAG и времён; результат сохраняется как один шаг с упорядоченным списком `tx_id`.

Это **демонстрационная абстракция**: журнал событий и шаг «голосования» сериализуются в **`nodes.json`** вместе с узлами.

### 1.2. Где вызывается

Файл **`internal/dag/store.go`**, функция **`appendTransactionLocked`** (конец функции, после записи узла в `s.nodes`):

1. **`s.gossip.LogGossip(txID, parentIDs, peerSeen)`** — протокол в **`internal/consensus/gossip.go`**, метод **`GossipState.LogGossip`**.

   Передаётся `seen`, собранный из списка родителей (в коде это текущие `parent_ids` нового узла).

2. Сбор всех узлов в **`[]consensus.NodeOrder`** (поля `TxID`, `ParentIDs`, `Timestamp`) через **`allNodesLocked`**.

3. **`s.gossip.RunVirtualVote(orders)`** — в **`internal/consensus/gossip.go`**, метод **`GossipState.RunVirtualVote`**.

4. Итог пишется в операционный лог строкой вида «Gossip: добавлен узел …, виртуальный порядок: …» через **`s.log`** (`internal/dag/store.go`).

### 1.3. Алгоритм `RunVirtualVote` (по коду)

Файл **`internal/consensus/gossip.go`**.

- Для каждого `tx_id` вычисляется **глубина** в графе: рекурсивно по родителям (`visit`), без родителей глубина 0, иначе `max(глубина родителей) + 1`.
- Строится список `(tx_id, depth, timestamp)` и сортируется:
  - сначала по **возрастанию depth**,
  - при равенстве — по **возрастанию timestamp**,
  - при равенстве — по **лексикографическому порядку `tx_id`**.
- Добавляется **`VirtualVoteStep`** с **`WinnerTxIDs`** = все узлы в этом упорядоченном порядке, **`Reason`** — текстовая строка из кода.

### 1.4. Где хранится на диске

Структура **`persistedGraph`** в **`internal/dag/persistence.go`**:

- **`gossip_events`** ← **`GossipState.Events`** (`GossipEvent`);
- **`gossip_votes`** ← **`GossipState.Votes`** (`VirtualVoteStep`, JSON-тег поля **`virtual_votes`**).

Читание/запись того же файла, что и узлы DAG — **`nodes.json`**.

---

## 2. Подпись: как работает и где в коде

### 2.1. Модель

Используется **ECDSA на кривой P-256**. Отдельный ключ для каждого кода страны (**BY**, **RU**, **KZ**, **AM**, **AZ**) из **`internal/model/types.go`**.

Ключи держит тип **`crypto.AuthorityKeys`** (**`internal/crypto/keys.go`**):

- **`private`** / **`public`** — карты по коду страны.

Загрузка и сохранение ключей на диск:

- **`internal/crypto/persist.go`** — **`LoadOrCreateAuthorityKeys`**, файл **`{каталог_БД}/authority_keys.json`**.

### 2.2. Что именно подписывается

Подпись строится **не над всем JSON узла**, а над **каноническим представлением полей транзакции без поля подписи**:

Функция **`CanonicalJSONWithoutSig`** — **`internal/crypto/canonical.go`**.

В объект входят поля (ключи сортируются, затем `json.Marshal`):

`action`, `document_hash`, `document_id`, `document_type`, `issuer_authority`, `issuer_country`, `metadata_hash`, `receiver_country`, `timestamp`, `tx_id`.

Поле **`issuer_signature` намеренно отсутствует**, иначе было бы циклическое определение подписи.

### 2.3. Цепочка вызовов при записи узла

Файл **`internal/dag/store.go`**, **`appendTransactionLocked`**:

```text
s.keys.SignTransaction(tx)
```

Реализация **`SignTransaction`** — **`internal/crypto/keys.go`**:

1. **`CanonicalJSONWithoutSig(tx)`** → байты **`body`**.
2. **`Sign(tx.IssuerCountry, body)`**:
   - **`h := sha256.Sum256(body)`** — первый SHA-256 от тела (см. раздел 3);
   - **`ecdsa.SignASN1(rand.Reader, priv, h[:])`** — подпись ASN.1 DER;
   - результат кодируется в **hex**-строку.
3. Строка записывается в **`tx.IssuerSignature`**.

Имеется в виду: подпись создаётся **ключом страны из поля `IssuerCountry`** транзакции.

### 2.4. Проверка подписи при валидации цепочки

Файл **`internal/dag/store.go`**, **`ValidateAll`** (цикл по всем узлам):

```text
s.keys.VerifyTransaction(&n.Transaction)
```

Реализация **`VerifyTransaction`** — **`internal/crypto/keys.go`**:

1. Снова **`CanonicalJSONWithoutSig(tx)`** → **`body`**.
2. **`h := sha256.Sum256(body)`** (тот же хэш, что при подписании).
3. Публичный ключ берётся по **`tx.IssuerCountry`**.
4. **`ecdsa.VerifyASN1(pub, h[:], sig)`** после декодирования **`IssuerSignature`** из hex.

При несоответствии в результат валидации попадает код **`bad_signature`**.

---

## 3. SHA-256 и связанные операции: где и для чего

Ниже все функции лежат в пакете **`internal/crypto`**, если не указано иное.

### 3.1. `SHA256Hex(data []byte)`

Файл **`internal/crypto/hash.go`**.

Использование: **`sha256.Sum256(data)`**, результат в hex. Это базовый примитив для:

- финального **`node_hash`** (строка-сборка → байты → **`SHA256Hex`**),
- листьев и пар в **`MerkleRoot`**,
- хэша канонического JSON транзакции (**`ContentHash`**),
- хэша канонических payload’ов документа/метаданных (**`HashCanonicalJSON`**).

### 3.2. Хэш «содержимого транзакции» для узла (`ContentHash`)

Файл **`internal/crypto/canonical.go`**, функция **`ContentHash(tx)`**:

```text
CanonicalJSONWithoutSig(tx) → байты → SHA256Hex → строка content hash
```

Эта строка входит в формулу **`ComputeNodeHash`** (раздел 4).

Важно: это **отдельный** объект от подписи: подпись также использует **`CanonicalJSONWithoutSig`**, но дальше для ECDSA берётся **`sha256.Sum256(body)`** (байтовый хэш), а **`ContentHash`** — это **ещё один** SHA-256 от тех же байтов, уже представленный как **hex-строка** для включения в строку **`payload`** узла.

### 3.3. Хэши документа и метаданных из JSON (API issue)

Файл **`internal/crypto/jsoncanon.go`**:

- **`canonicalizeJSON`** — рекурсивная сортировка ключей в объектах;
- **`CanonicalJSONFromPayload`** — сериализация без лишнего экранирования;
- **`HashCanonicalJSON(raw)`** — разбор JSON → канонизация → **`SHA256Hex`**.

Вызывается из **`internal/api/server.go`**, функция **`applyDocumentAndMetaHashes`**, когда клиент передаёт **`document_payload`** / **`metadata_payload`** или сверяет явные хэши с payload.

Итог попадает в поля **`DocumentHash`** и **`MetadataHash`** структуры **`model.DocumentTransaction`** (**`internal/model/types.go`**).

### 3.4. Merkle по родительским `node_hash`

Файл **`internal/crypto/hash.go`**:

- **`MerkleRoot(leaves []string)`** — листья — hex-строки **`node_hash`** родителей; список копируется и **сортируется**; уровни склеиваются через **`SHA256Pair`** (лексикографический порядок пары фиксируется в коде).
- Пустой список листьев даёт константный хэш от строки **`"empty"`**.

### 3.5. SHA-256 внутри ECDSA (подпись)

Файл **`internal/crypto/keys.go`**, методы **`Sign`** и **`VerifyTransaction`**: перед **`SignASN1`** / **`VerifyASN1`** используется **`sha256.Sum256`** от байтов канонического тела (см. раздел 2).

---

## 4. Как строится хэшчейн и структура узла

### 4.1. Структура узла на диске и в памяти

Тип **`DAGNode`** — **`internal/dag/node.go`**:

| Поле | JSON | Смысл |
|------|------|--------|
| **`Transaction`** | `transaction` | Одна **`DocumentTransaction`** — см. **`internal/model/types.go`**: `tx_id`, `document_id`, типы, хэши содержимого/метаданных, страны, `action`, `timestamp`, **`issuer_signature`**. |
| **`ParentIDs`** | `parent_ids` | Массив **`tx_id`** родительских узлов (рёбра DAG «новый узел → родители»). |
| **`NodeHash`** | `node_hash` | Агрегирующий хэш узла; связывает транзакцию с родителями. |

Граф в памяти: **`Store.nodes`** — **`map[string]*DAGNode`** по ключу **`tx_id`** (**`internal/dag/store.go`**).

### 4.2. Формула `node_hash`

Функция **`ComputeNodeHash`** — **`internal/dag/node.go`**:

1. **`ch := ContentHash(tx)`** — SHA-256 канонического JSON транзакции (hex).
2. Для каждого **`parent_id`** из **`parentIDs`** из карты **`parentNodeHashes`** берётся **`node_hash`** родителя (не транзакционный хэш напрямую). Если родитель не найден — ошибка.
3. **`mr := MerkleRoot(leaves)`** — корень по списку **`node_hash`** родителей в порядке **`parentIDs`**.
4. Строка **`payload`** (UTF-8):

   **`fmt.Sprintf("%s|%s|%s|%d", tx.TxID, ch, mr, tx.Timestamp)`**

5. **`node_hash = SHA256Hex([]byte(payload))`**.

Так новый узел криптографически зависит от содержимого своей транзакции и от **`node_hash`** всех указанных родителей.

### 4.3. Построение цепочки при добавлении транзакции

Вся логика в **`internal/dag/store.go`**, функция **`appendTransactionLocked`** (публичный вход **`appendTransaction`** добавляет **`persistGraph`**).

Пошагово:

1. **Уникальность** `tx_id`; если пустой — **`randomTxId`** в этом же файле.
2. **`timestamp`** по умолчанию — текущее время Unix (секунды).
3. **`action`** только **`issue`** или **`revoke`** (иначе ошибка).
4. Валидация родителей: каждый **`parent_id`** должен существовать в **`s.nodes`**.
5. Если **`parent_ids` пустой** и граф **не пуст** — подстановка **tips** (**`tipsLocked`**): все узлы, которые никто не указывает как родителя (активные «головы» DAG).
6. Карта **`ph`**: для каждого родителя **`ph[pid] = s.nodes[pid].NodeHash`**.
7. **`SignTransaction`** → заполнение **`IssuerSignature`**.
8. **`ComputeNodeHash(tx, parentIDs, ph)`** → **`NodeHash`**.
9. Узел добавляется в **`s.nodes`**.
10. Вызов **gossip** и **`RunVirtualVote`** (раздел 1).
11. Снаружи под блокировкой **`appendTransaction`** вызывается **`persistGraph`** — запись **`nodes.json`**.

Первый узел в пустом графе: родителей нет → **`MerkleRoot`** от пустого списка даёт хэш **`"empty"`**.

---

## 5. Операции «выдача» и «отзыв»: полный разбор по шагам и файлам

Обе операции в журнал сводятся к **`appendTransaction`** после специфических проверок и формирования **`DocumentTransaction`** на HTTP-слое или в **`Store`**.

### 5.1. Выдача документа (**issue**)

#### Шаг A — HTTP и разбор тела запроса

| Шаг | Файл | Функция / место |
|-----|------|------------------|
| Маршрут POST | **`internal/api/server.go`** | **`Routes`**: **`/api/tx/issue`** → **`handleIssue`**. |
| Разбор JSON | **`internal/api/server.go`** | Тип **`issueReq`** (поля `document_id`, `document_type`, хэши, payload’ы, страны, **`parent_ids`**). |

#### Шаг B — хэши содержимого и метаданных

| Шаг | Файл | Функция |
|-----|------|---------|
| Вычисление/проверка `document_hash`, `metadata_hash` | **`internal/api/server.go`** | **`applyDocumentAndMetaHashes`** — при наличии payload вызывает **`chaincrypto.HashCanonicalJSON`** (**`internal/crypto/jsoncanon.go`**). |

#### Шаг C — сборка транзакции

| Шаг | Файл | Что происходит |
|-----|------|----------------|
| Установка полей | **`internal/api/server.go`** | **`handleIssue`**: создаётся **`model.DocumentTransaction`** с **`ActionIssue`**, **`DocumentHash`**, **`MetadataHash`**, странами и типом; если тип пуст — **`model.DocDiploma`** (**`internal/model/types.go`**). |

#### Шаг D — запись в DAG

| Шаг | Файл | Функция |
|-----|------|---------|
| Вызов журнала | **`internal/api/server.go`** | **`s.Store.AddIssue(tx, req.ParentIDs)`**. |
| Проверка `action` | **`internal/dag/store.go`** | **`AddIssue`** требует **`model.ActionIssue`**. |
| Общий конвейер | **`internal/dag/store.go`** | **`appendTransaction`** → **`appendTransactionLocked`** (подпись, **`ComputeNodeHash`**, gossip, голосование, **`persistGraph`**). |

#### Шаг E — реестр для UI (не источник крипто-истины цепочки)

| Шаг | Файл | Функция |
|-----|------|---------|
| Обновление **`documents.json`** | **`internal/api/server.go`** | После успеха: **`db.UpsertDocument`** (**`internal/db/documents.go`**) — payload’ы, хэши, **`LastTxID`**, **`LastAction: issue`**. |

#### Шаг F — ответ клиенту

JSON с ключом **`node`** — сериализованный **`DAGNode`** (узел с **`transaction`**, **`parent_ids`**, **`node_hash`**).

---

### 5.2. Отзыв документа (**revoke**)

#### Шаг A — HTTP

| Шаг | Файл | Функция |
|-----|------|---------|
| Маршрут POST | **`internal/api/server.go`** | **`/api/tx/revoke`** → **`handleRevoke`**. |

#### Шаг B — формирование транзакции на сервере

| Шаг | Файл | Что происходит |
|-----|------|----------------|
| Тело запроса | **`internal/api/server.go`** | Тип **`revokeReq`**: **`document_id`**, **`issuer_country`**, **`parent_ids`**. |
| Сборка **`DocumentTransaction`** | **`internal/api/server.go`** | **`handleRevoke`**: **`ActionRevoke`**, **`IssuerCountry`** из запроса, **`IssuerAuthority`** фиксирован как строка **`Revocation`**, **`ReceiverCountry`** из **`model.CountryBY`**, **`MetadataHash`** от байтов **`"revoke"`** через **`chaincrypto.SHA256Hex`**, тип документа по умолчанию диплом и т.д. |

То есть для revoke часть полей задаётся **не клиентскими payload’ами документа**, а шаблоном в **`handleRevoke`**.

#### Шаг C — бизнес-правило «кто может отозвать»

| Шаг | Файл | Функция |
|-----|------|---------|
| Проверка до подписи | **`internal/dag/store.go`** | **`AddRevoke`** вызывает **`findIssuerForDoc(document_id)`** под **`RLock`**. |
| Поиск эмитента выпуска | **`internal/dag/store.go`** | **`findIssuerForDoc`**: среди узлов с **`document_id`** и **`action == issue`** выбирается выпуск с **минимальным `timestamp`** (ранний **`issue`** как эталон эмитента). |
| Сравнение | **`internal/dag/store.go`** | Если **`tx.IssuerCountry != issuer`** — ошибка **`отзыв может выполнить только эмитент …`**; узел **не** добавляется. |

Если проверка прошла — вызывается **`appendTransaction`** → тот же конвейер, что у issue: подпись ключом **`IssuerCountry`** транзакции revoke, **`node_hash`**, gossip, голосование, **`persistGraph`**.

#### Шаг D — реестр

| Шаг | Файл | Функция |
|-----|------|---------|
| Последнее действие | **`internal/api/server.go`** | **`db.UpsertDocumentLastAction`** (**`internal/db/documents.go`**) — **`LastTxID`**, **`LastAction: revoke`**. |

#### Шаг E — семантика в журнале

Узел **issue не удаляется**. В графе появляется **ещё один** узел **`revoke`** с тем же **`document_id`**. Связь с прошлым состоянием задаётся **`parent_ids`** (часто автоматически tips, если клиент передал пустой список).

Полная проверка журнала (**`/api/validate`**) дополнительно проверяет каждый revoke (**`ValidateAll`** в **`internal/dag/store.go`**): наличие issue по документу и совпадение эмитента (**`findIssuerLocked`** / коды **`revoke_no_issue`**, **`illegal_revoke`**). Отдельно формируются предупреждения **`document_revoked`**, если revoke не старше соответствующего issue — это про «действительность документа», не про поломку цепочки.

---

## Краткая карта файлов

| Тема | Основные файлы |
|------|----------------|
| DAG, добавление узла, валидация, issue/revoke на стороне журнала | **`internal/dag/store.go`**, **`internal/dag/node.go`** |
| Сохранение графа, **`nodes.json`**, миграция legacy verify | **`internal/dag/persistence.go`** |
| Консенсус-подобное упорядочивание и gossip | **`internal/consensus/gossip.go`** |
| ECDSA, канонизация транзакции для подписи и **`ContentHash`** | **`internal/crypto/keys.go`**, **`internal/crypto/canonical.go`** |
| SHA-256, Merkle | **`internal/crypto/hash.go`** |
| Хэши JSON payload’ов (issue в API) | **`internal/crypto/jsoncanon.go`** |
| HTTP issue/revoke | **`internal/api/server.go`** |
| Модель транзакции | **`internal/model/types.go`** |
| Файлы БД и имена JSON | **`internal/db/db.go`** |
| Ключи эмитентов на диске | **`internal/crypto/persist.go`** → **`authority_keys.json`** |

Этого достаточно, чтобы пройти любой шаг «хэшчейна» от HTTP до байтов на диске по конкретным функциям.
