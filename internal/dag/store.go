package dag

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"BBSI/internal/consensus"
	"BBSI/internal/crypto"
	"BBSI/internal/db"
	"BBSI/internal/model"
)

// Store — журнал узлов DAG (хэшчейн без «блоков»).
type Store struct {
	mu     sync.RWMutex
	opMu   sync.Mutex
	nodes  map[string]*DAGNode
	keys   *crypto.AuthorityKeys
	db     *db.Database
	gossip *consensus.GossipState
	opLog  []OperationLogEntry
	onLog  func(OperationLogEntry)
}
type OperationLogEntry struct {
	Time    int64  `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

func NewStore(keys *crypto.AuthorityKeys, database *db.Database) (*Store, error) {
	s := &Store{
		nodes:  make(map[string]*DAGNode),
		keys:   keys,
		db:     database,
		gossip: consensus.NewGossipState(),
	}
	if database != nil {
		if err := s.loadFromDisk(); err != nil {
			log.Printf("BBSI: nodes.json: %v", err)
		}
		if err := s.loadLogsFromDisk(); err != nil {
			log.Printf("BBSI: logs.json: %v", err)
		}
	}
	return s, nil
}

func (s *Store) SetLogHook(fn func(OperationLogEntry)) { s.onLog = fn }

// ResetChainAndLogs очищает узлы DAG, gossip и операционный журнал в памяти и в файлах.
// keys задаёт новые ключи подписи эмитентов (обязательно при полном сбросе authority_keys.json).
func (s *Store) ResetChainAndLogs(keys *crypto.AuthorityKeys) error {
	if keys != nil {
		s.keys = keys
	}
	s.mu.Lock()
	s.nodes = make(map[string]*DAGNode)
	s.gossip = consensus.NewGossipState()
	s.mu.Unlock()

	s.opMu.Lock()
	s.opLog = nil
	s.opMu.Unlock()

	if s.db == nil {
		return nil
	}
	if err := s.persistGraph(); err != nil {
		return err
	}
	return s.persistLogs()
}

func (s *Store) log(level, msg string) {
	e := OperationLogEntry{Time: time.Now().UnixMilli(), Level: level, Message: msg}
	s.opMu.Lock()
	s.opLog = append(s.opLog, e)
	if len(s.opLog) > 2000 {
		s.opLog = s.opLog[len(s.opLog)-1500:]
	}
	h := s.onLog
	s.opMu.Unlock()
	if h != nil {
		h(e)
	}
	_ = s.persistLogs()
}

func randomTxID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return hex.EncodeToString(b)
}

// Tips — узлы, которые не являются родителями ни для кого другого (активные «головы» DAG).
func (s *Store) Tips() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	child := map[string]bool{}
	for _, n := range s.nodes {
		for _, p := range n.ParentIDs {
			child[p] = true
		}
	}
	var tips []string
	for id := range s.nodes {
		if !child[id] {
			tips = append(tips, id)
		}
	}
	return tips
}

func (s *Store) parentHashes(parentIDs []string) map[string]string {
	out := make(map[string]string)
	for _, pid := range parentIDs {
		if n, ok := s.nodes[pid]; ok {
			out[pid] = n.NodeHash
		}
	}
	return out
}

// AddIssue — выпуск документа.
func (s *Store) AddIssue(tx *model.DocumentTransaction, parentIDs []string) (*DAGNode, error) {
	if tx.Action != model.ActionIssue {
		return nil, errors.New("ожидается action=issue")
	}
	return s.appendTransaction(tx, parentIDs)
}

// AddRevoke — только эмитент оригинального issue может отозвать.
func (s *Store) AddRevoke(tx *model.DocumentTransaction, parentIDs []string) (*DAGNode, error) {
	if tx.Action != model.ActionRevoke {
		return nil, errors.New("ожидается action=revoke")
	}
	issuer, ok := s.findIssuerForDoc(tx.DocumentID)
	if !ok {
		return nil, errors.New("документ не найден или нет выпуска (issue)")
	}
	if tx.IssuerCountry != issuer {
		return nil, fmt.Errorf("отзыв может выполнить только эмитент %s (указано: %s)", issuer, tx.IssuerCountry)
	}
	return s.appendTransaction(tx, parentIDs)
}

func (s *Store) findIssuerForDoc(docID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *DAGNode
	for _, n := range s.nodes {
		if n.Transaction.DocumentID != docID || n.Transaction.Action != model.ActionIssue {
			continue
		}
		if best == nil || n.Transaction.Timestamp < best.Transaction.Timestamp {
			nn := *n
			best = &nn
		}
	}
	if best == nil {
		return "", false
	}
	return best.Transaction.IssuerCountry, true
}

func (s *Store) appendTransaction(tx *model.DocumentTransaction, parentIDs []string) (*DAGNode, error) {
	node, err := s.appendTransactionLocked(tx, parentIDs)
	if err != nil {
		return nil, err
	}
	if err := s.persistGraph(); err != nil {
		s.log("warn", "сохранение nodes.json: "+err.Error())
	}
	return node, nil
}

func (s *Store) appendTransactionLocked(tx *model.DocumentTransaction, parentIDs []string) (*DAGNode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.nodes[tx.TxID]; exists {
		return nil, errors.New("tx_id уже существует")
	}
	if tx.TxID == "" {
		tx.TxID = randomTxID()
	}
	if tx.Timestamp == 0 {
		tx.Timestamp = time.Now().Unix()
	}
	if tx.Action != model.ActionIssue && tx.Action != model.ActionRevoke {
		return nil, errors.New("в журнал допускаются только транзакции issue и revoke")
	}
	for _, pid := range parentIDs {
		if _, ok := s.nodes[pid]; !ok {
			return nil, fmt.Errorf("неизвестный родитель: %s", pid)
		}
	}
	if len(parentIDs) == 0 && len(s.nodes) > 0 {
		parentIDs = s.tipsLocked()
	}
	ph := map[string]string{}
	for _, pid := range parentIDs {
		ph[pid] = s.nodes[pid].NodeHash
	}
	if err := s.keys.SignTransaction(tx); err != nil {
		return nil, err
	}
	nodeHash, err := ComputeNodeHash(tx, parentIDs, ph)
	if err != nil {
		return nil, err
	}
	node := &DAGNode{
		Transaction: *tx,
		ParentIDs:   append([]string(nil), parentIDs...),
		NodeHash:    nodeHash,
	}
	s.nodes[node.Transaction.TxID] = node

	seen := append([]string(nil), parentIDs...)
	s.gossip.LogGossip(node.Transaction.TxID, node.ParentIDs, seen)
	var orders []consensus.NodeOrder
	for _, nx := range s.allNodesLocked() {
		orders = append(orders, consensus.NodeOrder{
			TxID:      nx.Transaction.TxID,
			ParentIDs: append([]string(nil), nx.ParentIDs...),
			Timestamp: nx.Transaction.Timestamp,
		})
	}
	v := s.gossip.RunVirtualVote(orders)
	s.log("info", fmt.Sprintf("Gossip: добавлен узел %s, виртуальный порядок: %v", tx.TxID, v[0].WinnerTxIDs))
	return node, nil
}

func (s *Store) tipsLocked() []string {
	child := map[string]bool{}
	for _, n := range s.nodes {
		for _, p := range n.ParentIDs {
			child[p] = true
		}
	}
	var tips []string
	for id := range s.nodes {
		if !child[id] {
			tips = append(tips, id)
		}
	}
	return tips
}

func (s *Store) allNodesLocked() []*DAGNode {
	out := make([]*DAGNode, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, n)
	}
	return out
}

// NodesSnapshot — все узлы.
func (s *Store) NodesSnapshot() []*DAGNode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*DAGNode, 0, len(s.nodes))
	for _, n := range s.nodes {
		cp := *n
		cp.ParentIDs = append([]string(nil), n.ParentIDs...)
		out = append(out, &cp)
	}
	return out
}

func (s *Store) OperationLogSnapshot() []OperationLogEntry {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return append([]OperationLogEntry(nil), s.opLog...)
}

// ValidationResult — итог /api/validate и пошаговые сообщения для UI.
type ValidationResult struct {
	Ok            bool              `json:"ok"`
	Errors        []ValidationError `json:"errors,omitempty"`
	Warnings      []ValidationError `json:"warnings,omitempty"`
	SummaryRU     string            `json:"summary_ru"`
	ErrorCounts   map[string]int    `json:"error_counts,omitempty"`
	WarningCounts map[string]int    `json:"warning_counts,omitempty"`
}

type ValidationError struct {
	NodeID  string `json:"node_id"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Пояснение к коду ошибки для человека (одна строка).
var validationCodeRU = map[string]string{
	"bad_signature":                 "подпись ECDSA не совпадает с ключом страны из поля issuer_country (часто: атака «подмена эмитента», либо журнал подписан другими ключами, чем в текущем authority_keys.json)",
	"node_hash_mismatch":            "поле node_hash не согласовано с данными узла (типичная «тихая» подделка полей без пересчёта хэша)",
	"missing_parent":                "в графе указан родитель, которого нет среди узлов",
	"hash_error":       "ошибка при вычислении хэша узла",
	"revoke_no_issue":  "отзыв без предшествующего issue по документу",
	"illegal_revoke":                "отзыв подписан не тем эмитентом, который выпускал документ",
	"document_revoked":              "после выпуска (issue) зафиксирован отзыв (revoke) того же document_id — документ не считается действующим (ожидаемо после операции «Отозвать»; не ошибка журнала)",
}

var validationCodeOrder = []string{
	"bad_signature", "node_hash_mismatch", "missing_parent", "hash_error",
	"revoke_no_issue", "illegal_revoke",
}

var validationWarningCodeOrder = []string{
	"document_revoked",
}

func countByCode(errs []ValidationError) map[string]int {
	m := make(map[string]int)
	for _, e := range errs {
		m[e.Code]++
	}
	return m
}

func integrityOverviewLines(errs, warnings []ValidationError) string {
	structuralCodes := map[string]struct{}{
		"bad_signature": {}, "node_hash_mismatch": {}, "missing_parent": {}, "hash_error": {},
	}
	nStruct, nSem := 0, 0
	for _, e := range errs {
		if _, ok := structuralCodes[e.Code]; ok {
			nStruct++
		} else {
			nSem++
		}
	}
	if len(errs) == 0 && len(warnings) == 0 {
		return strings.Join([]string{
			"[1] Целостность цепи (подписи ECDSA, узловой хэш, связь с родителями в nodes.json)",
			"    Статус: OK.",
			"    Заметка: подмена поля в файле без пересчёта подписи и node_hash обычно даёт bad_signature или node_hash_mismatch.",
			"",
			"[2] Правила транзакций в журнале (issue и revoke)",
			"    Статус: OK.",
			"    Заметка: отзыв только от эмитента выпуска, после issue.",
		}, "\n")
	}
	if len(errs) == 0 && len(warnings) > 0 {
		return strings.Join([]string{
			"[1] Целостность цепи (подписи ECDSA, узловой хэш, связь с родителями в nodes.json)",
			"    Статус: OK.",
			"    Заметка: подмена поля в файле без пересчёта подписи и node_hash обычно даёт bad_signature или node_hash_mismatch.",
			"",
			"[2] Правила транзакций в журнале (issue и revoke)",
			"    Статус: ошибок правил нет.",
			fmt.Sprintf("    Дополнительно в поле warnings: %d записей о статусе документов (например отозванный после выпуска — код document_revoked; журнал при этом корректен).", len(warnings)),
		}, "\n")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[1] Целостность цепи (подписи ECDSA, узловой хэш, связь с родителями в nodes.json)\n")
	if nStruct == 0 {
		b.WriteString("    Статус: OK — журнал криптографически согласован.\n")
		b.WriteString("    Если правили JSON вручную без пересчёта, обычно видны bad_signature или node_hash_mismatch.\n")
	} else {
		fmt.Fprintf(&b, "    Статус: ЕСТЬ ПРОБЛЕМЫ (%d).\n", nStruct)
		b.WriteString("    Частые причины: правка nodes.json без пересчёта узла, другие ключи в authority_keys.json, подмена issuer_country без новой подписи.\n")
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "[2] Правила транзакций в журнале (issue и revoke)\n")
	if nSem == 0 {
		b.WriteString("    Статус: OK.\n")
	} else {
		fmt.Fprintf(&b, "    Статус: ЕСТЬ ЗАМЕЧАНИЯ (%d).\n", nSem)
		b.WriteString("    Это не про «битый файл», если пункт [1] выше OK: проверяется допустимость отзывов относительно выпуска.\n")
	}
	if len(warnings) > 0 {
		b.WriteString("\n")
		b.WriteString("[3] Статус документов (информация, поле warnings)\n")
		fmt.Fprintf(&b, "    Записей: %d — не ошибка проверки журнала.\n", len(warnings))
	}
	return strings.TrimRight(b.String(), "\n")
}

func validationSummaryRU(errs, warnings []ValidationError) (summary string, errCounts, warnCounts map[string]int) {
	errCounts = countByCode(errs)
	warnCounts = countByCode(warnings)
	if len(errs) == 0 && len(warnings) == 0 {
		summary = strings.Join([]string{
			"ИТОГ ПРОВЕРКИ: успешно.",
			"",
			integrityOverviewLines(nil, nil),
			"",
			"Что это значит: по каждому узлу подпись ECDSA совпадает с ключом страны; узловой хэш (node_hash) согласован с транзакцией и родителями;",
			"правила revoke/issue соблюдены (проверка содержимого документа делается отдельной кнопкой «Проверить», не через журнал).",
			"",
			"Сводка кодов: ошибок нет.",
		}, "\n")
		return summary, errCounts, warnCounts
	}
	if len(errs) == 0 && len(warnings) > 0 {
		var lines []string
		lines = append(lines, "ИТОГ ПРОВЕРКИ: успешно — цепочка и правила документов в порядке; ниже только сведения о статусе (не ошибки).")
		lines = append(lines, "")
		lines = append(lines, integrityOverviewLines(nil, warnings))
		lines = append(lines, "")
		lines = append(lines, "Сведения (поле warnings):")
		seen := map[string]bool{}
		for _, code := range validationWarningCodeOrder {
			n := warnCounts[code]
			if n == 0 {
				continue
			}
			seen[code] = true
			desc := validationCodeRU[code]
			if desc == "" {
				desc = "см. поле message в warnings"
			}
			lines = append(lines, fmt.Sprintf("  • %s — %d узл.: %s", code, n, desc))
		}
		for code, n := range warnCounts {
			if seen[code] || n == 0 {
				continue
			}
			lines = append(lines, fmt.Sprintf("  • %s — %d узл.", code, n))
		}
		lines = append(lines, "")
		lines = append(lines, "Сводка: ошибок нет; сведения по кодам: "+formatErrorCounts(warnCounts))
		summary = strings.Join(lines, "\n")
		return summary, errCounts, warnCounts
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("ИТОГ ПРОВЕРКИ: не пройдена — всего замечаний: %d.", len(errs)))
	lines = append(lines, "")
	lines = append(lines, integrityOverviewLines(errs, warnings))
	lines = append(lines, "")
	lines = append(lines, "Что не так (по типам):")
	seen := map[string]bool{}
	for _, code := range validationCodeOrder {
		n := errCounts[code]
		if n == 0 {
			continue
		}
		seen[code] = true
		desc := validationCodeRU[code]
		if desc == "" {
			desc = "см. поле message в errors"
		}
		lines = append(lines, fmt.Sprintf("  • %s — %d узл.: %s", code, n, desc))
	}
	for code, n := range errCounts {
		if seen[code] || n == 0 {
			continue
		}
		lines = append(lines, fmt.Sprintf("  • %s — %d узл.", code, n))
	}
	lines = append(lines, "")
	lines = append(lines, "Что делать: откройте ответ /api/validate (поле errors) для пар tx_id + code; устраните причину или начните цепочку заново с согласованными ключами.")
	if len(warnings) > 0 {
		lines = append(lines, "")
		lines = append(lines, "Дополнительно см. поле warnings (информация о статусе документов, не причина отказа проверки).")
	}
	lines = append(lines, "")
	lines = append(lines, "Сводка кодов: "+formatErrorCounts(errCounts))
	summary = strings.Join(lines, "\n")
	return summary, errCounts, warnCounts
}

func formatErrorCounts(m map[string]int) string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s×%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

func (s *Store) findLatestRevokeLocked(docID string) *DAGNode {
	var best *DAGNode
	for _, n := range s.nodes {
		if n.Transaction.DocumentID != docID || n.Transaction.Action != model.ActionRevoke {
			continue
		}
		if best == nil || n.Transaction.Timestamp >= best.Transaction.Timestamp {
			best = n
		}
	}
	return best
}

func (s *Store) ValidateAll() ValidationResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var errs, warns []ValidationError
	for _, n := range s.nodes {
		if !s.keys.VerifyTransaction(&n.Transaction) {
			errs = append(errs, ValidationError{
				NodeID: n.Transaction.TxID, Code: "bad_signature",
				Message: "ECDSA: подпись не проходит для IssuerCountry (подмена эмитента или повреждение данных)",
			})
		}
		ph := map[string]string{}
		for _, pid := range n.ParentIDs {
			pn, ok := s.nodes[pid]
			if !ok {
				errs = append(errs, ValidationError{NodeID: n.Transaction.TxID, Code: "missing_parent",
					Message: "родитель " + pid + " отсутствует"})
				continue
			}
			ph[pid] = pn.NodeHash
		}
		want, err := ComputeNodeHash(&n.Transaction, n.ParentIDs, ph)
		if err != nil {
			errs = append(errs, ValidationError{NodeID: n.Transaction.TxID, Code: "hash_error", Message: err.Error()})
			continue
		}
		if want != n.NodeHash {
			errs = append(errs, ValidationError{NodeID: n.Transaction.TxID, Code: "node_hash_mismatch",
				Message: "NodeHash не согласован с данными (возможна подделка DocumentHash/метаданных или Merkle родителей)"})
		}
	}
	// Правило revoke
	for _, n := range s.nodes {
		if n.Transaction.Action != model.ActionRevoke {
			continue
		}
		issuer, ok := s.findIssuerLocked(n.Transaction.DocumentID)
		if !ok {
			errs = append(errs, ValidationError{NodeID: n.Transaction.TxID, Code: "revoke_no_issue",
				Message: "отзыв без предшествующего issue"})
			continue
		}
		if n.Transaction.IssuerCountry != issuer {
			errs = append(errs, ValidationError{NodeID: n.Transaction.TxID, Code: "illegal_revoke",
				Message: fmt.Sprintf("отзыв не от эмитента выпуска (эмитент: %s)", issuer)})
		}
	}
	// Отзыв после выпуска (revoke не удаляет узел issue — фиксируется новая транзакция; документ считается недействительным).
	uniqDocs := map[string]struct{}{}
	for _, n := range s.nodes {
		if id := n.Transaction.DocumentID; id != "" {
			uniqDocs[id] = struct{}{}
		}
	}
	for did := range uniqDocs {
		issueN := s.findIssueNodeLocked(did)
		revN := s.findLatestRevokeLocked(did)
		if issueN == nil || revN == nil {
			continue
		}
		if revN.Transaction.Timestamp >= issueN.Transaction.Timestamp {
			warns = append(warns, ValidationError{
				NodeID: revN.Transaction.TxID,
				Code:   "document_revoked",
				Message: fmt.Sprintf(
					"документ %s отозван после выпуска — недействителен как действующий (issue=%s, revoke=%s)",
					did, issueN.Transaction.TxID, revN.Transaction.TxID),
			})
		}
	}
	summaryRU, errCounts, warnCounts := validationSummaryRU(errs, warns)
	return ValidationResult{
		Ok:            len(errs) == 0,
		Errors:        errs,
		Warnings:      warns,
		SummaryRU:     summaryRU,
		ErrorCounts:   errCounts,
		WarningCounts: warnCounts,
	}
}

// OpLogInfo — запись в общий журнал (используется API /api/validate и др.).
func (s *Store) OpLogInfo(message string) {
	s.log("info", message)
}

func (s *Store) findIssuerLocked(docID string) (string, bool) {
	var best *DAGNode
	for _, n := range s.nodes {
		if n.Transaction.DocumentID != docID || n.Transaction.Action != model.ActionIssue {
			continue
		}
		if best == nil || n.Transaction.Timestamp < best.Transaction.Timestamp {
			nn := *n
			best = &nn
		}
	}
	if best == nil {
		return "", false
	}
	return best.Transaction.IssuerCountry, true
}

func (s *Store) findIssueNodeLocked(docID string) *DAGNode {
	var best *DAGNode
	for _, n := range s.nodes {
		if n.Transaction.DocumentID != docID || n.Transaction.Action != model.ActionIssue {
			continue
		}
		if best == nil || n.Transaction.Timestamp < best.Transaction.Timestamp {
			best = n
		}
	}
	return best
}

// VerifyLookupResult — ответ POST /api/verify (поиск по журналу без записи узла).
type VerifyLookupResult struct {
	OK           bool   `json:"ok"`
	Status       string `json:"status"`
	SummaryRU    string `json:"summary_ru"`
	LatestTxID   string `json:"latest_tx_id,omitempty"`
	LatestAction string `json:"latest_action,omitempty"`
	IssueTxID    string `json:"issue_tx_id,omitempty"`
}

// VerifyLookup находит последнюю по времени транзакцию issue/revoke для document_id и сверяет хэши с выпуском при необходимости.
func (s *Store) VerifyLookup(docID, documentHash, metadataHash string) VerifyLookupResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if docID == "" {
		return VerifyLookupResult{OK: false, Status: "bad_request", SummaryRU: "Укажите document_id."}
	}
	latest := s.latestChainTxForDocLocked(docID)
	if latest == nil {
		return VerifyLookupResult{
			OK: false, Status: "not_found",
			SummaryRU: fmt.Sprintf("В журнале цепочки нет узлов issue/revoke для документа %s.", docID),
		}
	}
	switch latest.Transaction.Action {
	case model.ActionRevoke:
		return VerifyLookupResult{
			OK: false, Status: "revoked",
			SummaryRU: fmt.Sprintf(
				"Последняя запись по документу в журнале — отзыв (узел %s). Документ недействителен.",
				latest.Transaction.TxID,
			),
			LatestTxID:   latest.Transaction.TxID,
			LatestAction: model.ActionRevoke,
		}
	case model.ActionIssue:
		tx := latest.Transaction
		docMatch := tx.DocumentHash == documentHash
		metaMatch := tx.MetadataHash == metadataHash
		if docMatch && metaMatch {
			return VerifyLookupResult{
				OK: true, Status: "valid",
				SummaryRU: fmt.Sprintf(
					"Хэши совпадают с выпуском (%s). Последняя операция в журнале — выпуск.",
					tx.TxID,
				),
				LatestTxID:   tx.TxID,
				LatestAction: model.ActionIssue,
				IssueTxID:    tx.TxID,
			}
		}
		return VerifyLookupResult{
			OK: false, Status: "hash_mismatch",
			SummaryRU: "Хэш содержимого и/или метаданных не совпадает с узлом выпуска в журнале цепочки.",
			LatestTxID:   tx.TxID,
			LatestAction: model.ActionIssue,
			IssueTxID:    tx.TxID,
		}
	default:
		return VerifyLookupResult{OK: false, Status: "internal", SummaryRU: "Неизвестное действие узла в журнале."}
	}
}

func (s *Store) latestChainTxForDocLocked(docID string) *DAGNode {
	var best *DAGNode
	for _, n := range s.nodes {
		if n.Transaction.DocumentID != docID {
			continue
		}
		a := n.Transaction.Action
		if a != model.ActionIssue && a != model.ActionRevoke {
			continue
		}
		if best == nil {
			best = n
			continue
		}
		if laterChainNode(n, best) {
			best = n
		}
	}
	return best
}

func laterChainNode(a, b *DAGNode) bool {
	if a.Transaction.Timestamp != b.Transaction.Timestamp {
		return a.Transaction.Timestamp > b.Transaction.Timestamp
	}
	if a.Transaction.Action != b.Transaction.Action {
		return a.Transaction.Action == model.ActionRevoke && b.Transaction.Action == model.ActionIssue
	}
	return a.Transaction.TxID > b.Transaction.TxID
}

// --- Атаки: симуляция в памяти с откатом — журнал на диске не остаётся в «взломанном» виде ---

// AttackForgeryDocHash подменяет DocumentHash у issue только для проверки, затем восстанавливает узел и сохраняет исходное состояние.
func (s *Store) AttackForgeryDocHash(txID, fakeHash string) ([]string, ValidationResult) {
	var steps []string
	s.mu.Lock()
	n, ok := s.nodes[txID]
	if !ok {
		s.mu.Unlock()
		steps = append(steps, "узел не найден")
		return steps, ValidationResult{
			Ok:        false,
			SummaryRU: "ИТОГ СИМУЛЯЦИИ: не выполнена — узел с таким tx_id отсутствует.",
		}
	}
	if n.Transaction.Action != model.ActionIssue {
		s.mu.Unlock()
		steps = append(steps, "атака рассчитана на транзакцию issue")
		return steps, ValidationResult{
			Ok:        false,
			SummaryRU: "ИТОГ СИМУЛЯЦИИ: не выполнена — выбранный узел не является выпуском (issue).",
		}
	}
	backup := CloneDAGNode(n)
	steps = append(steps, "[Симуляция] Снимок узла сохранён; до конца сценария на диск записывается только восстановленное состояние.")
	steps = append(steps, "Исходная выдача (issue) найдена.")
	old := n.Transaction.DocumentHash
	n.Transaction.DocumentHash = fakeHash
	steps = append(steps, fmt.Sprintf("В памяти подменён DocumentHash: %s → %s", truncHex(old), truncHex(fakeHash)))
	steps = append(steps, "NodeHash в узле не пересчитан (модель «тихого» взлома журнала).")
	s.mu.Unlock()

	res := s.ValidateAll()

	s.mu.Lock()
	if nn, still := s.nodes[txID]; still {
		*nn = backup
	}
	s.mu.Unlock()
	if err := s.persistGraph(); err != nil {
		log.Printf("persist graph: %v", err)
	}
	steps = append(steps, "")
	steps = append(steps, "Проверка запущена на изменённом (несохранённом) состоянии — ниже итог именно для модели атаки.")
	steps = append(steps, fmt.Sprintf("Результат проверки при атаке: ok=%v (ожидаются node_hash_mismatch и др.)", res.Ok))
	steps = append(steps, "Исходный узел восстановлен и записан в nodes.json — рабочая цепочка не повреждена.")
	s.log("attack", "Forgery simulation (rolled back) "+txID)
	return steps, res
}

func truncHex(s string) string {
	const n = 16
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// AttackIssuerSubstitution меняет IssuerCountry в памяти для демонстрации bad_signature, затем откат и сохранение.
func (s *Store) AttackIssuerSubstitution(txID, newCountry string) ([]string, ValidationResult) {
	var steps []string
	s.mu.Lock()
	n, ok := s.nodes[txID]
	if !ok {
		s.mu.Unlock()
		steps = append(steps, "узел не найден")
		return steps, ValidationResult{
			Ok:        false,
			SummaryRU: "ИТОГ СИМУЛЯЦИИ: не выполнена — узел с таким tx_id отсутствует.",
		}
	}
	backup := CloneDAGNode(n)
	steps = append(steps, "[Симуляция] Снимок узла сохранён; после проверки состояние будет восстановлено.")
	old := n.Transaction.IssuerCountry
	n.Transaction.IssuerCountry = newCountry
	steps = append(steps, fmt.Sprintf("В памяти IssuerCountry изменён: %s → %s", old, newCountry))
	steps = append(steps, "Подпись ECDSA остаётся от ключа прежней страны → проверка даст bad_signature.")
	s.mu.Unlock()

	res := s.ValidateAll()

	s.mu.Lock()
	if nn, still := s.nodes[txID]; still {
		*nn = backup
	}
	s.mu.Unlock()
	if err := s.persistGraph(); err != nil {
		log.Printf("persist graph: %v", err)
	}
	steps = append(steps, "")
	steps = append(steps, fmt.Sprintf("Результат проверки при атаке: ok=%v (ожидается bad_signature на этом узле)", res.Ok))
	steps = append(steps, "Исходный узел восстановлен на диске — цепочка не повреждена.")
	s.log("attack", "Issuer substitution simulation (rolled back) "+txID)
	return steps, res
}

// IllegalRevokeDemo — попытка записать revoke от чужой страны; транзакция не добавляется, цепочка не меняется.
func (s *Store) IllegalRevokeDemo(docID, wrongCountry string, parentIDs []string) ([]string, error) {
	tx := &model.DocumentTransaction{
		TxID:            randomTxID(),
		DocumentID:      docID,
		DocumentType:    model.DocDiploma,
		DocumentHash:    "",
		IssuerCountry:   wrongCountry,
		IssuerAuthority: "Demo authority",
		ReceiverCountry: model.CountryBY,
		Action:          model.ActionRevoke,
		Timestamp:       time.Now().Unix(),
		MetadataHash:    crypto.SHA256Hex([]byte("meta")),
	}
	var steps []string
	steps = append(steps, "[Симуляция] Запись в журнал только если транзакция принята — здесь ожидается отказ API.")
	steps = append(steps, fmt.Sprintf("Попытка revoke для doc_id=%s от страны %s", docID, wrongCountry))
	_, err := s.AddRevoke(tx, parentIDs)
	if err != nil {
		steps = append(steps, "Результат: транзакция отклонена — "+err.Error())
		steps = append(steps, "[Симуляция] Журнал узлов не изменён — недопустимый revoke не записан.")
		s.log("attack", "Illegal revoke rejected: "+err.Error())
		return steps, err
	}
	steps = append(steps, "неожиданно принято")
	return steps, nil
}

func (s *Store) GossipSnapshot() (events []consensus.GossipEvent, votes []consensus.VirtualVoteStep) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	events = append([]consensus.GossipEvent(nil), s.gossip.Events...)
	votes = append([]consensus.VirtualVoteStep(nil), s.gossip.Votes...)
	return events, votes
}
