package api

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	chaincrypto "BBSI/internal/crypto"
	"BBSI/internal/dag"
	"BBSI/internal/db"
	"BBSI/internal/model"
)

type Server struct {
	Store     *dag.Store
	keys      *chaincrypto.AuthorityKeys
	DB        *db.Database
	attackLog func([]string)

	mu        sync.Mutex
	attackBuf []string
}

func NewServer(store *dag.Store, keys *chaincrypto.AuthorityKeys, database *db.Database) *Server {
	s := &Server{Store: store, keys: keys, DB: database}
	if database != nil {
		var af db.AttackLogsFile
		if err := database.ReadJSON(db.FileAttackLogs, &af); err == nil {
			s.mu.Lock()
			s.attackBuf = append([]string(nil), af.Lines...)
			s.mu.Unlock()
		}
	}
	store.SetLogHook(func(e dag.OperationLogEntry) { _ = e })
	return s
}

func (s *Server) persistAttackLogs() {
	if s.DB == nil {
		return
	}
	s.mu.Lock()
	lines := append([]string(nil), s.attackBuf...)
	s.mu.Unlock()
	_ = s.DB.WriteJSON(db.FileAttackLogs, db.AttackLogsFile{Lines: lines})
}

func (s *Server) logAttackStep(msg string) {
	s.mu.Lock()
	s.attackBuf = append(s.attackBuf, msg)
	if len(s.attackBuf) > 500 {
		s.attackBuf = s.attackBuf[len(s.attackBuf)-400:]
	}
	s.mu.Unlock()
	if s.attackLog != nil {
		s.attackLog([]string{msg})
	}
	s.persistAttackLogs()
}

func (s *Server) clearAttackLog() {
	s.mu.Lock()
	s.attackBuf = nil
	s.mu.Unlock()
	s.persistAttackLogs()
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/documents", s.handleDocumentsList)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/countries", s.handleCountries)
	mux.HandleFunc("/api/dag", s.handleDAG)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/db/reset", s.handleResetDB)
	mux.HandleFunc("/api/validate", s.handleValidate)
	mux.HandleFunc("/api/gossip", s.handleGossip)
	mux.HandleFunc("/api/merkle/proof/", s.handleMerkleProof)
	mux.HandleFunc("/api/tx/issue", func(w http.ResponseWriter, r *http.Request) {
		s.handleIssue(w, r)
	})
	mux.HandleFunc("/api/verify", s.handleVerifyLookup)
	mux.HandleFunc("/api/tx/revoke", func(w http.ResponseWriter, r *http.Request) {
		s.handleRevoke(w, r)
	})
	mux.HandleFunc("/api/attacks/forgery", func(w http.ResponseWriter, r *http.Request) {
		s.handleAttackForgery(w, r)
	})
	mux.HandleFunc("/api/attacks/issuer", func(w http.ResponseWriter, r *http.Request) {
		s.handleAttackIssuer(w, r)
	})
	mux.HandleFunc("/api/attacks/illegal-revoke", func(w http.ResponseWriter, r *http.Request) {
		s.handleAttackIllegalRevoke(w, r)
	})
	dir := filepath.Join(".", "web")
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
			return
		}
		http.FileServer(http.Dir(dir)).ServeHTTP(w, r)
	}))
	return s.withCORS(mux)
}

func (s *Server) withCORS(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (s *Server) json(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if s.DB == nil {
		s.json(w, http.StatusOK, map[string]interface{}{
			"types": []interface{}{}, "emitters": []interface{}{}, "authorities": []interface{}{},
		})
		return
	}
	var tf db.TypesFile
	var ef db.EmittersFile
	var af db.AuthoritiesFile
	_ = s.DB.ReadJSON(db.FileTypes, &tf)
	_ = s.DB.ReadJSON(db.FileEmitents, &ef)
	_ = s.DB.ReadJSON(db.FileAuthorities, &af)
	s.json(w, http.StatusOK, map[string]interface{}{
		"types":       tf.Types,
		"emitters":    ef.Emitters,
		"authorities": af.Authorities,
	})
}

func (s *Server) handleDocumentsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if s.DB == nil {
		s.json(w, http.StatusOK, map[string]interface{}{"documents": []interface{}{}})
		return
	}
	var df db.DocumentsFile
	_ = s.DB.ReadJSON(db.FileDocuments, &df)
	s.json(w, http.StatusOK, map[string]interface{}{"documents": df.Documents})
}

func (s *Server) handleCountries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	list := []string{model.CountryBY, model.CountryRU, model.CountryKZ, model.CountryAM, model.CountryAZ}
	info := []map[string]string{}
	for _, c := range list {
		pem, _ := s.keys.PublicKeyPEM(c)
		info = append(info, map[string]string{"code": c, "pem_preview": shorten(pem, 80)})
	}
	s.json(w, http.StatusOK, map[string]interface{}{"cis": info})
}

func shorten(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

type issueReq struct {
	DocumentID      string          `json:"document_id"`
	DocumentType    string          `json:"document_type"`
	DocumentHash    string          `json:"document_hash"`
	DocumentPayload json.RawMessage `json:"document_payload,omitempty"`
	IssuerCountry   string          `json:"issuer_country"`
	IssuerAuthority string          `json:"issuer_authority"`
	ReceiverCountry string          `json:"receiver_country"`
	MetadataHash    string          `json:"metadata_hash"`
	MetadataPayload json.RawMessage `json:"metadata_payload,omitempty"`
	ParentIDs       []string        `json:"parent_ids"`
}

func applyDocumentAndMetaHashes(
	documentHash string,
	documentPayload json.RawMessage,
	metadataHash string,
	metadataPayload json.RawMessage,
) (docHash string, metaHash string, errMsg string) {
	hasDocPayload := len(bytes.TrimSpace(documentPayload)) > 0
	hasMetaPayload := len(bytes.TrimSpace(metadataPayload)) > 0

	switch {
	case strings.TrimSpace(documentHash) != "" && hasDocPayload:
		want, err := chaincrypto.HashCanonicalJSON(documentPayload)
		if err != nil {
			return "", "", "document_payload: " + err.Error()
		}
		if want != strings.TrimSpace(documentHash) {
			return "", "", "document_hash не совпадает с хэшем от document_payload"
		}
		docHash = strings.TrimSpace(documentHash)
	case strings.TrimSpace(documentHash) != "":
		docHash = strings.TrimSpace(documentHash)
	case hasDocPayload:
		h, err := chaincrypto.HashCanonicalJSON(documentPayload)
		if err != nil {
			return "", "", "document_payload: " + err.Error()
		}
		docHash = h
	default:
		return "", "", "нужен document_hash или непустой document_payload (JSON)"
	}

	switch {
	case strings.TrimSpace(metadataHash) != "" && hasMetaPayload:
		want, err := chaincrypto.HashCanonicalJSON(metadataPayload)
		if err != nil {
			return docHash, "", "metadata_payload: " + err.Error()
		}
		if want != strings.TrimSpace(metadataHash) {
			return docHash, "", "metadata_hash не совпадает с хэшем от metadata_payload"
		}
		metaHash = strings.TrimSpace(metadataHash)
	case strings.TrimSpace(metadataHash) != "":
		metaHash = strings.TrimSpace(metadataHash)
	case hasMetaPayload:
		h, err := chaincrypto.HashCanonicalJSON(metadataPayload)
		if err != nil {
			return docHash, "", "metadata_payload: " + err.Error()
		}
		metaHash = h
	default:
		metaHash = ""
	}
	return docHash, metaHash, ""
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var req issueReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.json(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	dh, mh, errMsg := applyDocumentAndMetaHashes(req.DocumentHash, req.DocumentPayload, req.MetadataHash, req.MetadataPayload)
	if errMsg != "" {
		s.json(w, http.StatusBadRequest, map[string]string{"error": errMsg})
		return
	}
	tx := &model.DocumentTransaction{
		DocumentID:      req.DocumentID,
		DocumentType:    req.DocumentType,
		DocumentHash:    dh,
		IssuerCountry:   req.IssuerCountry,
		IssuerAuthority: req.IssuerAuthority,
		ReceiverCountry: req.ReceiverCountry,
		Action:          model.ActionIssue,
		MetadataHash:    mh,
	}
	if tx.DocumentType == "" {
		tx.DocumentType = model.DocDiploma
	}
	node, err := s.Store.AddIssue(tx, req.ParentIDs)
	if err != nil {
		s.json(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	_ = db.UpsertDocument(s.DB, db.StoredDocument{
		DocumentID:      req.DocumentID,
		DocumentType:    tx.DocumentType,
		DocumentPayload: req.DocumentPayload,
		MetadataPayload: req.MetadataPayload,
		DocumentHash:    dh,
		MetadataHash:    mh,
		LastTxID:        node.Transaction.TxID,
		LastAction:      model.ActionIssue,
	})
	s.json(w, http.StatusOK, map[string]interface{}{"node": node})
}

type verifyLookupReq struct {
	DocumentID      string          `json:"document_id"`
	DocumentHash    string          `json:"document_hash"`
	DocumentPayload json.RawMessage `json:"document_payload,omitempty"`
	MetadataHash    string          `json:"metadata_hash"`
	MetadataPayload json.RawMessage `json:"metadata_payload,omitempty"`
}

func (s *Server) handleVerifyLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if err := s.Store.ReloadChainFromDisk(); err != nil {
		s.json(w, http.StatusInternalServerError, map[string]string{"error": "nodes.json: " + err.Error()})
		return
	}
	var req verifyLookupReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.json(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	dh, mh, errMsg := applyDocumentAndMetaHashes(req.DocumentHash, req.DocumentPayload, req.MetadataHash, req.MetadataPayload)
	if errMsg != "" {
		s.json(w, http.StatusBadRequest, map[string]string{"error": errMsg})
		return
	}
	res := s.Store.VerifyLookup(req.DocumentID, dh, mh)
	s.json(w, http.StatusOK, res)
}

type revokeReq struct {
	DocumentID    string   `json:"document_id"`
	IssuerCountry string   `json:"issuer_country"`
	ParentIDs     []string `json:"parent_ids"`
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var req revokeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.json(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	tx := &model.DocumentTransaction{
		DocumentID:      req.DocumentID,
		DocumentType:    model.DocDiploma,
		IssuerCountry:   req.IssuerCountry,
		IssuerAuthority: "Revocation",
		ReceiverCountry: model.CountryBY,
		Action:          model.ActionRevoke,
		MetadataHash:    chaincrypto.SHA256Hex([]byte("revoke")),
	}
	node, err := s.Store.AddRevoke(tx, req.ParentIDs)
	if err != nil {
		s.json(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := db.UpsertDocumentLastAction(s.DB, req.DocumentID, node.Transaction.TxID, model.ActionRevoke); err != nil {
		log.Printf("BBSI: revoke — обновление реестра документов: %v", err)
	}
	s.json(w, http.StatusOK, map[string]interface{}{"node": node})
}

func (s *Server) handleDAG(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"nodes": s.Store.NodesSnapshot()})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"entries": s.Store.OperationLogSnapshot()})
}

func (s *Server) handleAttackLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodDelete {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodDelete {
		s.clearAttackLog()
		s.json(w, http.StatusOK, map[string]string{"ok": "cleared"})
		return
	}
	s.mu.Lock()
	lines := append([]string(nil), s.attackBuf...)
	s.mu.Unlock()
	s.json(w, http.StatusOK, map[string]interface{}{"lines": lines})
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if err := s.Store.ReloadChainFromDisk(); err != nil {
		s.json(w, http.StatusInternalServerError, map[string]string{"error": "nodes.json: " + err.Error()})
		return
	}
	res := s.Store.ValidateAll()
	s.Store.OpLogInfo(res.SummaryRU)
	s.json(w, http.StatusOK, res)
}

func (s *Server) handleResetDB(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if s.DB == nil {
		s.json(w, http.StatusInternalServerError, map[string]string{"error": "нет файловой БД"})
		return
	}
	keys, err := chaincrypto.RegenerateAuthorityKeys(s.DB.Dir)
	if err != nil {
		s.json(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := s.Store.ResetChainAndLogs(keys); err != nil {
		s.json(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := s.DB.WriteJSON(db.FileDocuments, db.DocumentsFile{Documents: []db.StoredDocument{}}); err != nil {
		s.json(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.clearAttackLog()
	s.keys = keys
	s.json(w, http.StatusOK, map[string]interface{}{
		"ok":      true,
		"message": "Цепочка, документы и логи очищены; сгенерированы новые ключи эмитентов. Справочники типов и стран сохранены.",
	})
}

func (s *Server) handleGossip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	ev, vv := s.Store.GossipSnapshot()
	s.json(w, http.StatusOK, map[string]interface{}{
		"events": ev,
		"votes":  vv,
	})
}

func (s *Server) handleMerkleProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	txID := strings.TrimPrefix(r.URL.Path, "/api/merkle/proof/")
	if txID == "" {
		http.Error(w, "tx id", http.StatusBadRequest)
		return
	}
	nodes := s.Store.NodesSnapshot()
	var ids []string
	for _, n := range nodes {
		ids = append(ids, n.Transaction.TxID)
	}
	sort.Strings(ids)
	var leaves []string
	for _, id := range ids {
		for _, n := range nodes {
			if n.Transaction.TxID == id {
				b, _ := json.Marshal(n.Transaction)
				leaves = append(leaves, chaincrypto.SHA256Hex(b))
				break
			}
		}
	}
	root := chaincrypto.MerkleRoot(leaves)
	_ = root
	// упрощённое доказательство: индекс и соседние хэши
	idx := -1
	for i, id := range ids {
		if id == txID {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.json(w, http.StatusNotFound, map[string]string{"error": "tx not in merkle set"})
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{
		"merkle_root": root,
		"leaf_index":  idx,
		"tx_id":       txID,
		"note":        "листья — SHA-256 от JSON транзакции (демо Merkle по всем узлам графа)",
	})
}

type attackTwo struct {
	TxID     string `json:"tx_id"`
	FakeHash string `json:"fake_hash"`
}

func (s *Server) handleAttackForgery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var body attackTwo
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.TxID == "" {
		s.json(w, http.StatusBadRequest, map[string]string{"error": "tx_id обязателен"})
		return
	}
	if body.FakeHash == "" {
		body.FakeHash = chaincrypto.SHA256Hex([]byte("forged-pdf-content"))
	}
	s.clearAttackLog()
	steps, res := s.Store.AttackForgeryDocHash(body.TxID, body.FakeHash)
	for _, st := range steps {
		s.logAttackStep(st)
	}
	s.logAttackStep("Валидация при симуляции: ok=" + boolStr(res.Ok))
	for _, e := range res.Errors {
		s.logAttackStep(e.NodeID + " [" + e.Code + "] " + e.Message)
	}
	s.json(w, http.StatusOK, map[string]interface{}{"steps": steps, "validation": res})
}

type attackIssuer struct {
	TxID       string `json:"tx_id"`
	NewCountry string `json:"new_country"`
}

func (s *Server) handleAttackIssuer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var body attackIssuer
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.TxID == "" || body.NewCountry == "" {
		s.json(w, http.StatusBadRequest, map[string]string{"error": "tx_id и new_country обязательны"})
		return
	}
	s.clearAttackLog()
	steps, res := s.Store.AttackIssuerSubstitution(body.TxID, body.NewCountry)
	for _, st := range steps {
		s.logAttackStep(st)
	}
	s.logAttackStep("Валидация при симуляции: ok=" + boolStr(res.Ok))
	for _, e := range res.Errors {
		s.logAttackStep(e.NodeID + " [" + e.Code + "] " + e.Message)
	}
	s.json(w, http.StatusOK, map[string]interface{}{"steps": steps, "validation": res})
}

type attackRev struct {
	DocumentID   string   `json:"document_id"`
	WrongCountry string   `json:"wrong_country"`
	ParentIDs    []string `json:"parent_ids"`
}

func (s *Server) handleAttackIllegalRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var body attackRev
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.DocumentID == "" || body.WrongCountry == "" {
		s.json(w, http.StatusBadRequest, map[string]string{"error": "document_id и wrong_country обязательны"})
		return
	}
	s.clearAttackLog()
	s.logAttackStep("[Симуляция] Попытка записать revoke от стороны, не являющейся эмитентом выпуска…")
	steps, err := s.Store.IllegalRevokeDemo(body.DocumentID, body.WrongCountry, body.ParentIDs)
	for _, st := range steps {
		s.logAttackStep(st)
	}
	val := s.Store.ValidateAll()
	s.logAttackStep("Текущее состояние цепочки после отказа (полная проверка): ok=" + boolStr(val.Ok))
	status := http.StatusOK
	if err != nil {
		status = http.StatusBadRequest
	}
	s.json(w, status, map[string]interface{}{"steps": steps, "error": errString(err), "validation": val})
}

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
