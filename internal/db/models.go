package db

import "encoding/json"

// TypesFile — types.json
type TypesFile struct {
	Types []DocTypeEntry `json:"types"`
}

type DocTypeEntry struct {
	ID      string `json:"id"`
	LabelRU string `json:"label_ru"`
}

// EmittersFile — emitents.json
type EmittersFile struct {
	Emitters []EmitterEntry `json:"emitters"`
}

type EmitterEntry struct {
	Code   string `json:"code"`
	NameRU string `json:"name_ru"`
}

// AuthoritiesFile — authorities.json
type AuthoritiesFile struct {
	Authorities []AuthorityEntry `json:"authorities"`
}

type AuthorityEntry struct {
	ID          string `json:"id"`
	CountryCode string `json:"country_code"`
	NameRU      string `json:"name_ru"`
}

// DocumentsFile — documents.json (снимки для хэширования / справочник)
type DocumentsFile struct {
	Documents []StoredDocument `json:"documents"`
}

type StoredDocument struct {
	DocumentID      string          `json:"document_id"`
	DocumentType    string          `json:"document_type"`
	DocumentPayload json.RawMessage `json:"document_payload,omitempty"`
	MetadataPayload json.RawMessage `json:"metadata_payload,omitempty"`
	DocumentHash    string          `json:"document_hash"`
	MetadataHash    string          `json:"metadata_hash"`
	LastTxID        string          `json:"last_tx_id,omitempty"`
	LastAction      string          `json:"last_action,omitempty"`
	UpdatedAtUnix   int64           `json:"updated_at_unix"`
}

// LogsFile — logs.json
type LogsFile struct {
	Entries []LogEntryJSON `json:"entries"`
}

type LogEntryJSON struct {
	Time    int64  `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// AttackLogsFile — attack_logs.json
type AttackLogsFile struct {
	Lines []string `json:"lines"`
}
