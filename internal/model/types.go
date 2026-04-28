package model

// CIS-ориентированные коды стран (аналог EBSI для СНГ).
const (
	CountryBY = "BY" // Беларусь
	CountryRU = "RU" // Россия
	CountryKZ = "KZ" // Казахстан
	CountryAM = "AM" // Армения
	CountryAZ = "AZ" // Азербайджан
)

// Действия над документом.
const (
	ActionIssue  = "issue"
	ActionVerify = "verify" // не используется в журнале; оставлено для совместимости со старыми JSON
	ActionRevoke = "revoke"
)

// Типы документов.
const (
	DocDiploma     = "diploma"
	DocTaxRecord   = "tax_record"
	DocCertificate = "certificate"
)

// DocumentTransaction — одна операция над одним документом (узел DAG — обёртка в dag.DAGNode).
type DocumentTransaction struct {
	TxID            string `json:"tx_id"`
	DocumentID      string `json:"document_id"`
	DocumentType    string `json:"document_type"`
	DocumentHash    string `json:"document_hash"`
	IssuerCountry   string `json:"issuer_country"`
	IssuerAuthority string `json:"issuer_authority"`
	ReceiverCountry string `json:"receiver_country"`
	Action          string `json:"action"`
	Timestamp       int64  `json:"timestamp"`
	IssuerSignature string `json:"issuer_signature"`
	MetadataHash    string `json:"metadata_hash"`
}
