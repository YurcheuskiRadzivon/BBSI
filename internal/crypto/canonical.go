package crypto

import (
	"encoding/json"
	"sort"

	"BBSI/internal/model"
)

// CanonicalJSONWithoutSig — детерминированная сериализация полей для подписи и NodeHash.
func CanonicalJSONWithoutSig(tx *model.DocumentTransaction) ([]byte, error) {
	m := map[string]interface{}{
		"action":           tx.Action,
		"document_hash":    tx.DocumentHash,
		"document_id":      tx.DocumentID,
		"document_type":    tx.DocumentType,
		"issuer_authority": tx.IssuerAuthority,
		"issuer_country":   tx.IssuerCountry,
		"metadata_hash":    tx.MetadataHash,
		"receiver_country": tx.ReceiverCountry,
		"timestamp":        tx.Timestamp,
		"tx_id":            tx.TxID,
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]interface{}, len(m))
	for _, k := range keys {
		ordered[k] = m[k]
	}
	return json.Marshal(ordered)
}

func ContentHash(tx *model.DocumentTransaction) (string, error) {
	b, err := CanonicalJSONWithoutSig(tx)
	if err != nil {
		return "", err
	}
	return SHA256Hex(b), nil
}
