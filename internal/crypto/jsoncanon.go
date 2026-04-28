package crypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
)

// canonicalizeJSON приводит map и slice к виду с сортировкой ключей в объектах (детерминированная сериализация).
func canonicalizeJSON(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]interface{}, len(x))
		for _, k := range keys {
			out[k] = canonicalizeJSON(x[k])
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(x))
		for i := range x {
			out[i] = canonicalizeJSON(x[i])
		}
		return out
	default:
		return x
	}
}

// CanonicalJSONFromPayload сериализует уже канонизированное значение без HTML-экранирования (как JSON.stringify в браузере для типичных данных).
func CanonicalJSONFromPayload(v interface{}) ([]byte, error) {
	cv := canonicalizeJSON(v)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cv); err != nil {
		return nil, err
	}
	// json.Encoder добавляет завершающий \n — убираем для совпадения с JSON.stringify без trailing newline
	b := bytes.TrimSpace(buf.Bytes())
	return b, nil
}

// HashCanonicalJSON вычисляет SHA-256(hex) от канонического JSON полезной нагрузки документа или метаданных.
func HashCanonicalJSON(raw json.RawMessage) (string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", errors.New("пустой JSON")
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}
	b, err := CanonicalJSONFromPayload(v)
	if err != nil {
		return "", err
	}
	return SHA256Hex(b), nil
}
