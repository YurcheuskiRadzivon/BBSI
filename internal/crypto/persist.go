package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"BBSI/internal/model"
)

const authorityKeysFileName = "authority_keys.json"

type authorityKeysFile struct {
	Version        int               `json:"version"`
	PrivateKeysPEM map[string]string `json:"private_keys_pem"`
}

func expectedCountries() []string {
	return []string{
		model.CountryBY, model.CountryRU, model.CountryKZ,
		model.CountryAM, model.CountryAZ,
	}
}

// LoadOrCreateAuthorityKeys загружает ECDSA-ключи стран из dbDir/authority_keys.json
// или создаёт новые и сохраняет их. Без этого файла при каждом перезапуске процесса
// генерировались бы новые ключи и все подписи в nodes.json становились недействительными (bad_signature).
func LoadOrCreateAuthorityKeys(dbDir string) (*AuthorityKeys, error) {
	path := filepath.Join(dbDir, authorityKeysFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		k := NewAuthorityKeys()
		if err := k.saveToFile(path); err != nil {
			return nil, fmt.Errorf("сохранение %s: %w", path, err)
		}
		return k, nil
	}
	if len(data) == 0 {
		k := NewAuthorityKeys()
		if err := k.saveToFile(path); err != nil {
			return nil, fmt.Errorf("сохранение пустого %s: %w", path, err)
		}
		return k, nil
	}
	var f authorityKeysFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: некорректный JSON: %w", path, err)
	}
	k, err := authorityKeysFromPEM(f.PrivateKeysPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

// RegenerateAuthorityKeys удаляет файл ключей и создаёт новые ключи для всех стран (полный сброс подписей).
func RegenerateAuthorityKeys(dbDir string) (*AuthorityKeys, error) {
	path := filepath.Join(dbDir, authorityKeysFileName)
	_ = os.Remove(path)
	k := NewAuthorityKeys()
	if err := k.saveToFile(path); err != nil {
		return nil, err
	}
	return k, nil
}

func authorityKeysFromPEM(m map[string]string) (*AuthorityKeys, error) {
	if len(m) == 0 {
		return nil, errors.New("private_keys_pem пусто")
	}
	for _, c := range expectedCountries() {
		if _, ok := m[c]; !ok {
			return nil, fmt.Errorf("нет ключа для страны %s", c)
		}
	}
	out := &AuthorityKeys{
		private: make(map[string]*ecdsa.PrivateKey),
		public:  make(map[string]*ecdsa.PublicKey),
	}
	for country, pemStr := range m {
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			return nil, fmt.Errorf("страна %s: неверный PEM", country)
		}
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("страна %s: разбор ключа: %w", country, err)
		}
		out.private[country] = priv
		out.public[country] = &priv.PublicKey
	}
	return out, nil
}

func (k *AuthorityKeys) saveToFile(path string) error {
	k.mu.RLock()
	defer k.mu.RUnlock()
	m := make(map[string]string, len(k.private))
	for country, priv := range k.private {
		der, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return err
		}
		block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
		m[country] = string(pem.EncodeToMemory(block))
	}
	f := authorityKeysFile{Version: 1, PrivateKeysPEM: m}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
