package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"

	"BBSI/internal/model"
)

// AuthorityKeys — ключи центров выдачи по коду страны (в памяти, для прототипа).
type AuthorityKeys struct {
	mu      sync.RWMutex
	private map[string]*ecdsa.PrivateKey
	public  map[string]*ecdsa.PublicKey
}

func NewAuthorityKeys() *AuthorityKeys {
	k := &AuthorityKeys{
		private: make(map[string]*ecdsa.PrivateKey),
		public:  make(map[string]*ecdsa.PublicKey),
	}
	countries := []string{
		model.CountryBY, model.CountryRU, model.CountryKZ,
		model.CountryAM, model.CountryAZ,
	}
	for _, c := range countries {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		k.private[c] = priv
		k.public[c] = &priv.PublicKey
	}
	return k
}

func (k *AuthorityKeys) Sign(country string, hash []byte) (string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	priv, ok := k.private[country]
	if !ok {
		return "", fmt.Errorf("неизвестная страна-эмитент: %s", country)
	}
	h := sha256.Sum256(hash)
	sigASN1, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sigASN1), nil
}

// SignTransaction подписывает каноническое тело транзакции (без поля подписи).
func (k *AuthorityKeys) SignTransaction(tx *model.DocumentTransaction) error {
	body, err := CanonicalJSONWithoutSig(tx)
	if err != nil {
		return err
	}
	sig, err := k.Sign(tx.IssuerCountry, body)
	if err != nil {
		return err
	}
	tx.IssuerSignature = sig
	return nil
}

func (k *AuthorityKeys) Verify(country string, messageHash []byte, signatureHex string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	pub, ok := k.public[country]
	if !ok {
		return false
	}
	sig, err := hex.DecodeString(signatureHex)
	if err != nil || len(sig) < 8 {
		return false
	}
	h := sha256.Sum256(messageHash)
	// ASN1 или сырой concat r|s — выше подписали ASN1 через SignASN1; декодируем как ASN1
	return ecdsa.VerifyASN1(pub, h[:], sig)
}

// VerifyTransaction проверяет подпись по публичному ключу страны из поля IssuerCountry.
func (k *AuthorityKeys) VerifyTransaction(tx *model.DocumentTransaction) bool {
	body, err := CanonicalJSONWithoutSig(tx)
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(tx.IssuerSignature)
	if err != nil {
		return false
	}
	k.mu.RLock()
	pub, ok := k.public[tx.IssuerCountry]
	k.mu.RUnlock()
	if !ok {
		return false
	}
	h := sha256.Sum256(body)
	return ecdsa.VerifyASN1(pub, h[:], sig)
}

// PublicKeyPEM для отладки / UI.
func (k *AuthorityKeys) PublicKeyPEM(country string) (string, error) {
	k.mu.RLock()
	pub, ok := k.public[country]
	k.mu.RUnlock()
	if !ok {
		return "", errors.New("unknown country")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}
