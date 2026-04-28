package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

func SHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func SHA256Pair(a, b string) string {
	// Детерминированный порядок для Merkle уровня.
	if a > b {
		a, b = b, a
	}
	return SHA256Hex([]byte(a + b))
}

// MerkleRoot вычисляет корень бинарного дерева Меркла по листьям (hex-строки хэшей).
func MerkleRoot(leaves []string) string {
	if len(leaves) == 0 {
		return SHA256Hex([]byte("empty"))
	}
	layer := append([]string(nil), leaves...)
	sort.Strings(layer)
	for len(layer) > 1 {
		var next []string
		for i := 0; i < len(layer); i += 2 {
			if i+1 < len(layer) {
				next = append(next, SHA256Pair(layer[i], layer[i+1]))
			} else {
				next = append(next, SHA256Pair(layer[i], layer[i]))
			}
		}
		layer = next
	}
	return layer[0]
}
