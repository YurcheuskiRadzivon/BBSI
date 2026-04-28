package dag

import (
	"fmt"

	"BBSI/internal/crypto"
	"BBSI/internal/model"
)

// DAGNode — узел направленного ациклического графа (одна транзакция + ссылки на родителей).
type DAGNode struct {
	Transaction model.DocumentTransaction `json:"transaction"`
	ParentIDs   []string                  `json:"parent_ids"`
	NodeHash    string                    `json:"node_hash"`
}

// CloneDAGNode — глубокая копия узла (для симуляций атак и отката).
func CloneDAGNode(n *DAGNode) DAGNode {
	if n == nil {
		return DAGNode{}
	}
	tx := n.Transaction
	pids := append([]string(nil), n.ParentIDs...)
	return DAGNode{Transaction: tx, ParentIDs: pids, NodeHash: n.NodeHash}
}

// ComputeNodeHash: Hash = SHA-256(TxID + ContentHash + MerkleRoot(родители) + timestamp) в духе спецификации.
func ComputeNodeHash(tx *model.DocumentTransaction, parentIDs []string, parentNodeHashes map[string]string) (string, error) {
	ch, err := crypto.ContentHash(tx)
	if err != nil {
		return "", err
	}
	var leaves []string
	for _, pid := range parentIDs {
		h, ok := parentNodeHashes[pid]
		if !ok {
			return "", fmt.Errorf("родитель не найден: %s", pid)
		}
		leaves = append(leaves, h)
	}
	mr := crypto.MerkleRoot(leaves)
	payload := fmt.Sprintf("%s|%s|%s|%d", tx.TxID, ch, mr, tx.Timestamp)
	return crypto.SHA256Hex([]byte(payload)), nil
}
