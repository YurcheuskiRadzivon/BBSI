package dag

import (
	"fmt"
	"sort"

	"BBSI/internal/consensus"
	"BBSI/internal/db"
	"BBSI/internal/model"
)

type persistedGraph struct {
	Nodes  []*DAGNode                  `json:"nodes"`
	Events []consensus.GossipEvent     `json:"gossip_events"`
	Votes  []consensus.VirtualVoteStep `json:"gossip_votes"`
}

func (s *Store) loadFromDisk() error {
	if s.db == nil {
		return nil
	}
	var pg persistedGraph
	if err := s.db.ReadJSON(db.FileNodes, &pg); err != nil {
		return err
	}
	return s.replacePersistedGraph(&pg)
}

// sanitizePersistedGraph удаляет узлы verify из старых журналов и пересчитывает node_hash у оставшихся узлов.
func sanitizePersistedGraph(pg *persistedGraph) error {
	if pg == nil || len(pg.Nodes) == 0 {
		return nil
	}
	byID := make(map[string]*DAGNode)
	verifyIDs := make(map[string]bool)
	for _, n := range pg.Nodes {
		if n == nil {
			continue
		}
		cp := *n
		cp.ParentIDs = append([]string(nil), n.ParentIDs...)
		id := cp.Transaction.TxID
		byID[id] = &cp
		if cp.Transaction.Action == model.ActionVerify {
			verifyIDs[id] = true
		}
	}
	if len(verifyIDs) == 0 {
		return nil
	}
	for id, n := range byID {
		if verifyIDs[id] {
			continue
		}
		n.ParentIDs = resolveParentsSkippingVerify(n.ParentIDs, byID, verifyIDs)
	}
	for id := range verifyIDs {
		delete(byID, id)
	}
	if len(byID) == 0 {
		pg.Nodes = nil
		return nil
	}
	if err := recomputeAllNodeHashes(byID); err != nil {
		return err
	}
	out := make([]*DAGNode, 0, len(byID))
	for _, n := range byID {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Transaction.TxID < out[j].Transaction.TxID
	})
	pg.Nodes = out
	return nil
}

func resolveParentsSkippingVerify(parentIDs []string, byID map[string]*DAGNode, verifyIDs map[string]bool) []string {
	var out []string
	seen := map[string]bool{}
	var expand func(string)
	expand = func(pid string) {
		if verifyIDs[pid] {
			pn, ok := byID[pid]
			if !ok {
				return
			}
			for _, pp := range pn.ParentIDs {
				expand(pp)
			}
			return
		}
		if seen[pid] {
			return
		}
		seen[pid] = true
		out = append(out, pid)
	}
	for _, pid := range parentIDs {
		expand(pid)
	}
	return out
}

func recomputeAllNodeHashes(byID map[string]*DAGNode) error {
	if len(byID) == 0 {
		return nil
	}
	computed := make(map[string]string)
	pending := make(map[string]*DAGNode)
	for id, n := range byID {
		pending[id] = n
	}
	for len(pending) > 0 {
		progress := false
		for id, n := range pending {
			ph := make(map[string]string)
			ok := true
			for _, pid := range n.ParentIDs {
				h, has := computed[pid]
				if !has {
					ok = false
					break
				}
				ph[pid] = h
			}
			if !ok {
				continue
			}
			nh, err := ComputeNodeHash(&n.Transaction, n.ParentIDs, ph)
			if err != nil {
				return err
			}
			n.NodeHash = nh
			computed[id] = nh
			delete(pending, id)
			progress = true
		}
		if !progress {
			return fmt.Errorf("не удалось пересчитать node_hash после удаления verify (цикл или битые родители)")
		}
	}
	return nil
}

func (s *Store) replacePersistedGraph(pg *persistedGraph) error {
	if pg != nil && len(pg.Nodes) > 0 {
		if err := sanitizePersistedGraph(pg); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes = make(map[string]*DAGNode)
	if pg != nil {
		for _, n := range pg.Nodes {
			if n == nil {
				continue
			}
			cp := *n
			cp.ParentIDs = append([]string(nil), n.ParentIDs...)
			s.nodes[cp.Transaction.TxID] = &cp
		}
		s.gossip.Events = append([]consensus.GossipEvent(nil), pg.Events...)
		s.gossip.Votes = append([]consensus.VirtualVoteStep(nil), pg.Votes...)
	}
	return nil
}

func (s *Store) loadLogsFromDisk() error {
	if s.db == nil {
		return nil
	}
	var lf db.LogsFile
	if err := s.db.ReadJSON(db.FileLogs, &lf); err != nil {
		return err
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	for _, e := range lf.Entries {
		s.opLog = append(s.opLog, OperationLogEntry{Time: e.Time, Level: e.Level, Message: e.Message})
	}
	return nil
}

func (s *Store) persistGraph() error {
	if s.db == nil {
		return nil
	}
	s.mu.RLock()
	pg := persistedGraph{
		Events: append([]consensus.GossipEvent(nil), s.gossip.Events...),
		Votes:  append([]consensus.VirtualVoteStep(nil), s.gossip.Votes...),
	}
	for _, n := range s.nodes {
		cp := *n
		cp.ParentIDs = append([]string(nil), n.ParentIDs...)
		pg.Nodes = append(pg.Nodes, &cp)
	}
	s.mu.RUnlock()
	sort.Slice(pg.Nodes, func(i, j int) bool {
		return pg.Nodes[i].Transaction.TxID < pg.Nodes[j].Transaction.TxID
	})
	return s.db.WriteJSON(db.FileNodes, pg)
}

func (s *Store) persistLogs() error {
	if s.db == nil {
		return nil
	}
	s.opMu.Lock()
	entries := append([]OperationLogEntry(nil), s.opLog...)
	s.opMu.Unlock()
	var lf db.LogsFile
	for _, e := range entries {
		lf.Entries = append(lf.Entries, db.LogEntryJSON{Time: e.Time, Level: e.Level, Message: e.Message})
	}
	return s.db.WriteJSON(db.FileLogs, lf)
}

// ReloadChainFromDisk перечитывает nodes.json с диска в память перед проверкой целостности,
// чтобы правки файла без перезапуска сервера учитывались в /api/validate.
func (s *Store) ReloadChainFromDisk() error {
	if s.db == nil {
		return nil
	}
	var pg persistedGraph
	if err := s.db.ReadJSON(db.FileNodes, &pg); err != nil {
		return err
	}
	return s.replacePersistedGraph(&pg)
}
