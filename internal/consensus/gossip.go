package consensus

import (
	"sort"
	"time"
)

// GossipEvent — шаг «сплетен о сплетнях»: известен вид событий и кто кого видел (упрощённо).
type GossipEvent struct {
	Seq       int      `json:"seq"`
	Timestamp int64    `json:"timestamp"`
	TxID      string   `json:"tx_id"`
	ParentIDs []string `json:"parent_ids"`
	PeerHints []string `json:"peer_hints"`
}

// VirtualVoteStep — результат «виртуального голосования».
type VirtualVoteStep struct {
	Round       int      `json:"round"`
	WinnerTxIDs []string `json:"winner_tx_ids"`
	Reason      string   `json:"reason"`
}

// GossipState — журнал gossip + раунды (защита — мьютекс Store).
type GossipState struct {
	Events []GossipEvent     `json:"events"`
	Votes  []VirtualVoteStep `json:"virtual_votes"`
}

func NewGossipState() *GossipState {
	return &GossipState{}
}

func (g *GossipState) LogGossip(txID string, parentIDs []string, peerSeen []string) {
	seq := len(g.Events) + 1
	g.Events = append(g.Events, GossipEvent{
		Seq:       seq,
		Timestamp: time.Now().UnixMilli(),
		TxID:      txID,
		ParentIDs: append([]string(nil), parentIDs...),
		PeerHints: append([]string(nil), peerSeen...),
	})
}

// NodeOrder — минимальные данные для упорядочивания без зависимости от dag.
type NodeOrder struct {
	TxID      string
	ParentIDs []string
	Timestamp int64
}

// RunVirtualVote — детерминированный порядок узлов.
func (g *GossipState) RunVirtualVote(nodes []NodeOrder) []VirtualVoteStep {
	depth := map[string]int{}
	backing := append([]NodeOrder(nil), nodes...)
	idToOrder := make(map[string]*NodeOrder, len(backing))
	for i := range backing {
		idToOrder[backing[i].TxID] = &backing[i]
	}
	var visit func(id string) int
	visit = func(id string) int {
		if d, ok := depth[id]; ok {
			return d
		}
		n := idToOrder[id]
		if n == nil {
			depth[id] = 0
			return 0
		}
		if len(n.ParentIDs) == 0 {
			depth[id] = 0
			return 0
		}
		maxP := -1
		for _, p := range n.ParentIDs {
			d := visit(p)
			if d > maxP {
				maxP = d
			}
		}
		depth[id] = maxP + 1
		return depth[id]
	}
	for i := range backing {
		visit(backing[i].TxID)
	}
	type item struct {
		id    string
		depth int
		ts    int64
	}
	var items []item
	for i := range backing {
		n := backing[i]
		items = append(items, item{id: n.TxID, depth: depth[n.TxID], ts: n.Timestamp})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].depth != items[j].depth {
			return items[i].depth < items[j].depth
		}
		if items[i].ts != items[j].ts {
			return items[i].ts < items[j].ts
		}
		return items[i].id < items[j].id
	})
	var winners []string
	for _, it := range items {
		winners = append(winners, it.id)
	}
	step := VirtualVoteStep{
		Round:       1,
		WinnerTxIDs: winners,
		Reason:      "упорядочивание по глубине в DAG + timestamp + tx_id (виртуальное голосование)",
	}
	g.Votes = append(g.Votes, step)
	return []VirtualVoteStep{step}
}
