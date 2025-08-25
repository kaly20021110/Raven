package mempool

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"bft/mvba/store"
	"time"
)

type Synchronizer struct {
	Name         core.NodeID
	Store        *store.Store
	Transimtor   *Transmit
	LoopBackChan chan crypto.Digest
	//consensusCoreChan chan<- core.Messgae //只接收消息
	Parameters core.Parameters
	interChan  chan core.Messgae
}

func NewSynchronizer(
	Name core.NodeID,
	Transimtor *Transmit,
	LoopBackChan chan crypto.Digest,
	Parameters core.Parameters,
	//consensusCoreChan chan<- core.Messgae,
	store *store.Store,
) *Synchronizer {
	return &Synchronizer{
		Name:         Name,
		Store:        store,
		Transimtor:   Transimtor,
		LoopBackChan: LoopBackChan,
		Parameters:   Parameters,
		//consensusCoreChan: consensusCoreChan,
		interChan: make(chan core.Messgae, 1000),
	}
}

func (sync *Synchronizer) Cleanup(epoch uint64) {
	message := &SyncCleanUpBlockMsg{
		epoch,
	}
	sync.interChan <- message
}

// 检查proposer提出的这个块本地是否收到所有的payloads
func (sync *Synchronizer) Verify(proposer core.NodeID, Epoch int64, digests []crypto.Digest, consensusblockhash crypto.Digest) VerifyStatus {
	var missing []crypto.Digest
	for _, digest := range digests {
		if _, err := sync.Store.Read(digest[:]); err != nil {
			missing = append(missing, digest)
		}
	}
	if len(missing) == 0 {
		return OK
	}
	message := &SyncBlockMsg{
		missing, proposer, Epoch, consensusblockhash,
	}
	sync.interChan <- message
	logger.Debug.Printf("verify error the missing payloads len is %d epoch is %d proposer is %d\n", len(missing), Epoch, proposer)
	return Wait
}

func (sync *Synchronizer) Run() {
	ticker := time.NewTicker(1000 * time.Millisecond) //定时进行请求区块
	defer ticker.Stop()
	pending := make(map[crypto.Digest]struct {
		Epoch    uint64
		Notify   chan<- struct{}
		LastSend time.Time
		Missing  []crypto.Digest
		Author   core.NodeID
	})
	waiting := make(chan crypto.Digest, 10_000)
	for {
		select {
		case reqMsg := <-sync.interChan:
			{
				switch reqMsg.MsgType() {
				case SyncBlockType:
					{
						req, _ := reqMsg.(*SyncBlockMsg)
						digest := req.ConsensusBlockHash
						if _, ok := pending[digest]; ok {
							logger.Debug.Printf("verify and is asking now skip the block %v\n", digest)
							continue
						}

						notify := make(chan struct{})
						go func() {
							waiting <- waiter(req.Missing, req.ConsensusBlockHash, *sync.Store, notify)
						}()
						pending[digest] = struct {
							Epoch    uint64
							Notify   chan<- struct{}
							LastSend time.Time
							Missing  []crypto.Digest
							Author   core.NodeID
						}{uint64(req.Epoch), notify, time.Now(), req.Missing, req.Author}

						message := &RequestBlockMsg{
							Type:    0,
							Digests: req.Missing,
							Author:  sync.Name,
						}
						//找作者要相关的区块
						sync.Transimtor.MempoolSend(sync.Name, req.Author, message)
					}
				case SyncCleanUpBlockType:
					{
						req, _ := reqMsg.(*SyncCleanUpBlockMsg)
						var keys []crypto.Digest
						for key, val := range pending {
							if val.Epoch <= req.Epoch {
								close(val.Notify)
								keys = append(keys, key)
							}
						}
						for _, key := range keys {
							delete(pending, key)
						}
					}

				}

			}
		case block := <-waiting:
			{
				if block != (crypto.Digest{}) {
					logger.Error.Printf("successfully get the ask block\n")
					delete(pending, block)
					sync.LoopBackChan <- block
				}
			}
		case <-ticker.C: // recycle request  超时了也不找别人要
			{
				now := time.Now()
				for digest, entry := range pending {
					if now.Sub(entry.LastSend) > time.Duration(sync.Parameters.SyncRetryDelay)*time.Millisecond { // 超时重发阈值
						logger.Debug.Printf("recycle request and len of pending is %d\n", len(pending))
						// 重发请求
						msg := &RequestBlockMsg{
							Type:    0,
							Digests: entry.Missing,
							Author:  sync.Name,
						}
						//找所有人要
						sync.Transimtor.MempoolSend(sync.Name, core.NONE, msg)

						// 更新发送时间
						entry.LastSend = now
						pending[digest] = entry
					}
				}
			}

		}
	}
}

func waiter(missing []crypto.Digest, blockhash crypto.Digest, store store.Store, notify <-chan struct{}) crypto.Digest {
	finish := make(chan struct{})
	go func() {
		logger.Warn.Printf("missing length is %d\n", len(missing))
		for _, digest := range missing {
			store.NotifyRead(digest[:])
		}
		close(finish)
	}()

	select {
	case <-finish:
	case <-notify:
		return crypto.Digest{}
	}
	return blockhash
}
