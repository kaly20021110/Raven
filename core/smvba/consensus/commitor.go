package consensus

import (
	"bft/mvba/logger"
	"bft/mvba/mempool"
)

type Committor struct {
	Mempool           *mempool.Mempool
	Index             int64
	Blocks            map[int64]*mempool.Block
	commitCh          chan *mempool.Block
	consensuscommitCh chan *ConsensusBlock
	callBack          chan<- struct{}
}

func NewCommittor(callBack chan<- struct{}, pool *mempool.Mempool) *Committor {
	c := &Committor{
		Mempool:           pool,
		Index:             0,
		Blocks:            map[int64]*mempool.Block{},
		commitCh:          make(chan *mempool.Block, 1_000),
		consensuscommitCh: make(chan *ConsensusBlock, 1_000),
		callBack:          callBack,
	}
	go c.run()
	go c.TrytoCommit()
	return c
}

func (c *Committor) Commit(block *ConsensusBlock) {
	c.consensuscommitCh <- block
}

func (c *Committor) TrytoCommit() {
	for b := range c.consensuscommitCh {
		logger.Debug.Printf("commit ConsensusBlock epoch %d node %d the length of the payload is %d\n", b.Epoch, b.Proposer, len(b.PayLoads))
		for _, payload := range b.PayLoads {
			if smallblock, err := c.Mempool.GetBlock(payload); err == nil {
				c.commitCh <- smallblock
			} else {
				//阻塞提交，等待收到payload
				logger.Error.Printf("get key error\n")
			}
		}
		logger.Info.Printf("commit ConsensusBlock epoch %d node %d\n", b.Epoch, b.Proposer)
	}
}

func (c *Committor) run() {
	for block := range c.commitCh {
		if block.Batch.ID != -1 {
			logger.Info.Printf("commit Block node %d batch_id %d\n", block.Proposer, block.Batch.ID)
		} else {
			logger.Error.Printf("commit null Block node %d batch_id %d\n", block.Proposer, block.Batch.ID)
		}
		c.callBack <- struct{}{}
	}
}
