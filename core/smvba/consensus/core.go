package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"bft/mvba/mempool"
	"bft/mvba/pool"
	"bft/mvba/store"
	"sync"
)

type Core struct {
	Name            core.NodeID
	Committee       core.Committee
	Parameters      core.Parameters
	SigService      *crypto.SigService
	Store           *store.Store
	TxPool          *pool.Pool
	Transimtor      *core.Transmitor
	Aggreator       *Aggreator
	Elector         *Elector
	Commitor        *Committor
	loopBackChannel chan crypto.Digest //从mempool部分获取到区块
	connectChannel  chan core.Messgae

	FinishFlags         map[int64]map[core.NodeID]crypto.Digest // finish? map[epoch][node] = blockHash 完成了spb的两阶段的证明
	SPbInstances        map[int64]map[core.NodeID]*SPB          // map[epoch][node]
	abaInstances        map[int64]map[int64]*ABA                //map[epoch]map[index] index可以计算出leader
	LockSetMap          map[int64]map[core.NodeID]bool          //epoch -node lock 是否已经收到了lock
	LockFlag            map[int64]map[core.NodeID]struct{}      //SPB里面的第一轮投票需要停掉
	Lockmu              sync.RWMutex
	FinishFlag          map[int64]map[core.NodeID]struct{} //SPB里面的第二轮投票需要停掉
	Finishmu            sync.RWMutex
	SkipFlag            map[int64]map[core.NodeID]struct{} //这个leader已经被跳过了，如果需要抉择下一个leader必须等前面所有的leader都完成
	Skipmu              sync.RWMutex
	abaInvokeFlag       map[int64]map[int64]map[int64]map[uint8]struct{} //aba invoke flag
	Epoch               int64
	CommitEpoch         int64
	BlocksWaitforCommit map[int64]*ConsensusBlock
	ParallelABAResult   map[int64]map[int]uint8 //epoch - index -ABA结果
	ParallelABAIndex    map[int64]int           //每一轮都要记录最后一个并行序列
	abaCallBack         chan *ABABack

	blockhashlock      sync.RWMutex
	ConsensusBlockHash map[int64]map[core.NodeID]crypto.Digest //存储每个块的哈希值
}

func NewCore(
	Name core.NodeID,
	Committee core.Committee,
	Parameters core.Parameters,
	SigService *crypto.SigService,
	Store *store.Store,
	TxPool *pool.Pool,
	Transimtor *core.Transmitor,
	callBack chan<- struct{},
	loopBackchannel chan crypto.Digest,
	mconnectchannel chan core.Messgae,
	pool *mempool.Mempool,
) *Core {
	c := &Core{
		Name:                Name,
		Committee:           Committee,
		Parameters:          Parameters,
		SigService:          SigService,
		Store:               Store,
		TxPool:              TxPool,
		Transimtor:          Transimtor,
		Epoch:               0,
		CommitEpoch:         0,
		BlocksWaitforCommit: make(map[int64]*ConsensusBlock),
		Aggreator:           NewAggreator(Committee, SigService),
		Elector:             NewElector(SigService, Committee),
		Commitor:            NewCommittor(callBack, pool),
		loopBackChannel:     loopBackchannel,
		connectChannel:      mconnectchannel,
		FinishFlags:         make(map[int64]map[core.NodeID]crypto.Digest),
		SPbInstances:        make(map[int64]map[core.NodeID]*SPB),
		abaInstances:        make(map[int64]map[int64]*ABA), //针对index序列的ABA
		LockFlag:            make(map[int64]map[core.NodeID]struct{}),
		FinishFlag:          make(map[int64]map[core.NodeID]struct{}),
		SkipFlag:            make(map[int64]map[core.NodeID]struct{}),
		LockSetMap:          make(map[int64]map[core.NodeID]bool),
		abaInvokeFlag:       make(map[int64]map[int64]map[int64]map[uint8]struct{}),
		ParallelABAResult:   make(map[int64]map[int]uint8),
		ParallelABAIndex:    make(map[int64]int),
		abaCallBack:         make(chan *ABABack, 1000),
		ConsensusBlockHash:  make(map[int64]map[core.NodeID]crypto.Digest),
	}

	return c
}

func (c *Core) initParallelABAResult(epoch int64) {
	if _, ok := c.ParallelABAResult[epoch]; !ok {
		c.ParallelABAResult[epoch] = make(map[int]uint8)
	}
	for i := 0; i < c.Committee.Size(); i++ {
		c.ParallelABAResult[epoch][i] = uint8(2)
	}
}

func (c *Core) messageFilter(epoch int64) bool {
	return epoch < c.Epoch
}

func (c *Core) storeConsensusBlock(block *ConsensusBlock) error {
	key := block.Hash()
	value, err := block.Encode()
	if err != nil {
		return err
	}
	return c.Store.Write(key[:], value)
}

func (c *Core) getConsensusBlock(digest crypto.Digest) (*ConsensusBlock, error) {
	value, err := c.Store.Read(digest[:])

	if err == store.ErrNotFoundKey {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	b := &ConsensusBlock{}
	if err := b.Decode(value); err != nil {
		return nil, err
	}
	return b, err
}

func (c *Core) getSpbInstance(epoch int64, node core.NodeID) *SPB {
	rItems, ok := c.SPbInstances[epoch]
	if !ok {
		rItems = make(map[core.NodeID]*SPB)
		c.SPbInstances[epoch] = rItems
	}
	instance, ok := rItems[node]
	if !ok {
		instance = NewSPB(c, epoch, node)
		rItems[node] = instance
	}
	return instance
}

func (c *Core) getABAInstance(epoch, index int64) *ABA {
	items, ok := c.abaInstances[epoch]
	if !ok {
		items = make(map[int64]*ABA)
		c.abaInstances[epoch] = items
	}
	instance, ok := items[index]
	if !ok {
		instance = NewABA(c, epoch, index, c.abaCallBack)
		items[index] = instance
	}
	return instance
}

func (c *Core) VisitLockFlag(epoch int64, node core.NodeID) bool {
	c.Lockmu.RLock()
	if _, oks := c.LockFlag[epoch]; oks {
		if _, ok := c.LockFlag[epoch][node]; ok {
			c.Lockmu.RUnlock()
			return true
		}
	}
	c.Lockmu.RUnlock()
	return false
}

func (c *Core) VisitFinishFlag(epoch int64, node core.NodeID) bool {
	c.Finishmu.RLock()
	if _, oks := c.FinishFlag[epoch]; oks {
		if _, ok := c.FinishFlag[epoch][node]; ok {
			c.Finishmu.RUnlock()
			return true
		}
	}
	c.Finishmu.RUnlock()
	return false

}

func (c *Core) VisitSkipFlag(epoch int64, node core.NodeID) bool {
	c.Skipmu.RLock()
	if _, oks := c.SkipFlag[epoch]; oks {
		if _, ok := c.SkipFlag[epoch][node]; ok {
			c.Skipmu.RUnlock()
			return true
		}
	}
	c.Skipmu.RUnlock()
	return false

}

// 是否已经完成finish
func (c *Core) hasFinish(epoch int64, node core.NodeID) (bool, crypto.Digest) {
	if items, ok := c.FinishFlags[epoch]; !ok {
		return false, crypto.Digest{}
	} else {
		d, ok := items[node]
		return ok, d
	}
}

// 获取并行ABA的最后一个ABA即按照优先级序列处理里面第一个完成finish的节点的前一个序列节点
func (c *Core) getABAStopInstance(epoch int64) (int, core.NodeID) {
	for i := 0; i < c.Committee.Size(); i++ {
		leader := c.Elector.GetLeader(epoch, i)
		if check, _ := c.hasFinish(epoch, leader); check {
			if i == 0 {
				return -1, leader //直接commit
			} else {
				leader = c.Elector.GetLeader(epoch, i-1)
				return i - 1, leader
			}
		}
	}
	return -1, core.NONE
}

func (c *Core) generatorBlock(epoch int64) *ConsensusBlock {
	referencechan := make(chan []crypto.Digest)
	msg := &mempool.MakeConsensusBlockMsg{
		MaxBlockSize: c.Parameters.MaxPayloadSize, Blocks: referencechan,
	}
	c.connectChannel <- msg
	//c.Transimtor.ConnectRecvChannel() <- msg
	payloads := <-referencechan
	consensusblock := NewConsensusBlock(c.Name, payloads, epoch)
	logger.Info.Printf("create ConsensusBlock epoch %d node %d\n", consensusblock.Epoch, consensusblock.Proposer)

	//logger.Info.Printf("create ConsensusBlock epoch %d node %d paloads %d\n", consensusblock.Epoch, consensusblock.Proposer, len(consensusblock.PayLoads))
	return consensusblock
}

// 检查当前区块的所有payload是否都已经收到
func (c *Core) verifyConsensusBlock(block *ConsensusBlock) bool {
	logger.Debug.Printf("verify times epoch %d\n", block.Epoch)
	verifychan := make(chan mempool.VerifyStatus)
	msg := &mempool.VerifyBlockMsg{
		Proposer:           block.Proposer, //提块的人
		Epoch:              block.Epoch,
		Payloads:           block.PayLoads,
		ConsensusBlockHash: block.Hash(),
		Sender:             verifychan,
	}
	c.connectChannel <- msg
	//获取当前区块的状态
	verifystatus := <-verifychan
	if verifystatus == mempool.OK {
		return true
	} else {
		return false
	}
}

func (c *Core) AddConsensusBlockHash(epoch int64, node core.NodeID, digest crypto.Digest) {
	c.blockhashlock.Lock()
	defer c.blockhashlock.Unlock()
	if _, ok := c.ConsensusBlockHash[epoch]; !ok {
		c.ConsensusBlockHash[epoch] = make(map[core.NodeID]crypto.Digest)
	}
	if _, exist := c.ConsensusBlockHash[epoch][node]; !exist {
		c.ConsensusBlockHash[epoch][node] = digest
	}
}

func (c *Core) GetConsensusBlockHash(epoch int64, node core.NodeID) (crypto.Digest, bool) {
	c.blockhashlock.Lock()
	defer c.blockhashlock.Unlock()
	if _, ok := c.ConsensusBlockHash[epoch]; !ok {
		c.ConsensusBlockHash[epoch] = make(map[core.NodeID]crypto.Digest)
		return crypto.Digest{}, false
	}
	if value, exist := c.ConsensusBlockHash[epoch][node]; exist {
		return value, true
	} else {
		return crypto.Digest{}, false
	}
}

/*********************************** Protocol Start***************************************/
func (c *Core) handleSpbProposal(p *SPBProposal) error {
	logger.Debug.Printf("Processing SPBProposal proposer %d epoch %d phase %d\n", p.Author, p.Epoch, p.Phase)
	if c.messageFilter(p.Epoch) {
		return nil
	}
	//Store Block at first time
	if p.Phase == SPB_ONE_PHASE {
		if err := c.storeConsensusBlock(p.B); err != nil {
			logger.Error.Printf("Store Block error: %v\n", err)
			return err
		}
		c.AddConsensusBlockHash(p.Epoch, p.Author, p.B.Hash())
		//如果是第一次收到区块先检查payloads,会有小部分人没有收到相关区块
		if ok := c.verifyConsensusBlock(p.B); !ok {
			logger.Error.Printf("proposal 1 checkreferrence error and try to retriver Author %d Epoch %d lenof Reference %d\n", p.Author, p.Epoch, len(p.B.PayLoads))
			return nil
		}
	}

	if p.Phase == SPB_ONE_PHASE {
		if c.VisitLockFlag(p.Epoch, p.Author) { //暂停第一轮的投票聚合
			logger.Debug.Printf("already send message as lock ,can not continue to vote for finish epoch %d author %d\n", p.Epoch, p.Author)
			return nil
		}
	}
	if p.Phase == SPB_TWO_PHASE {
		if c.VisitFinishFlag(p.Epoch, p.Author) { //暂停第二轮的投票聚合
			logger.Debug.Printf("already send message as Finish ,can not continue to vote for finish epoch %d author %d\n", p.Epoch, p.Author)
			return nil
		}
	}

	spb := c.getSpbInstance(p.Epoch, p.Author)
	go spb.processProposal(p)

	return nil
}

func (c *Core) handleSpbVote(v *SPBVote) error {

	//discard message
	if c.messageFilter(v.Epoch) {
		return nil
	}
	logger.Debug.Printf("Processing SPBVote author %d proposer %d epoch %d phase %d\n", v.Author, v.Proposer, v.Epoch, v.Phase)
	spb := c.getSpbInstance(v.Epoch, v.Proposer)
	go spb.processVote(v)

	return nil
}

func (c *Core) handleFinish(f *Finish) error {

	//discard message
	if c.messageFilter(f.Epoch) {
		return nil
	}
	logger.Debug.Printf("Processing Finish epoch %d Author %d \n", f.Epoch, f.Author)

	if flag, err := c.Aggreator.AddFinishVote(f); err != nil {
		return err
	} else {
		rF, ok := c.FinishFlags[f.Epoch]
		if !ok {
			rF = make(map[core.NodeID]crypto.Digest)
			c.FinishFlags[f.Epoch] = rF
		}
		rF[f.Author] = f.BlockHash
		if flag { //2f+1 finish?
			return c.invokeReadyandShare(f.Epoch)
		}
	}
	return nil
}

func (c *Core) generateNoProposalSet(epoch int64) map[core.NodeID]struct{} {
	ID := make(map[core.NodeID]struct{})

	for i := 0; i < c.Committee.Size(); i++ {
		item := c.getSpbInstance(epoch, core.NodeID(i))
		if item.BlockHash.Load() == nil {
			ID[core.NodeID(i)] = struct{}{}
			c.Lockmu.Lock()
			_, ok := c.LockFlag[epoch]
			if !ok {
				c.LockFlag[epoch] = make(map[core.NodeID]struct{})
			}
			c.LockFlag[epoch][core.NodeID(i)] = struct{}{} //更新不能投票了
			c.Lockmu.Unlock()
		}
	}

	return ID
}

func (c *Core) generateLockSet(epoch int64) map[core.NodeID]struct{} {
	ID := make(map[core.NodeID]struct{})

	for i := 0; i < c.Committee.Size(); i++ {
		item := c.getSpbInstance(epoch, core.NodeID(i))
		if item.IsLock() {
			ID[core.NodeID(i)] = struct{}{}
			c.Finishmu.Lock()
			_, ok := c.FinishFlag[epoch]
			if !ok {
				c.FinishFlag[epoch] = make(map[core.NodeID]struct{})
			}
			c.FinishFlag[epoch][core.NodeID(i)] = struct{}{} //更新不能投票了
			c.Finishmu.Unlock()
		}
	}

	return ID
}

func (c *Core) invokeReadyandShare(epoch int64) error {
	logger.Debug.Printf("Processing invoke Ready and Share epoch %d\n", epoch)
	ID := c.generateNoProposalSet(epoch)
	LockID := c.generateLockSet(epoch)
	//广播electshare消息
	share, _ := NewElectShare(c.Name, epoch, ID, LockID, c.SigService)
	c.Transimtor.Send(c.Name, core.NONE, share)
	c.Transimtor.RecvChannel() <- share
	return nil
}

func (c *Core) handleElectShare(share *ElectShare) error {
	//discard message
	if c.messageFilter(share.Epoch) {
		return nil
	}
	logger.Debug.Printf("Processing ElectShare author %d epoch %d\n", share.Author, share.Epoch)
	if leader, valid, err := c.Elector.AddShareVote(share); err != nil {
		return err
	} else if valid { //处理locksetMap
		if _, ok := c.LockSetMap[share.Epoch]; !ok {
			c.LockSetMap[share.Epoch] = make(map[core.NodeID]bool)
		}
		for i := range share.Lockset {
			if ok := c.LockSetMap[share.Epoch][i]; !ok {
				c.LockSetMap[share.Epoch][i] = true
			}
		}
		if leader[0] != core.NodeID(-1) { //收集到了2f+1个elect消息
			logger.Debug.Printf("leader[0] is what?%d\n", leader[0])
			c.processLeader(share.Epoch)
		}
	}
	return nil
}

func (c *Core) processLeader(epoch int64) error {
	if epoch < c.Epoch {
		logger.Debug.Printf("Processing Leader error for epoch is less than c.Epoch\n")
		return nil
	}
	//并行ABA预备工作
	index, leaderid := c.getABAStopInstance(epoch)
	//处理可以直接commit的部分
	if index == -1 && leaderid != core.NONE {
		if check, value := c.hasFinish(epoch, leaderid); check {
			logger.Debug.Printf("Processing Leader for epoch %d and leader %d has finish and can commit\n", epoch, leaderid)
			if b, err := c.getConsensusBlock(value); err != nil {
				return err
			} else if b != nil {
				c.BlocksWaitforCommit[b.Epoch] = b
				c.CommitAllBlocks()
				// if ok := c.verifyConsensusBlock(b); !ok {
				// 	logger.Error.Printf("processLeader 1 checkreferrence error and try to retriver Author %d Epoch %d lenof Reference %d\n", b.Proposer, b.Epoch, len(b.PayLoads))
				// 	c.BlocksWaitforCommit[b.Epoch] = b
				// 	return nil
				// } else {
				// 	c.BlocksWaitforCommit[b.Epoch] = b
				// 	c.CommitAllBlocks()
				// }
				logger.Debug.Printf("help commit message leader %d epoch %d \n", leaderid, epoch)
				help, _ := NewHelpCommit(c.Name, leaderid, epoch, b, c.SigService)
				c.Transimtor.Send(c.Name, core.NONE, help)
				//进入下一个epoch
				logger.Debug.Printf("through commitderectly 1 advanceepoch %d \n", epoch+1)
				if epoch == c.Epoch {
					c.advanceNextEpoch(epoch + 1)
				}

			} else {
				logger.Debug.Printf("Processing retriever epoch %d \n", epoch)
			}
		}
		return nil
	}

	logger.Debug.Printf("ParallelABA Processing Leader for epoch %d and index id  %d \n", epoch, index)
	//处理并行ABA的部分
	c.ParallelABAIndex[epoch] = index
	for i := 0; i <= c.ParallelABAIndex[epoch]; i++ {
		abaleader := c.Elector.GetLeader(epoch, i)
		if c.Elector.judgeSkip(epoch, abaleader) {
			//发送helpskip的消息，并且置这个位置的ABA的结果为0
			_, ok := c.SkipFlag[epoch]
			if !ok {
				c.SkipFlag[epoch] = make(map[core.NodeID]struct{})
			}
			c.SkipFlag[epoch][abaleader] = struct{}{}
			//ERROR 修改之处 这个地方修改了会出现空指针
			if c.ParallelABAResult == nil {
				c.ParallelABAResult = make(map[int64]map[int]uint8)
			}

			if _, ok := c.ParallelABAResult[epoch]; !ok {
				c.ParallelABAResult[epoch] = make(map[int]uint8)
			}
			c.ParallelABAResult[epoch][i] = uint8(0)
			//帮助所有人skip
			skip, _ := NewHelpSkip(c.Name, abaleader, epoch, int(i), c.SigService)
			c.Transimtor.Send(c.Name, core.NONE, skip)
			c.Transimtor.RecvChannel() <- skip
		} else {
			if c.LockSetMap[epoch][abaleader] {
				//以1调用prepareABA
				prepare, _ := NewPrepare(c.Name, abaleader, int64(i), epoch, uint8(1), c.SigService)
				c.Transimtor.Send(c.Name, core.NONE, prepare)
				c.Transimtor.RecvChannel() <- prepare

			} else {
				//以0调用prepareABA
				prepare, _ := NewPrepare(c.Name, abaleader, int64(i), epoch, uint8(0), c.SigService)
				c.Transimtor.Send(c.Name, core.NONE, prepare)
				c.Transimtor.RecvChannel() <- prepare
			}
		}
	}

	//如果发现都已经skip掉了前一项，那么现在就可以直接提交finish的这一项
	if c.judgeCommit(epoch, index) {
		if check1, value1 := c.hasFinish(epoch, leaderid); check1 {
			logger.Debug.Printf("Processing Leader for epoch %d and leader %d has finish and can commit\n", epoch, leaderid)
			if b1, err1 := c.getConsensusBlock(value1); err1 != nil {
				return err1
			} else if b1 != nil {
				c.BlocksWaitforCommit[b1.Epoch] = b1
				c.CommitAllBlocks()
				// if ok1 := c.verifyConsensusBlock(b1); !ok1 {
				// 	logger.Error.Printf("processLeader 2 checkreferrence error and try to retriver Author %d Epoch %d lenof Reference %d\n", b1.Proposer, b1.Epoch, len(b1.PayLoads))
				// 	c.BlocksWaitforCommit[b1.Epoch] = b1
				// 	return nil
				// } else {
				// 	c.BlocksWaitforCommit[b1.Epoch] = b1
				// 	c.CommitAllBlocks()
				// }
				logger.Debug.Printf("help commit message leader %d epoch %d \n", leaderid, epoch)
				help, _ := NewHelpCommit(c.Name, leaderid, epoch, b1, c.SigService)
				c.Transimtor.Send(c.Name, core.NONE, help)
				logger.Debug.Printf("through commitderectly 2 advanceepoch %d \n", epoch+1)
				if epoch == c.Epoch {
					c.advanceNextEpoch(epoch + 1)
				}
			} else {
				logger.Debug.Printf("Processing retriever epoch %d \n", epoch)
			}
		}
	}

	logger.Debug.Printf("Processing Leader epoch %d index %d Leader %d\n", epoch, index, c.Elector.GetLeader(epoch, index))
	return nil
}

func (c *Core) handlePrepare(p *Prepare) error {
	logger.Debug.Printf("handle prepare message epoch %d leader%d author %d value %d\n", p.Epoch, p.Leader, p.Author, p.Flag)
	flag, value, err := c.Aggreator.AddPrepare(p)
	if flag == Prepare_FullThreshold {
		//直接结束ABA，发送ABAHalt
		c.ParallelABAResult[p.Epoch][int(p.Index)] = uint8(p.Flag)

		temp, _ := NewABAHalt(c.Name, p.Leader, p.Epoch, p.Index, 0, p.Flag, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, temp)
		c.Transimtor.RecvChannel() <- temp

	} else if flag == Prepare_HightThreshold {
		//以value调用ABA
		//logger.Debug.Printf("the start time is %d %d 1 the time first create the aba val is:\n", c.Name, epoch, time.Now())
		abaVal, _ := NewABAVal(c.Name, p.Leader, p.Epoch, p.Index, 0, value, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, abaVal)
		c.Transimtor.RecvChannel() <- abaVal
	}
	return err
}

func (c *Core) handleOutput(epoch int64, blockHash crypto.Digest) error {
	logger.Debug.Printf("Processing Ouput epoch %d \n", epoch)
	if c.messageFilter(epoch) {
		return nil
	}
	if b, err := c.getConsensusBlock(blockHash); err != nil {
		return err
	} else if b != nil {
		c.BlocksWaitforCommit[b.Epoch] = b
		c.CommitAllBlocks()
		// if ok := c.verifyConsensusBlock(b); !ok {
		// 	c.BlocksWaitforCommit[b.Epoch] = b
		// 	logger.Error.Printf("handleOutput checkreferrence error and try to retriver Author %d Epoch %d lenof Reference %d\n", b.Proposer, b.Epoch, len(b.PayLoads))
		// 	return nil
		// } else {
		// 	c.BlocksWaitforCommit[b.Epoch] = b
		// 	c.CommitAllBlocks()
		// }
		help, _ := NewHelpCommit(c.Name, b.Proposer, epoch, b, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, help)
		c.Transimtor.RecvChannel() <- help //不用发给自己
	} else {
		logger.Debug.Printf("Processing retriever epoch %d \n", epoch)
	}
	if epoch == c.Epoch {
		logger.Debug.Printf("through handleoutput advanceepoch %d \n", epoch+1)
		c.advanceNextEpoch(epoch + 1)
	}
	//c.advanceNextEpoch(epoch + 1)
	return nil
}

func (c *Core) handleABAVal(val *ABAVal) error {
	if c.messageFilter(val.Epoch) {
		return nil
	}
	logger.Debug.Printf("Processing aba val leader %d epoch %d round %d in-round %d val %d\n", val.Leader, val.Epoch, val.Round, val.InRound, val.Flag)

	//判断是否已经skip  收到ABA的时候
	if _, oks := c.SkipFlag[val.Epoch]; oks {
		if _, ok := c.SkipFlag[val.Epoch][val.Leader]; ok { //可以skip掉
			logger.Debug.Printf("help skip message leader %d epoch %d index %d\n", val.Leader, val.Epoch, int(val.Round))
			skip, _ := NewHelpSkip(c.Name, val.Leader, val.Epoch, int(val.Round), c.SigService)
			c.Transimtor.Send(c.Name, val.Author, skip)
			c.Transimtor.RecvChannel() <- skip
			return nil
		}
	}

	go c.getABAInstance(val.Epoch, val.Round).ProcessABAVal(val)

	return nil
}

func (c *Core) handleABAMux(mux *ABAMux) error {
	if c.messageFilter(mux.Epoch) {
		return nil
	}
	logger.Debug.Printf("Processing aba mux leader %d epoch %d round %d in-round %d val %d\n", mux.Leader, mux.Epoch, mux.Round, mux.InRound, mux.Flag)

	if _, oks := c.SkipFlag[mux.Epoch]; oks {
		if _, ok := c.SkipFlag[mux.Epoch][mux.Leader]; ok { //可以skip掉
			skip, _ := NewHelpSkip(c.Name, mux.Leader, mux.Epoch, int(mux.Round), c.SigService)
			c.Transimtor.Send(c.Name, mux.Author, skip)
			c.Transimtor.RecvChannel() <- skip
			return nil
		}
	}

	go c.getABAInstance(mux.Epoch, mux.Round).ProcessABAMux(mux)

	return nil
}

func (c *Core) handleCoinShare(share *CoinShare) error {
	if c.messageFilter(share.Epoch) {
		return nil
	}
	logger.Debug.Printf("Processing coin share epoch %d round %d in-round %d", share.Epoch, share.Round, share.InRound)

	if ok, coin, err := c.Aggreator.addCoinShare(share); err != nil {
		return err
	} else if ok {
		logger.Debug.Printf("ABA epoch %d ex-round %d in-round %d coin %d\n", share.Epoch, share.Round, share.InRound, coin)
		go c.getABAInstance(share.Epoch, share.Round).ProcessCoin(share.InRound, coin, share.Leader)
	}

	return nil
}

func (c *Core) handleABAHalt(halt *ABAHalt) error {
	if c.messageFilter(halt.Epoch) {
		return nil
	}
	logger.Debug.Printf("Processing aba halt leader %d epoch %d in-round %d value %d\n", halt.Leader, halt.Epoch, halt.InRound, halt.Flag)
	go c.getABAInstance(halt.Epoch, halt.Round).ProcessHalt(halt)
	return nil
}
func (c *Core) isInvokeABA(epoch, round, inRound int64, tag uint8) bool {
	flags, ok := c.abaInvokeFlag[epoch]
	if !ok {
		return false
	}
	flag, ok := flags[round]
	if !ok {
		return false
	}
	item, ok := flag[inRound]
	if !ok {
		return false
	}
	_, ok = item[tag]
	return ok
}

func (c *Core) invokeABAVal(leader core.NodeID, epoch, round, inRound int64, flag uint8) error {
	logger.Debug.Printf("Invoke ABA epoch %d ex_round %d in_round %d val %d\n", epoch, round, inRound, flag)
	if c.isInvokeABA(epoch, round, inRound, flag) {
		return nil
	}
	flags, ok := c.abaInvokeFlag[epoch]
	if !ok {
		flags = make(map[int64]map[int64]map[uint8]struct{})
		c.abaInvokeFlag[epoch] = flags
	}
	items, ok := flags[round]
	if !ok {
		items = make(map[int64]map[uint8]struct{})
		flags[round] = items
	}
	item, ok := items[inRound]
	if !ok {
		item = make(map[uint8]struct{})
		items[inRound] = item
	}
	item[flag] = struct{}{}
	abaVal, _ := NewABAVal(c.Name, leader, epoch, round, inRound, flag, c.SigService)
	c.Transimtor.Send(c.Name, core.NONE, abaVal)
	c.Transimtor.RecvChannel() <- abaVal

	return nil
}

// 判断是否可以提交当前块 前面所有的ABA的输出是0，这个块是最新的ABA输出值1的块
func (c *Core) judgeCommit(epoch int64, index int) bool {
	for i := 0; i < index; i++ {
		if c.ParallelABAResult[epoch][i] != uint8(0) {
			return false
		}
	}
	return true
}

func (c *Core) processABABack(back *ABABack) error {
	if back.ExRound > int64(c.ParallelABAIndex[back.Epoch]) {
		logger.Debug.Printf("the aba halt index is lager than the core.Parallel index\n")
		return nil
	}
	if back.Typ == ABA_INVOKE {
		return c.invokeABAVal(back.Leader, back.Epoch, back.ExRound, back.InRound, back.Flag)
	} else if back.Typ == ABA_HALT {
		if back.Flag == FLAG_NO { //next leader 选择下一个leader去判断
			c.ParallelABAResult[back.Epoch][int(back.ExRound)] = uint8(0)
			if c.judgeCommit(back.Epoch, c.ParallelABAIndex[back.Epoch]+1) {
				leader := c.Elector.GetLeader(back.Epoch, c.ParallelABAIndex[back.Epoch]+1)
				blockHash, exist := c.GetConsensusBlockHash(back.Epoch, leader)
				if !exist {
					//impossible
					logger.Error.Printf("judgeCommitOK but instance.getBlockHashError TYPE1\n")
				} else {
					return c.handleOutput(back.Epoch, blockHash)
				}
			}
			//return c.invokeNextLeader(back.Epoch, back.ExRound)
		} else if back.Flag == FLAG_YES { //如果可以提交直接提交，//nextepoch
			c.ParallelABAResult[back.Epoch][int(back.ExRound)] = uint8(1)
			if c.judgeCommit(back.Epoch, int(back.ExRound)) {
				blockHash, exist := c.GetConsensusBlockHash(back.Epoch, back.Leader)
				if !exist {
					//impossible
					logger.Error.Printf("judgeCommitOK but instance.getBlockHashError TYPE2\n")
				} else {
					return c.handleOutput(back.Epoch, blockHash)
				}
			}
		}
	}
	return nil
}

func (c *Core) handleHelpSkip(skip *HelpSkip) error {
	if c.messageFilter(skip.Epoch) {
		return nil
	}
	if skip.Index > c.ParallelABAIndex[skip.Epoch] { //如果收到的helpskip的index值大于本地，向发送helpskip的人发送abahalt但是其实好像不会出现这种情况skip和finish不会同时出现
		return nil
	}
	logger.Debug.Printf("handleHelpSkip from %d epoch %d round %d\n", skip.Author, skip.Epoch, skip.Index)

	c.ParallelABAResult[skip.Epoch][skip.Index] = uint8(0)
	//检查前面所有的值
	if c.judgeCommit(skip.Epoch, c.ParallelABAIndex[skip.Epoch]+1) {
		leader := c.Elector.GetLeader(skip.Epoch, c.ParallelABAIndex[skip.Epoch]+1)
		blockHash, exist := c.GetConsensusBlockHash(skip.Epoch, leader)
		if !exist {
			//impossible
			logger.Error.Printf("judgeCommitOK but instance.getBlockHashError because has not receive the block\n")
		} else {
			return c.handleOutput(skip.Epoch, blockHash)
		}
	}
	return nil
}

func (c *Core) handleHelpCommit(help *HelpCommit) error {
	logger.Debug.Printf("handle help commit message epoch %d author %d leader %d\n", help.Epoch, help.Author, help.Leader)
	if c.messageFilter(help.Epoch) { //如果已经进入下一轮了
		return nil
	}
	if _, ok := c.BlocksWaitforCommit[help.Epoch]; !ok {
		c.BlocksWaitforCommit[help.Epoch] = help.B
		c.CommitAllBlocks()
	}
	if help.Epoch == c.Epoch { //如果等于当前epoch,那么直接进入下一个epoch
		logger.Debug.Printf("through helpcommit advanceepoch %d \n", help.Epoch+1)
		c.advanceNextEpoch(help.Epoch + 1)
	}

	// if ok := c.verifyConsensusBlock(help.B); !ok {
	// 	logger.Error.Printf("handleHelpCommit checkreferrence error and try to retriver Author %d Epoch %d lenof Reference %d\n", help.B.Proposer, help.B.Epoch, len(help.B.PayLoads))
	// 	c.BlocksWaitforCommit[help.B.Epoch] = help.B
	// 	return nil
	// } else {
	// 	if _, ok := c.BlocksWaitforCommit[help.B.Epoch]; !ok {
	// 		c.BlocksWaitforCommit[help.B.Epoch] = help.B
	// 	}
	// 	c.CommitAllBlocks()
	// }
	return nil
}

func (c *Core) CommitAllBlocks() {
	commitEpoch := c.CommitEpoch
	for i := commitEpoch; i <= c.Epoch; i++ {
		logger.Debug.Printf("Commit Epoch is %d nowepoch is %d\n", commitEpoch, c.Epoch)
		if block, ok := c.BlocksWaitforCommit[i]; ok {
			if flag := c.verifyConsensusBlock(block); flag {
				c.Commitor.Commit(block)
				delete(c.BlocksWaitforCommit, i)
				c.CommitEpoch = block.Epoch + 1
				//把这个payload从发块队列里面剔除
				msg := &mempool.CleanBlockMsg{
					Digests: block.PayLoads,
					Epoch:   block.Epoch,
				}
				c.connectChannel <- msg
			} else {
				break
			}
		} else {
			break
		}
	}
}

func (c *Core) handleLoopBack(blockhash crypto.Digest) error {
	if block, err := c.getConsensusBlock(blockhash); err != nil {
		logger.Error.Printf("loopback error\n")
		return err
	} else {
		logger.Debug.Printf("procesing block loop back round %d node %d \n", block.Epoch, block.Proposer)
		c.AddConsensusBlockHash(block.Epoch, block.Proposer, blockhash)
		proposal, _ := NewSPBProposal(block.Proposer, block, block.Epoch, SPB_ONE_PHASE, nil, c.SigService)
		if block.Epoch >= c.Epoch { //如果已经进入下一轮就没必要再处理这个方案了
			go c.getSpbInstance(proposal.Epoch, proposal.Author).processProposal(proposal)
		}
		//处理commit的情况
		if b, exist := c.BlocksWaitforCommit[block.Epoch]; exist {
			if block.Epoch == b.Epoch && block.Proposer == b.Proposer {
				logger.Debug.Printf("commit all blocks when handle loopback epoch %d author %d\n", b.Epoch, b.Proposer)
				c.CommitAllBlocks()
				if block.Epoch == c.Epoch { //不能提前进入下一轮
					logger.Debug.Printf("through loopback advanceepoch %d \n", block.Epoch+1)
					c.advanceNextEpoch(block.Epoch + 1)
				}
			}
		}
	}
	return nil
}

/*********************************** Protocol End***************************************/
func (c *Core) advanceNextEpoch(epoch int64) {
	if epoch <= c.Epoch {
		logger.Debug.Printf("advance next epoch error and the epoch is %d\n", epoch)
		return
	}
	c.initParallelABAResult(epoch)
	logger.Debug.Printf("advance next epoch %d\n", epoch)
	logger.Info.Printf("advance next epoch %d\n", epoch)
	//Clear Something
	c.Epoch = epoch
	block := c.generatorBlock(epoch)
	proposal, _ := NewSPBProposal(c.Name, block, epoch, SPB_ONE_PHASE, nil, c.SigService)
	c.Transimtor.Send(c.Name, core.NONE, proposal)
	c.Transimtor.RecvChannel() <- proposal

	if _, ok := c.BlocksWaitforCommit[epoch]; ok {
		c.CommitAllBlocks()
		logger.Debug.Printf("continuously advance next epoch %d\n", epoch)
		//这里应该清除掉一点队列里面堆积的区块
		if epoch == c.Epoch {
			c.advanceNextEpoch(epoch + 1)
		}
	}
}

func (c *Core) Run() {
	if c.Name < core.NodeID(c.Parameters.Faults) {
		logger.Debug.Printf("Node %d is faulty\n", c.Name)
		return
	}
	c.initParallelABAResult(c.Epoch)
	block := c.generatorBlock(c.Epoch)
	proposal, _ := NewSPBProposal(c.Name, block, c.Epoch, SPB_ONE_PHASE, nil, c.SigService)
	if err := c.Transimtor.Send(c.Name, core.NONE, proposal); err != nil {
		panic(err)
	}
	c.Transimtor.RecvChannel() <- proposal

	recvChannal := c.Transimtor.RecvChannel()
	for {
		var err error
		select {
		case msg := <-recvChannal:
			{
				if validator, ok := msg.(Validator); ok {
					if !validator.Verify(c.Committee) {
						err = core.ErrSignature(msg.MsgType())
						break
					}
				}
				switch msg.MsgType() {
				case SPBProposalType:
					err = c.handleSpbProposal(msg.(*SPBProposal))
				case SPBVoteType:
					err = c.handleSpbVote(msg.(*SPBVote))
				case FinishType:
					err = c.handleFinish(msg.(*Finish))
				case ElectShareType:
					err = c.handleElectShare(msg.(*ElectShare))
				case HelpSkipType:
					err = c.handleHelpSkip(msg.(*HelpSkip))
				case HelpCommitType:
					err = c.handleHelpCommit(msg.(*HelpCommit))
				case PrepareType:
					err = c.handlePrepare(msg.(*Prepare))
				case ABAValType:
					err = c.handleABAVal(msg.(*ABAVal))
				case ABAMuxType:
					err = c.handleABAMux(msg.(*ABAMux))
				case CoinShareType:
					err = c.handleCoinShare(msg.(*CoinShare))
				case ABAHaltType:
					err = c.handleABAHalt(msg.(*ABAHalt))

				}
			}
		case block := <-c.loopBackChannel:
			{
				err = c.handleLoopBack(block)
			}
		case abaBack := <-c.abaCallBack:
			err = c.processABABack(abaBack)
		default:
		}
		if err != nil {
			logger.Warn.Println(err)
		}
	}
}
