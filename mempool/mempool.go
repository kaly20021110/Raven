package mempool

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"bft/mvba/network"
	"bft/mvba/pool"
	"bft/mvba/store"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Mempool struct {
	Name              core.NodeID
	Committee         core.Committee
	Parameters        core.Parameters
	SigService        *crypto.SigService
	Store             *store.Store
	TxPool            *pool.Pool
	Transimtor        *Transmit
	Queue             map[crypto.Digest]struct{} //整个mempool的最大容量
	ActualQueue       []crypto.Digest            //按照收到时间的排序的实际payload序列
	OwnPayLoadChannel []*Block
	Sync              *Synchronizer
	connectChannel    chan core.Messgae
	//ConsensusMempoolCoreChan <-chan core.Messgae
}

func NewMempool(
	Name core.NodeID,
	Committee core.Committee,
	Parameters core.Parameters,
	SigService *crypto.SigService,
	Store *store.Store,
	TxPool *pool.Pool,
	loopbackchannel chan crypto.Digest,
	consensusMempoolCoreChan chan core.Messgae,
) *Mempool {
	m := &Mempool{
		Name:           Name,
		Committee:      Committee,
		Parameters:     Parameters,
		SigService:     SigService,
		Store:          Store,
		TxPool:         TxPool,
		Queue:          make(map[crypto.Digest]struct{}),
		ActualQueue:    make([]crypto.Digest, 0),
		connectChannel: consensusMempoolCoreChan,
	}
	transmitor := initmempooltransmit(Name, Committee, Parameters)
	m.Transimtor = transmitor
	m.Sync = NewSynchronizer(Name, transmitor, loopbackchannel, Parameters, Store)
	return m
}

func initmempooltransmit(id core.NodeID, committee core.Committee, parameters core.Parameters) *Transmit {
	//step1 .Invoke networl
	addr := fmt.Sprintf(":%s", strings.Split(committee.MempoolAddress(id), ":")[1])
	cc := network.NewCodec(DefaultMessageTypeMap)
	sender := network.NewSender(cc)
	go sender.Run()
	receiver := network.NewReceiver(addr, cc)
	go receiver.Run()
	transimtor := NewTransmit(sender, receiver, parameters, committee)

	//Step 2: Waiting for all nodes to be online
	logger.Info.Println("Waiting for all mempool nodes to be online...")
	time.Sleep(time.Millisecond * time.Duration(parameters.SyncTimeout))
	addrs := committee.MempoolBroadCast(id)
	wg := sync.WaitGroup{}
	for _, addr := range addrs {
		wg.Add(1)
		go func(address string) {
			defer wg.Done()
			for {
				conn, err := net.Dial("tcp", address)
				if err != nil {
					time.Sleep(time.Microsecond * 10000)
					continue
				}
				conn.Close()
				break
			}
		}(addr)
	}
	wg.Wait()

	return transimtor
}

func (c *Mempool) StoreBlock(block *Block) error {
	key := block.Hash()
	value, err := block.Encode()
	if err != nil {
		return err
	}
	return c.Store.Write(key[:], value)
}

func (c *Mempool) GetBlock(digest crypto.Digest) (*Block, error) {
	value, err := c.Store.Read(digest[:])

	if err == store.ErrNotFoundKey {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	b := &Block{}
	if err := b.Decode(value); err != nil {
		return nil, err
	}
	return b, err
}

func (m *Mempool) payloadProcess(block *Block) error {

	if uint64(len(m.Queue)) >= m.Parameters.MaxQueenSize {
		return core.ErrFullMemory(m.Name)
	}
	//本地存储
	if err := m.StoreBlock(block); err != nil {
		return err
	}
	//转发给其他人
	message := &OtherBlockMsg{
		Block: block,
	}
	m.Transimtor.MempoolSend(m.Name, core.NONE, message)
	return nil
}

func (m *Mempool) HandleOwnBlock(block *OwnBlockMsg) error {
	//logger.Debug.Printf("handle mempool OwnBlockMsg\n")  自己的值先不加入自己的内存池队列，给一个缓冲的时间，尽量减少去要payload的时间
	if uint64(len(m.Queue)) >= m.Parameters.MaxQueenSize {
		return core.ErrFullMemory(m.Name)
	}
	digest := block.Block.Hash()
	if err := m.payloadProcess(block.Block); err != nil {
		return err
	}
	m.Queue[digest] = struct{}{}
	m.ActualQueue = append(m.ActualQueue, digest)
	return nil
}

func (m *Mempool) HandleOthorBlock(block *OtherBlockMsg) error {
	//m.generateBlocks()
	logger.Debug.Printf("receive other blocks from author %d batchID is %d\n", block.Block.Proposer, block.Block.Batch.ID)
	//logger.Debug.Printf("handle mempool otherBlockMsg\n")
	if uint64(len(m.Queue)) >= m.Parameters.MaxQueenSize {
		logger.Error.Printf("ErrFullMemory\n")
		return core.ErrFullMemory(m.Name)
	}

	digest := block.Block.Hash()
	// Verify that the payload is correctly signed.
	if flag := block.Block.Verify(m.Committee); !flag {
		logger.Error.Printf("Block sign error\n")
		return nil
	}

	if _, err := m.GetBlock(digest); err == nil {
		//已经存在这个值了，因为我发现某些值会反复放到队列中
		logger.Debug.Printf("the block has received batchid is %d\n", block.Block.Batch.ID)
		return nil
	}

	if err := m.StoreBlock(block.Block); err != nil {
		return err
	}

	m.Queue[digest] = struct{}{}
	m.ActualQueue = append(m.ActualQueue, digest)
	return nil
}

func (m *Mempool) HandleRequestBlock(request *RequestBlockMsg) error {
	logger.Debug.Printf("handle mempool RequestBlockMsg from %d\n", request.Author)
	for _, digest := range request.Digests {
		if b, err := m.GetBlock(digest); err != nil {
			logger.Debug.Printf("handle mempool RequestBlockMsg from %d error can not get the right payload\n", request.Author)
			return err
		} else {
			message := &OtherBlockMsg{
				Block: b,
			}
			m.Transimtor.MempoolSend(m.Name, request.Author, message) //只发给向自己要的人
			//m.Transimtor.Send(m.Name, core.NONE, message) //发给所有人
		}
	}
	return nil
}

// 获取共识区块所引用的微区块
func (m *Mempool) HandleMakeBlockMsg(makemsg *MakeConsensusBlockMsg) ([]crypto.Digest, error) {
	//nums := makemsg.MaxBlockSize / uint64(len(crypto.Digest{}))

	nums := makemsg.MaxBlockSize
	ret := make([]crypto.Digest, 0)
	if len(m.Queue) == 0 {
		logger.Debug.Printf("HandleMakeBlockMsg and len(m.Queue) == 0\n")
		block, _ := NewBlock(m.Name, m.TxPool.GetBatch(), m.SigService)
		if block.Batch.ID != -1 {
			logger.Info.Printf("create Block node %d batch_id %d \n", block.Proposer, block.Batch.ID)
		}
		digest := block.Hash()
		if err := m.payloadProcess(block); err != nil {
			return nil, err
		}
		ret = append(ret, digest)
	} else {
		logger.Debug.Printf("HandleMakeBlockMsg and len(m.Queue) %d the payloadsize is %d\n", len(m.Queue), nums)

		for key := range m.Queue {
			ret = append(ret, key)
			nums--
			if nums == 0 {
				break
			}
		}
		//移除
		for _, key := range ret {
			delete(m.Queue, key)
		}
		// if len(m.ActualQueue) <= nums {
		// 	for _, value := range m.ActualQueue {
		// 		ret = append(ret, value)
		// 		nums--
		// 		if nums == 0 {
		// 			break
		// 		}
		// 	}
		// 	//清空队列
		// 	m.ActualQueue = m.ActualQueue[:0]
		// } else {
		// 	index := nums
		// 	for _, value := range m.ActualQueue {
		// 		ret = append(ret, value)
		// 		nums--
		// 		if nums == 0 {
		// 			break
		// 		}
		// 	}
		// 	m.ActualQueue = m.ActualQueue[index:]
		// }

		// //移除
		// for _, key := range ret {
		// 	delete(m.Queue, key)
		// }

	}
	return ret, nil
}

func (m *Mempool) HandleCleanBlock(msg *CleanBlockMsg) error {
	//本地清理删除payload
	for _, digest := range msg.Digests {
		delete(m.Queue, digest)
	}
	//同步清楚某个epoch之前的所有请求
	m.Sync.Cleanup(uint64(msg.Epoch))
	return nil
}

func (m *Mempool) HandleVerifyMsg(msg *VerifyBlockMsg) VerifyStatus {
	return m.Sync.Verify(msg.Proposer, msg.Epoch, msg.Payloads, msg.ConsensusBlockHash)
}

func (m *Mempool) generateBlocks() error {
	batchChannal := m.TxPool.BatchChannel()
	for batch := range batchChannal {
		block, _ := NewBlock(m.Name, batch, m.SigService)
		if block.Batch.ID != -1 {
			logger.Info.Printf("create Block node %d batch_id %d \n", block.Proposer, block.Batch.ID)
			m.OwnPayLoadChannel = append(m.OwnPayLoadChannel, block)
			ownmessage := &OwnBlockMsg{
				Block: block,
			}
			m.Transimtor.MempoolChannel() <- ownmessage
			time.Sleep(time.Duration(m.Parameters.MinPayloadDelay) * time.Millisecond)
		}
	}
	return nil
}

func (m *Mempool) Run() {
	//一直广播微区块
	if m.Name < core.NodeID(m.Parameters.Faults) {
		logger.Debug.Printf("Node %d is faulty\n", m.Name)
		return
	}
	go m.Sync.Run()
	go m.generateBlocks()

	//监听mempool的消息通道
	mempoolrecvChannal := m.Transimtor.MempoolChannel()
	connectrecvChannal := m.connectChannel

	for {
		var err error
		select {
		case msg := <-connectrecvChannal:
			{
				switch msg.MsgType() {
				case MakeBlockType:
					{
						req, _ := msg.(*MakeConsensusBlockMsg)
						data, errors := m.HandleMakeBlockMsg(req)
						req.Blocks <- data //把引用传进去了，具体使用的时候要注意,这一步要传递到哪里去？
						logger.Debug.Printf("send data to consensus\n")
						err = errors
					}
				case VerifyBlockType:
					{
						req, _ := msg.(*VerifyBlockMsg)
						req.Sender <- m.HandleVerifyMsg(req)
					}
				case CleanBlockType:
					{
						err = m.HandleCleanBlock(msg.(*CleanBlockMsg))
					}
				}
			}
		case msg := <-mempoolrecvChannal:
			{
				switch msg.MsgType() {
				case OwnBlockType:
					{
						err = m.HandleOwnBlock(msg.(*OwnBlockMsg))
					}
				case OtherBlockType:
					{
						err = m.HandleOthorBlock(msg.(*OtherBlockMsg))
					}
				case RequestBlockType:
					{
						err = m.HandleRequestBlock(msg.(*RequestBlockMsg))
					}
				}
			}
		default:
		}
		if err != nil {
			switch err.(type) {
			default:
				logger.Error.Printf("Mempool Core: %s\n", err.Error())
			}
		}
	}
}
