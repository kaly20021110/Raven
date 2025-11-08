package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sort"
)

type Aggreator struct {
	committee           core.Committee
	sigService          *crypto.SigService
	finishAggreator     map[int64]*FinishAggreator
	coins               map[int64]map[int64]map[int64]*CoinAggreator //epoch-leader-inround
	QCAggreator         map[int64]map[int8]*qcAggreator              //epoch phase
	PrepareAggreator    map[int64]map[int64]*prepareAggreator        //epoch - index
	PrepareAUXAggreator map[int64]map[int64]*prepareAUXAggreator
}

func NewAggreator(committee core.Committee, sigService *crypto.SigService) *Aggreator {
	return &Aggreator{
		committee:           committee,
		sigService:          sigService,
		finishAggreator:     make(map[int64]*FinishAggreator),
		coins:               make(map[int64]map[int64]map[int64]*CoinAggreator),
		QCAggreator:         make(map[int64]map[int8]*qcAggreator),
		PrepareAggreator:    make(map[int64]map[int64]*prepareAggreator),
		PrepareAUXAggreator: make(map[int64]map[int64]*prepareAUXAggreator),
	}
}

func (a *Aggreator) AddPrepare(p *Prepare) (uint8, uint8, error) {
	items, ok := a.PrepareAggreator[p.Epoch]
	if !ok {
		items = make(map[int64]*prepareAggreator)
		a.PrepareAggreator[p.Epoch] = items
	}
	if item, ok := items[p.Index]; ok {
		return item.Append(a.committee, a.sigService, p)
	} else {
		item = newprepareAggreator()
		items[p.Index] = item
		return item.Append(a.committee, a.sigService, p)
	}
}

func (a *Aggreator) AddPrepareAUX(p *PrepareAUX) (uint8, uint8, error) {
	items, ok := a.PrepareAUXAggreator[p.Epoch]
	if !ok {
		items = make(map[int64]*prepareAUXAggreator)
		a.PrepareAUXAggreator[p.Epoch] = items
	}
	if item, ok := items[p.Index]; ok {
		return item.Append(a.committee, a.sigService, p)
	} else {
		item = newprepareAUXAggreator()
		items[p.Index] = item
		return item.Append(a.committee, a.sigService, p)
	}
}

func (a *Aggreator) AddFinishVote(finish *Finish) (bool, error) {
	if items, ok := a.finishAggreator[finish.Epoch]; ok {
		logger.Debug.Printf("adding finishing message now epoch %d\n", finish.Epoch)
		return items.Append(a.committee, finish)
	} else {
		items = NewFinishAggreator()
		a.finishAggreator[finish.Epoch] = items
		logger.Debug.Printf("create finishAggreator message now %d author %d\n", finish.Epoch, finish.Author)
		return items.Append(a.committee, finish)
	}
}

func (a *Aggreator) addCoinShare(coinShare *CoinShare) (bool, uint8, error) {
	items, ok := a.coins[coinShare.Epoch]
	if !ok {
		items = make(map[int64]map[int64]*CoinAggreator)
		a.coins[coinShare.Epoch] = items
	}
	item, ok := items[coinShare.Round]
	if !ok {
		item = make(map[int64]*CoinAggreator)
		items[coinShare.Round] = item
	}
	instance, ok := item[coinShare.InRound]
	if !ok {
		instance = NewCoinAggreator()
		items[coinShare.Round][coinShare.InRound] = instance
	}
	return instance.append(a.committee, a.sigService, coinShare)
}
func (a *Aggreator) addVote(v *SPBVote) (bool, []byte, error) {
	items, ok := a.QCAggreator[v.Epoch]
	if !ok {
		items = make(map[int8]*qcAggreator)
		a.QCAggreator[v.Epoch] = items
	}
	if item, ok := items[v.Phase]; ok {
		return item.Append(a.committee, a.sigService, v)
	} else {
		item = newqcAggreator()
		items[v.Phase] = item
		return item.Append(a.committee, a.sigService, v)
	}
}

type FinishAggreator struct {
	Authors map[core.NodeID]struct{}
}

func NewFinishAggreator() *FinishAggreator {
	return &FinishAggreator{
		Authors: make(map[core.NodeID]struct{}),
	}
}

func (f *FinishAggreator) Append(committee core.Committee, finish *Finish) (bool, error) {
	if _, ok := f.Authors[finish.Author]; ok {
		return false, core.ErrOneMoreMessage(finish.MsgType(), finish.Epoch, finish.Author)
	}
	f.Authors[finish.Author] = struct{}{}
	if len(f.Authors) == committee.HightThreshold() {
		return true, nil
	}
	return false, nil
}

type CoinAggreator struct {
	Used   map[core.NodeID]struct{}
	Shares []crypto.SignatureShare
}

func NewCoinAggreator() *CoinAggreator {
	return &CoinAggreator{
		Used:   make(map[core.NodeID]struct{}),
		Shares: make([]crypto.SignatureShare, 0),
	}
}

func (c *CoinAggreator) append(committee core.Committee, sigService *crypto.SigService, share *CoinShare) (bool, uint8, error) {
	if _, ok := c.Used[share.Author]; ok {
		return false, 0, core.ErrOneMoreMessage(share.MsgType(), share.Epoch, share.Author)
	}
	c.Shares = append(c.Shares, share.Share)
	if len(c.Shares) == committee.HightThreshold() {
		var seed uint64 = 0
		data, err := crypto.CombineIntactTSPartial(c.Shares, sigService.ShareKey, share.Hash())
		if err != nil {
			logger.Error.Printf("Combine signature error: %v\n", err)
			return false, 0, err
		}
		for i := 0; i < len(data) && i < RANDOM_LEN; i++ {
			seed = seed<<8 + uint64(data[i])
		}
		return true, uint8(seed % 2), nil
	}

	return false, 0, nil
}

type qcAggreator struct {
	shares  []crypto.SignatureShare
	Authors map[core.NodeID]struct{}
}

func newqcAggreator() *qcAggreator {
	return &qcAggreator{
		shares:  make([]crypto.SignatureShare, 0),
		Authors: make(map[core.NodeID]struct{}),
	}
}
func (e *qcAggreator) Append(committee core.Committee, sigService *crypto.SigService, v *SPBVote) (bool, []byte, error) {
	if _, ok := e.Authors[v.Author]; ok {
		return false, nil, core.ErrOneMoreMessage(v.MsgType(), v.Epoch, v.Author)
	}
	e.Authors[v.Author] = struct{}{}
	e.shares = append(e.shares, v.Signature)
	if len(e.shares) == committee.HightThreshold() {
		//qcvalue, err := crypto.CombineIntactTSPartial(e.shares, sigService.ShareKey, v.Hash())
		var result []byte
		for _, item := range e.shares {
			result = append(result, item.PartialSig...)
		}
		//return true, qcvalue, err
		return true, result, nil
	}
	return false, nil, nil

}

type prepareAggreator struct {
	authors   map[core.NodeID]struct{}
	zerocount map[core.NodeID]struct{}
	onecount  map[core.NodeID]struct{}
}

func newprepareAggreator() *prepareAggreator {
	return &prepareAggreator{
		authors:   make(map[core.NodeID]struct{}),
		zerocount: make(map[core.NodeID]struct{}),
		onecount:  make(map[core.NodeID]struct{}),
	}
}

// PrepareAppend这个函数需要再好好看一下
func (p *prepareAggreator) Append(committee core.Committee, sigService *crypto.SigService, pre *Prepare) (uint8, uint8, error) {
	//这种写法会让好多消息收不到并且重复计算很多消息
	// if _, ok := p.authors[pre.Author]; ok {
	// 	return uint8(0), uint8(2), core.ErrOneMoreMessage(pre.MsgType(), pre.Epoch, pre.Author)
	// }
	// p.authors[pre.Author] = struct{}{}
	if _, ok := p.zerocount[pre.Author]; ok {
		return uint8(0), uint8(2), core.ErrOneMoreMessage(pre.MsgType(), pre.Epoch, pre.Author)
	}
	if _, ok := p.onecount[pre.Author]; ok {
		return uint8(0), uint8(2), core.ErrOneMoreMessage(pre.MsgType(), pre.Epoch, pre.Author)
	}
	p.authors[pre.Author] = struct{}{}
	if pre.Flag == uint8(0) {
		p.zerocount[pre.Author] = struct{}{}
	} else {
		p.onecount[pre.Author] = struct{}{}
	}

	//VAL阶段
	if len(p.onecount) != committee.HightThreshold() && len(p.zerocount) == committee.LowThreshold() {
		return Prepare_LowThreshold, uint8(0), nil
	}
	if len(p.zerocount) != committee.HightThreshold() && len(p.onecount) == committee.LowThreshold() {
		return Prepare_LowThreshold, uint8(1), nil
	}

	//保证了只会广播一次AUX
	if len(p.zerocount) == committee.HightThreshold() {
		if len(p.onecount) < committee.HightThreshold() {
			return Prepare_HightThreshold, uint8(0), nil
		}
	}
	if len(p.onecount) == committee.HightThreshold() {
		if len(p.zerocount) < committee.HightThreshold() {
			return Prepare_HightThreshold, uint8(1), nil
		}
	}
	//如果收到2f+1个VAL

	// if len(p.authors) == committee.HightThreshold() {
	// 	if len(p.onecount) >= committee.LowThreshold() {
	// 		falg = uint8(1)
	// 	}
	// 	return Prepare_HightThreshold, falg, nil
	// } else if len(p.authors) == committee.Size() {
	// 	return Prepare_FullThreshold, pre.Flag, nil
	// } else {
	// 	return uint8(0), uint8(2), nil
	// }
	return uint8(0), uint8(2), nil
}

type prepareAUXAggreator struct {
	authors   map[core.NodeID]struct{}
	zerocount map[core.NodeID]struct{}
	onecount  map[core.NodeID]struct{}
}

func newprepareAUXAggreator() *prepareAUXAggreator {
	return &prepareAUXAggreator{
		authors:   make(map[core.NodeID]struct{}),
		zerocount: make(map[core.NodeID]struct{}),
		onecount:  make(map[core.NodeID]struct{}),
	}
}

func (p *prepareAUXAggreator) Append(committee core.Committee, sigService *crypto.SigService, pre *PrepareAUX) (uint8, uint8, error) {

	if _, ok := p.authors[pre.Author]; ok {
		return uint8(0), uint8(2), core.ErrOneMoreMessage(pre.MsgType(), pre.Epoch, pre.Author)
	}
	p.authors[pre.Author] = struct{}{}
	if pre.Flag == uint8(0) {
		p.zerocount[pre.Author] = struct{}{}
	} else {
		p.onecount[pre.Author] = struct{}{}
	}
	falg := uint8(0)
	if len(p.authors) >= committee.HightThreshold() {
		if len(p.zerocount) == committee.HightThreshold() {
			return Prepare_FullThreshold, falg, nil //代表可以直接退出 2f+1个AUX全是0
		}
		if len(p.zerocount) >= 1 {
			return Prepare_HightThreshold, falg, nil
		} else {
			falg = uint8(1)
			return Prepare_HightThreshold, falg, nil
		}
	}
	return uint8(0), uint8(2), nil
}

const RANDOM_LEN = 3

type ElectAggreator struct {
	shares       []crypto.SignatureShare
	authors      map[core.NodeID]struct{}
	ValueNoCount map[core.NodeID]int
	QCCount      map[core.NodeID]int //mq=1
	QCNoCount    map[core.NodeID]int //mq=0
}

func NewElectAggreator() *ElectAggreator {
	return &ElectAggreator{
		shares:       make([]crypto.SignatureShare, 0),
		authors:      make(map[core.NodeID]struct{}),
		ValueNoCount: make(map[core.NodeID]int),
		QCCount:      make(map[core.NodeID]int),
		QCNoCount:    make(map[core.NodeID]int),
	}
}
func hash(rand, index int) uint64 {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d-%d", rand, index)))
	return new(big.Int).SetBytes(h[:]).Uint64() // 转换整个哈希值为整数
}

func (e *ElectAggreator) Append(committee core.Committee, sigService *crypto.SigService, elect *ElectShare) (map[int]core.NodeID, bool, error) {
	var noReady map[int]core.NodeID = make(map[int]core.NodeID)
	noReady[0] = -1
	if _, ok := e.authors[elect.Author]; ok {
		return noReady, false, core.ErrOneMoreMessage(elect.MsgType(), elect.Epoch, elect.Author)
	}
	e.authors[elect.Author] = struct{}{}
	e.shares = append(e.shares, elect.SigShare)
	for i := range elect.Noproposalset { //更新no-proposal的具体值
		e.ValueNoCount[i] = e.ValueNoCount[i] + 1
	}
	if len(e.shares) == committee.HightThreshold() {
		coin, err := crypto.CombineIntactTSPartial(e.shares, sigService.ShareKey, elect.Hash())
		if err != nil {
			return noReady, false, err
		}
		var rand int
		for i := 0; i < RANDOM_LEN; i++ {
			if coin[i] > 0 {
				rand = rand<<8 + int(coin[i])
			} else {
				rand = rand<<8 + int(-coin[i])
			}
		}
		//set priority
		index := make([]int, committee.Size())
		for i := 0; i < committee.Size(); i++ {
			index[i] = i
		}
		sort.Slice(index, func(i, j int) bool {
			return hash(rand, index[i]) > hash(rand, index[j])
		})
		var prioritymap map[int]core.NodeID = make(map[int]core.NodeID)
		for i := 0; i < committee.Size(); i++ {
			prioritymap[i] = core.NodeID(index[i])
		}

		return prioritymap, true, nil
	}
	return noReady, true, nil
}
