package node

import (
	"bft/mvba/config"
	"bft/mvba/core"
	smvba "bft/mvba/core/smvba/consensus"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"bft/mvba/mempool"
	"bft/mvba/pool"
	"bft/mvba/store"
	"fmt"
)

type Node struct {
	commitChannel chan struct{}
}

func NewNode(
	keysFile, tssKeyFile, committeeFile, parametersFile, storePath, logPath string,
	logLevel, nodeID int,
) (*Node, error) {

	commitChannel := make(chan struct{}, 10_000)
	//step 1: init log config
	logger.SetOutput(logger.InfoLevel, logger.NewFileWriter(fmt.Sprintf("%s/node-info-%d.log", logPath, nodeID)))
	logger.SetOutput(logger.DebugLevel, logger.NewFileWriter(fmt.Sprintf("%s/node-debug-%d.log", logPath, nodeID)))
	logger.SetOutput(logger.WarnLevel, logger.NewFileWriter(fmt.Sprintf("%s/node-warn-%d.log", logPath, nodeID)))
	logger.SetOutput(logger.ErrorLevel, logger.NewFileWriter(fmt.Sprintf("%s/node-error-%d.log", logPath, nodeID)))
	logger.SetLevel(logger.Level(logLevel))

	//step 2: ReadKeys
	_, priKey, err := config.GenKeysFromFile(keysFile)
	if err != nil {
		logger.Error.Println(err)
		return nil, err
	}

	shareKey, err := config.GenTsKeyFromFile(tssKeyFile)
	if err != nil {
		logger.Error.Println(err)
		return nil, err
	}

	//step 3: committee and parameters
	commitee, err := config.GenCommitteeFromFile(committeeFile)
	if err != nil {
		logger.Error.Println(err)
		return nil, err
	}

	poolParameters, coreParameters, err := config.GenParamatersFromFile(parametersFile)
	if err != nil {
		logger.Error.Println(err)
		return nil, err
	}

	//step 4: invoke pool and mempool
	txpool := pool.NewPool(poolParameters, commitee.Size(), nodeID)

	_store := store.NewStore(store.NewDefaultNutsDB(storePath))
	sigService := crypto.NewSigService(priKey, shareKey)

	loopbackchannel := make(chan crypto.Digest, 10_000)
	connectChannel := make(chan core.Messgae, 10_000)

	mempool := mempool.NewMempool(core.NodeID(nodeID), commitee, coreParameters, sigService, _store, txpool, loopbackchannel, connectChannel)

	//step 5:invoke core
	err = smvba.Consensus(core.NodeID(nodeID), commitee, coreParameters, txpool, _store, sigService, commitChannel, loopbackchannel, connectChannel, mempool)

	if err != nil {
		logger.Error.Println(err)
		return nil, err
	}
	logger.Info.Printf("Node %d successfully booted \n", nodeID)

	return &Node{
		commitChannel: commitChannel,
	}, nil
}

// AnalyzeBlock: block
func (n *Node) AnalyzeBlock() {
	for range n.commitChannel {
		//to do something
	}
}
