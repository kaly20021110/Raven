package test

// import (
// 	"lightDAG/core"
// 	"bft/mvba/network"
// 	"sync"
// 	"testing"
// 	"time"
// )

// func TestNetwork(t *testing.T) {
// 	// logger.SetOutput(logger.InfoLevel|logger.DebugLevel|logger.ErrorLevel|logger.WarnLevel, logger.NewFileWriter("./default.log"))
// 	cc := network.NewCodec(core.DefaultMsgTypes)
// 	addr := ":8080"
// 	receiver := network.NewReceiver(addr, cc)
// 	go receiver.Run()
// 	time.Sleep(time.Second)
// 	sender := network.NewSender(cc)
// 	go sender.Run()

// 	wg := sync.WaitGroup{}
// 	for i := 0; i < 10; i++ {
// 		wg.Add(1)
// 		go func(ind int) {
// 			defer wg.Done()
// 			msg := &network.NetMessage{
// 				Msg: &core.EchoMsg{
// 					Author:   1,
// 					Proposer: 1,
// 				},
// 				Address: []string{addr},
// 			}
// 			sender.Send(msg)
// 		}(i)
// 	}

// 	for i := 0; i < 10; i++ {
// 		msg := receiver.Recv().(*core.EchoMsg)
// 		t.Logf("Messsage type: %d Data: %#v\n", msg.MsgType(), msg)
// 	}
// 	wg.Wait()
// }

// MockMsg 是实现 Messgae 接口的 mock 类型
// type MockMsg struct {
// 	Data string
// }

// func (m MockMsg) Encode() ([]byte, error) {
// 	return []byte(m.Data), nil
// }
// func (m MockMsg) Decode(data []byte) error {
// 	m.Data = string(data)
// 	return nil
// }

// // MockCodec 是一个假的 Codec，用于测试
// type MockCodec struct{}

// func (c *MockCodec) Bind(conn net.Conn) *network.Codec {
// 	return &network.Codec{Conn: conn}
// }

// func startReceiver(t *testing.T, addr string, cc *network.Codec, recvCh chan network.Messgae, stopCh <-chan struct{}) {
// 	receiver := network.NewReceiver(addr, cc)
// 	go func() {
// 		receiver.Run()
// 	}()

// 	// 转发消息到测试用通道
// 	go func() {
// 		for {
// 			select {
// 			case msg := <-receiver.RecvChannel():
// 				recvCh <- msg
// 			case <-stopCh:
// 				return
// 			}
// 		}
// 	}()
// }

// func TestNetwork(t *testing.T) {
// 	addr := "127.0.0.1:9100"
// 	cc := &MockCodec{}

// 	recvCh := make(chan network.Messgae, 100)
// 	stopCh := make(chan struct{})
// 	defer close(stopCh)

// 	// 启动 Receiver
// 	startReceiver(t, addr, cc, recvCh, stopCh)
// 	time.Sleep(500 * time.Millisecond)

// 	// 启动 Sender
// 	sender := NewSender(cc)
// 	go sender.Run()

// 	// 发送一条消息
// 	sender.Send(&network.NetMessage{
// 		Msg:     MockMsg{Data: "hello"},
// 		Address: []string{addr},
// 	})

// 	select {
// 	case msg := <-recvCh:
// 		m := msg.(MockMsg)
// 		if m.Data != "hello" {
// 			t.Errorf("expected 'hello', got '%s'", m.Data)
// 		}
// 	case <-time.After(2 * time.Second):
// 		t.Fatal("did not receive message")
// 	}

// 	// 模拟 Receiver 重启
// 	t.Log("restarting receiver...")
// 	close(stopCh)
// 	time.Sleep(500 * time.Millisecond)

// 	newRecvCh := make(chan network.Messgae, 100)
// 	newStopCh := make(chan struct{})
// 	defer close(newStopCh)
// 	startReceiver(t, addr, cc, newRecvCh, newStopCh)
// 	time.Sleep(500 * time.Millisecond)

// 	// 再发一次消息，测试 Sender 重连能力
// 	sender.Send(&network.NetMessage{
// 		Msg:     MockMsg{Data: "after restart"},
// 		Address: []string{addr},
// 	})

// 	select {
// 	case msg := <-newRecvCh:
// 		m := msg.(MockMsg)
// 		if m.Data != "after restart" {
// 			t.Errorf("expected 'after restart', got '%s'", m.Data)
// 		}
// 	case <-time.After(2 * time.Second):
// 		t.Fatal("did not receive message after restart")
// 	}

// 	// 并发发送测试
// 	t.Log("running concurrent senders")
// 	var wg sync.WaitGroup
// 	for i := 0; i < 5; i++ {
// 		wg.Add(1)
// 		go func(id int) {
// 			defer wg.Done()
// 			localSender := network.NewSender(cc)
// 			go localSender.Run()
// 			localSender.Send(&network.NetMessage{
// 				Msg:     MockMsg{Data: "msg from sender"},
// 				Address: []string{addr},
// 			})
// 		}(i)
// 	}
// 	wg.Wait()

// 	timeout := time.After(2 * time.Second)
// 	count := 0
// 	for count < 5 {
// 		select {
// 		case <-newRecvCh:
// 			count++
// 		case <-timeout:
// 			t.Fatalf("expected 5 messages, got %d", count)
// 		}
// 	}
// }
