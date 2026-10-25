package lite_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wendy "github.com/wendylabsinc/wendy-go"
	"github.com/wendylabsinc/wendy-go/lite"
	"github.com/wendylabsinc/wendy-go/lite/pb"
	"google.golang.org/protobuf/proto"
)

type fakeLink struct {
	messages   chan []byte
	done       chan struct{}
	once       sync.Once
	closed     atomic.Int32
	result     pb.WendyComResult
	badVersion bool
}

var _ wendy.LiteLink = (*fakeLink)(nil)

func newLink() *fakeLink {
	return &fakeLink{messages: make(chan []byte, 16), done: make(chan struct{})}
}
func (*fakeLink) Handshake() error        { return nil }
func (*fakeLink) PreferredChunkSize() int { return 1024 }
func (l *fakeLink) Close() error          { l.once.Do(func() { l.closed.Add(1); close(l.done) }); return nil }
func (l *fakeLink) Send(data []byte) error {
	req := new(pb.WendyComMessage)
	if err := proto.Unmarshal(data, req); err != nil {
		return err
	}
	var response *pb.WendyComMessage
	if h := req.GetHandshake(); h != nil {
		if l.badVersion {
			h.Version.Major++
		}
		response = &pb.WendyComMessage{Msg: &pb.WendyComMessage_Handshake{Handshake: h}}
	} else if c := req.GetCommand(); c != nil {
		response = &pb.WendyComMessage{Msg: &pb.WendyComMessage_Response{Response: &pb.WendyComResponse{RequestId: c.RequestId, Result: l.result}}}
	} else {
		return errors.New("unexpected request")
	}
	encoded, err := proto.Marshal(response)
	if err != nil {
		return err
	}
	select {
	case l.messages <- encoded:
		return nil
	case <-l.done:
		return io.EOF
	}
}
func (l *fakeLink) Receive(timeout time.Duration) ([]byte, error) {
	var deadline <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		deadline = timer.C
	}
	select {
	case data := <-l.messages:
		return data, nil
	case <-l.done:
		return nil, io.EOF
	case <-deadline:
		return nil, context.DeadlineExceeded
	}
}

func TestClientThroughInjectedLink(t *testing.T) {
	link := newLink()
	client := lite.NewClient(wendy.CryptoEntropy{})
	if err := client.Connect(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := client.Ping(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.Done():
	default:
		t.Fatal("closing client did not terminate dispatch")
	}
	if link.closed.Load() != 1 {
		t.Fatal("host link closed more than once")
	}
}

func TestClientHandshakeAndRemoteErrors(t *testing.T) {
	bad := newLink()
	bad.badVersion = true
	client := lite.NewClient(wendy.CryptoEntropy{})
	if err := client.Connect(context.Background(), bad); err == nil || bad.closed.Load() != 1 {
		t.Fatalf("handshake failure did not close link: %v", err)
	}
	busy := newLink()
	busy.result = pb.WendyComResult_WENDY_COM_RESULT_BUSY
	client = lite.NewClient(wendy.CryptoEntropy{})
	if err := client.Connect(context.Background(), busy); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Ping(); err == nil {
		t.Fatal("remote busy result was lost")
	}
	canceled := newLink()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := lite.NewClient(wendy.CryptoEntropy{}).Connect(ctx, canceled); !errors.Is(err, context.Canceled) || canceled.closed.Load() != 1 {
		t.Fatalf("cancellation did not close host link: %v", err)
	}
}

func TestPublicSensorTypesAndCatalog(t *testing.T) {
	var asm lite.Assembler
	frame := asm.Add(&pb.SensorData{ChannelId: 1, FrameSeq: 2, Flags: lite.FlagLastChunk, Payload: []byte{1, 2}})
	if frame == nil || frame.ChannelID != 1 || frame.Seq != 2 {
		t.Fatalf("sensor wire alias failed: %+v", frame)
	}
	manifest := &pb.SensorManifest{Sensors: []*pb.SensorDescriptor{{ChannelId: 1, Format: &pb.SensorDescriptor_Audio{Audio: &pb.AudioFormat{Codec: pb.AudioFormat_PCM_S16LE, SampleRate: 48000, Channels: 1}}}}}
	audio, err := lite.SelectAudio(manifest, lite.AudioOptions{ID: 1, IDSet: true})
	if err != nil || audio.GetChannelId() != 1 {
		t.Fatalf("audio wire alias failed: %v", err)
	}
	boards, err := lite.WendyLiteBoards()
	if err != nil || len(boards) == 0 {
		t.Fatalf("catalog: %v", err)
	}
	if _, err = lite.WendyLiteFirmwareID(boards[0].Board); err != nil {
		t.Fatal(err)
	}
}
