package cloud_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	wendy "github.com/wendylabsinc/wendy-go"
	"github.com/wendylabsinc/wendy-go/cloud"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const inboxService = "/wendycloud.v2.NotificationService/"
const notificationID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
const olderID = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"

// The host owns session resolution and authenticates each physical RPC, including
// Core's internal batches/continuations. This fake host uses only WendyGo APIs.
type inboxTransport struct {
	wendy.Transport
	authorize func(context.Context, wendy.RPCRequest) (wendy.Metadata, error)
}

func (h inboxTransport) Unary(ctx context.Context, request wendy.RPCRequest) (wendy.RPCResponse, error) {
	md, err := h.authorize(ctx, request)
	if err != nil {
		return wendy.RPCResponse{}, err
	}
	request.Metadata = md
	return h.Transport.Unary(ctx, request)
}

func inboxClient(t *testing.T, handle func(grpc.ServerStream, string, []byte) error) *cloud.Client {
	t.Helper()
	key, signer := operator(t)
	var mu sync.Mutex
	nonces := map[string]bool{}
	transport := rpcTransport(t, func(stream grpc.ServerStream, method string, wire []byte) error {
		md, _ := metadata.FromIncomingContext(stream.Context())
		if len(md.Get("authorization")) != 1 || len(md.Get("dpop")) != 1 || md.Get("authorization")[0] != "DPoP inbox-token" {
			return fmt.Errorf("missing or duplicate auth metadata")
		}
		_, claims := verifyJWS(t, key, []byte(md.Get("dpop")[0]))
		digest := sha256.Sum256([]byte("inbox-token"))
		nonce, _ := claims["jti"].(string)
		mu.Lock()
		reused := nonces[nonce]
		nonces[nonce] = true
		mu.Unlock()
		if nonce == "" || reused || claims["htm"] != "POST" || claims["htu"] != "https://cloud.example.test:443"+method || claims["ath"] != base64.RawURLEncoding.EncodeToString(digest[:]) {
			return fmt.Errorf("stale or incorrectly bound proof for %s", method)
		}
		if !reflect.DeepEqual(md.Get("x-correlation-id"), []string{"inbox-flow"}) {
			return fmt.Errorf("lost host metadata")
		}
		return handle(stream, strings.TrimPrefix(method, inboxService), wire)
	})
	return &cloud.Client{Transport: inboxTransport{Transport: transport, authorize: func(ctx context.Context, request wendy.RPCRequest) (wendy.Metadata, error) {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 10*time.Second {
			return nil, fmt.Errorf("missing per-RPC timeout")
		}
		// A real host resolves/refreshes the Cloud-resource token and its bound key
		// here, before producing fresh metadata for request.Method.
		return cloud.AuthenticationMetadata(ctx, wendy.CryptoEntropy{}, "cloud.example.test:443", request.Method, "inbox-token", signer, append(request.Metadata,
			wendy.MetadataEntry{Name: "authorization", Value: []byte("stale")},
			wendy.MetadataEntry{Name: "dpop", Value: []byte("stale")},
			wendy.MetadataEntry{Name: "x-correlation-id", Value: []byte("inbox-flow")}))
	}}}
}

func TestNotificationReadsThroughPublicFacade(t *testing.T) {
	severity, read := cloud.NotificationSeverityWarning, cloud.NotificationRead
	now := time.Unix(1730000000, 123000000).UTC()
	timestamp, _ := proto.Marshal(timestamppb.New(now))
	metadataValue, _ := structpb.NewStruct(map[string]any{"source": "robot", "count": float64(2), "active": true, "empty": nil, "nested": map[string]any{"items": []any{"one", float64(2)}}})
	metadataWire, _ := proto.Marshal(metadataValue)
	row := inboxBytes(nil, 3, []byte(tenant))
	row = inboxBytes(row, 4, []byte("body"))
	row = inboxInt(row, 5, uint64(severity))
	row = inboxBytes(row, 7, timestamp)
	row = inboxBytes(row, 9, []byte("title"))
	row = inboxBytes(row, 10, []byte("wendy://notifications/"+notificationID))
	row = inboxBytes(row, 11, []byte(strings.ToUpper(notificationID)))
	row = inboxBytes(row, 12, metadataWire)
	row = inboxBytes(row, 17, timestamp)
	// Inactive rich fields cannot alter the basic model.
	for _, tag := range []protowire.Number{18, 19, 21} {
		row = inboxBytes(row, tag, nil)
	}
	listCalls := 0
	client := inboxClient(t, func(stream grpc.ServerStream, method string, wire []byte) error {
		fields := inboxFields(t, wire)
		switch method {
		case "GetNotification":
			wantInboxFields(t, fields, map[protowire.Number][]any{2: {notificationID}})
			return stream.SendMsg(row)
		case "ListNotificationsV2":
			listCalls++
			limit := uint64(30)
			if listCalls == 2 {
				limit = 5
			}
			wantInboxFields(t, fields, map[protowire.Number][]any{1: {tenant}, 2: {notificationID}, 3: {olderID}, 4: {limit}, 5: {uint64(severity)}, 6: {uint64(read)}})
			return stream.SendMsg(inboxInt(inboxBytes(nil, 1, row), 2, 1))
		case "CountNotifications":
			wantInboxFields(t, fields, map[protowire.Number][]any{1: {tenant}, 2: {uint64(severity)}, 3: {uint64(read)}})
			return stream.SendMsg(inboxInt(nil, 1, 42))
		default:
			return fmt.Errorf("unexpected method %s", method)
		}
	})
	n, err := client.GetNotification(context.Background(), strings.ToUpper(notificationID))
	if err != nil {
		t.Fatal(err)
	}
	want := cloud.Notification{ID: notificationID, OrganizationID: tenant, Title: "title", Body: "body", Severity: severity, DeepLink: "wendy://notifications/" + notificationID, Metadata: metadataValue.AsMap(), CreatedAt: &now, ReadAt: &now}
	if !reflect.DeepEqual(*n, want) || n.ReadStatus() != read {
		t.Fatalf("model changed: %+v", n)
	}
	if (cloud.Notification{}).ReadStatus() != cloud.NotificationUnread {
		t.Fatal("absent read timestamp is not unread")
	}
	query := cloud.NotificationQuery{Severity: &severity, ReadStatus: &read}
	limit := 5
	for _, limit := range []*int{nil, &limit} {
		batch, err := client.ListNotifications(context.Background(), tenant, query, cloud.NotificationPage{BeforeID: notificationID, AfterID: olderID, Limit: limit})
		if err != nil || batch == nil || !batch.HasMore || !reflect.DeepEqual(batch.Notifications, []cloud.Notification{want}) {
			t.Fatalf("list: %+v, %v", batch, err)
		}
	}
	count, err := client.CountNotifications(context.Background(), tenant, query)
	if err != nil || count != 42 {
		t.Fatalf("count %d: %v", count, err)
	}
}

func TestNotificationIDBatches(t *testing.T) {
	for _, read := range []bool{false, true} {
		for _, size := range []int{0, 1, 200, 201} {
			t.Run(fmt.Sprintf("read=%t/ids=%d", read, size), func(t *testing.T) {
				ids := make([]string, size)
				for i := range ids {
					ids[i] = fmt.Sprintf("%08x-2222-4333-8444-555555555555", i+1)
				}
				calls := 0
				client := inboxClient(t, func(stream grpc.ServerStream, method string, wire []byte) error {
					start := calls * 200
					calls++
					want := map[protowire.Number][]any{1: {}}
					for _, id := range ids[start:min(start+200, size)] {
						want[1] = append(want[1], id)
					}
					expectedMethod := "DeleteNotifications"
					if read {
						expectedMethod = "SetNotificationReadStatus"
						want[2] = []any{uint64(cloud.NotificationUnread)}
					}
					if method != expectedMethod {
						return fmt.Errorf("wrong method %s", method)
					}
					wantInboxFields(t, inboxFields(t, wire), want)
					count := len(want[1])
					if read {
						count = 0
					} // updated_count is not a success Boolean.
					return stream.SendMsg(inboxInt(nil, 1, uint64(count)))
				})
				var err error
				if read {
					err = client.SetNotificationReadStatus(context.Background(), cloud.NotificationUnread, ids)
				} else {
					var count int
					count, err = client.DeleteNotifications(context.Background(), ids)
					if count != size {
						t.Fatalf("changed count %d, want %d", count, size)
					}
				}
				if err != nil || calls != (size+199)/200 {
					t.Fatalf("calls=%d: %v", calls, err)
				}
			})
		}
	}
}

func TestNotificationThroughContinuation(t *testing.T) {
	for _, read := range []bool{false, true} {
		t.Run(fmt.Sprint("read=", read), func(t *testing.T) {
			calls := 0
			severity := cloud.NotificationSeverityCritical
			client := inboxClient(t, func(stream grpc.ServerStream, method string, wire []byte) error {
				calls++
				want := map[protowire.Number][]any{1: {tenant}, 2: {uint64(severity)}, 3: {notificationID}}
				expectedMethod := "DeleteNotificationsThrough"
				if read {
					expectedMethod = "SetNotificationReadStatusThrough"
					want[3] = []any{uint64(cloud.NotificationRead)}
					want[4] = []any{notificationID}
				}
				if method != expectedMethod || calls > 2 {
					return fmt.Errorf("unexpected continuation %s (%d)", method, calls)
				}
				wantInboxFields(t, inboxFields(t, wire), want)
				if calls == 1 {
					return stream.SendMsg(inboxInt(inboxInt(nil, 1, 1000), 2, 1))
				}
				return stream.SendMsg(inboxInt(nil, 1, 7)) // Absent tag 2 means no more.
			})
			var count int
			var err error
			if read {
				count, err = client.SetNotificationReadStatusThrough(context.Background(), cloud.NotificationRead, tenant, notificationID, &severity)
			} else {
				count, err = client.DeleteNotificationsThrough(context.Background(), tenant, notificationID, &severity)
			}
			if err != nil || count != 1007 || calls != 2 {
				t.Fatalf("count=%d calls=%d: %v", count, calls, err)
			}
		})
	}
}

func TestNotificationFailureStopsMutations(t *testing.T) {
	for _, through := range []bool{false, true} {
		for _, read := range []bool{false, true} {
			t.Run(fmt.Sprintf("through=%t/read=%t", through, read), func(t *testing.T) {
				calls := 0
				client := inboxClient(t, func(stream grpc.ServerStream, _ string, _ []byte) error {
					calls++
					if calls == 1 {
						return stream.SendMsg(inboxInt(inboxInt(nil, 1, 1), 2, 1))
					}
					stream.SetTrailer(metadata.Pairs("x-correlation-id", "inbox-denied"))
					return status.Error(codes.PermissionDenied, "inbox denied")
				})
				ids := make([]string, 401)
				for i := range ids {
					ids[i] = notificationID
				}
				count, err := mutateInbox(context.Background(), client, through, read, ids)
				var rpc *wendy.RPCStatusError
				if count != 0 || calls != 2 || !errors.As(err, &rpc) || rpc.Code != wendy.RPCPermissionDenied || status.Code(rpc.Cause) != codes.PermissionDenied || rpc.Message != "inbox denied" || inboxMetadata(rpc.TrailingMetadata, "x-correlation-id") != "inbox-denied" {
					t.Fatalf("count=%d calls=%d status lost: %v (%#v)", count, calls, err, rpc)
				}
			})
		}
	}
}

func TestNotificationCancellationStopsMutations(t *testing.T) {
	for _, through := range []bool{false, true} {
		for _, read := range []bool{false, true} {
			t.Run(fmt.Sprintf("through=%t/read=%t", through, read), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := 0
				client := inboxClient(t, func(stream grpc.ServerStream, _ string, _ []byte) error {
					calls++
					return stream.SendMsg(inboxInt(inboxInt(nil, 1, 1), 2, 1))
				})
				client.Transport = cancelInboxTransport{Transport: client.Transport, cancel: cancel}
				ids := make([]string, 201)
				for i := range ids {
					ids[i] = notificationID
				}
				count, err := mutateInbox(ctx, client, through, read, ids)
				var rpc *wendy.RPCStatusError
				canceled := errors.Is(err, context.Canceled) || (errors.As(err, &rpc) && rpc.Code == wendy.RPCCanceled)
				if count != 0 || calls != 1 || !canceled {
					t.Fatalf("count=%d calls=%d cancellation lost: %v", count, calls, err)
				}
			})
		}
	}
}

func mutateInbox(ctx context.Context, client *cloud.Client, through, read bool, ids []string) (int, error) {
	if through {
		if read {
			return client.SetNotificationReadStatusThrough(ctx, cloud.NotificationRead, tenant, notificationID, nil)
		}
		return client.DeleteNotificationsThrough(ctx, tenant, notificationID, nil)
	}
	if read {
		return 0, client.SetNotificationReadStatus(ctx, cloud.NotificationRead, ids)
	}
	return client.DeleteNotifications(ctx, ids)
}

func TestNotificationErrorsThroughPublicFacade(t *testing.T) {
	client := inboxClient(t, func(stream grpc.ServerStream, _ string, _ []byte) error {
		stream.SetTrailer(metadata.Pairs("x-correlation-id", "timeout-flow"))
		return status.Error(codes.DeadlineExceeded, "host deadline")
	})
	_, err := client.GetNotification(context.Background(), notificationID)
	var inbox *cloud.NotificationError
	var rpc *wendy.RPCStatusError
	if !errors.As(err, &inbox) || inbox.Kind != cloud.NotificationTimedOut || !errors.As(err, &rpc) || rpc.Code != wendy.RPCDeadlineExceeded || status.Code(rpc.Cause) != codes.DeadlineExceeded || inboxMetadata(rpc.TrailingMetadata, "x-correlation-id") != "timeout-flow" {
		t.Fatalf("timeout cause lost: %v (%#v)", err, rpc)
	}
	// Invalid requests and empty mutations return before reaching any host.
	local := &cloud.Client{}
	_, err = local.GetNotification(context.Background(), "invalid")
	if !errors.As(err, &inbox) || inbox.Kind != cloud.NotificationInvalidID {
		t.Fatalf("validation error lost: %v", err)
	}
	if count, err := local.DeleteNotifications(context.Background(), nil); count != 0 || err != nil {
		t.Fatalf("empty delete: %d %v", count, err)
	}
	if err := local.SetNotificationReadStatus(context.Background(), 0, nil); err != nil {
		t.Fatalf("empty read: %v", err)
	}
}

func inboxBytes(wire []byte, tag protowire.Number, value []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(wire, tag, protowire.BytesType), value)
}
func inboxInt(wire []byte, tag protowire.Number, value uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(wire, tag, protowire.VarintType), value)
}
func inboxFields(t *testing.T, wire []byte) map[protowire.Number][]any {
	t.Helper()
	fields := map[protowire.Number][]any{}
	for len(wire) > 0 {
		tag, kind, n := protowire.ConsumeTag(wire)
		if n < 0 {
			t.Error(protowire.ParseError(n))
			return nil
		}
		wire = wire[n:]
		var value any
		switch kind {
		case protowire.BytesType:
			var b []byte
			b, n = protowire.ConsumeBytes(wire)
			value = string(b)
		case protowire.VarintType:
			value, n = protowire.ConsumeVarint(wire)
		default:
			t.Errorf("unexpected wire kind %v", kind)
			return nil
		}
		if n < 0 {
			t.Error(protowire.ParseError(n))
			return nil
		}
		fields[tag] = append(fields[tag], value)
		wire = wire[n:]
	}
	return fields
}
func wantInboxFields(t *testing.T, got, want map[protowire.Number][]any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("typed request fields changed: got %v, want %v", got, want)
	}
}

// Cancel after a successful host response, before Core can start another batch.
type cancelInboxTransport struct {
	wendy.Transport
	cancel context.CancelFunc
}

func (h cancelInboxTransport) Unary(ctx context.Context, request wendy.RPCRequest) (wendy.RPCResponse, error) {
	response, err := h.Transport.Unary(ctx, request)
	h.cancel()
	return response, err
}
func inboxMetadata(md wendy.Metadata, name string) string {
	for _, entry := range md {
		if entry.Name == name {
			return string(entry.Value)
		}
	}
	return ""
}
