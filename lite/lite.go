// Package lite exposes Core's WendyCom client, SensorLink audio and firmware
// catalog. Hosts retain connection setup, framing, TLS, prompts and files.
package lite

import (
	"context"

	core "github.com/wendylabsinc/WendyOS/go/wendy-core/core/lite"
	wendy "github.com/wendylabsinc/wendy-go"
	"github.com/wendylabsinc/wendy-go/lite/pb"
)

// Client drives one connection; Close is terminal. Connect takes a host LiteLink.
type Client = core.Client

// DeviceIdentity contains the firmware-reported device identifier and names.
type DeviceIdentity = core.DeviceIdentity

// DeviceInfo reports firmware and supported application formats.
type DeviceInfo = core.DeviceInfo

// AppType selects a WASM or native image.
type AppType = core.AppType

// ConfPushMode selects replacement or update of the device configuration.
type ConfPushMode = core.ConfPushMode

// ConsoleChunk is console output; Gap marks dropped bytes.
type ConsoleChunk = core.ConsoleChunk

// SensorFrame contains a reassembled frame and its first chunk's timestamp.
type SensorFrame = core.SensorFrame

// Assembler reassembles bounded SensorLink frames; it is not concurrent-safe.
type Assembler = core.Assembler

// AudioClient supplies sensor subscriptions and connection lifecycle.
type AudioClient = core.AudioClient

// AudioOptions selects a microphone and its native format.
type AudioOptions = core.AudioOptions

// AudioChunk is owned PCM S16LE audio and its format and timestamp.
type AudioChunk = core.AudioChunk

// AudioStream reassembles microphone frames with a bounded latency queue.
type AudioStream = core.AudioStream

// WendyLiteBoard pairs an installable board with its chip and firmware.
type WendyLiteBoard = core.WendyLiteBoard

// WendyLiteTarget is a supported ESP32 chip family.
type WendyLiteTarget = core.WendyLiteTarget

// Firmware describes published versions for a catalog binary.
type Firmware = core.Firmware

// Protocol flags, image formats and configuration modes retain Core's values.
const (
	AppTypeWasm         = core.AppTypeWasm
	AppTypeNative       = core.AppTypeNative
	ConfPushModeReplace = core.ConfPushModeReplace
	ConfPushModeUpdate  = core.ConfPushModeUpdate
	FlagKeyframe        = core.FlagKeyframe
	FlagLastChunk       = core.FlagLastChunk
	MaxFrameBytes       = core.MaxFrameBytes
)

// NewClient creates a single-use client with host-provided handshake entropy.
func NewClient(entropy wendy.Entropy) *Client { return core.NewClient(entropy) }

// AudioChannels returns manifest entries describing microphones.
func AudioChannels(manifest *pb.SensorManifest) []*pb.SensorDescriptor {
	return core.AudioChannels(manifest)
}

// SelectAudio selects a PCM S16LE microphone matching the requested format.
func SelectAudio(manifest *pb.SensorManifest, opts AudioOptions) (*pb.SensorDescriptor, error) {
	return core.SelectAudio(manifest, opts)
}

// SubscribeAudio starts a microphone subscription; Close releases it.
func SubscribeAudio(ctx context.Context, client AudioClient, ch *pb.SensorDescriptor) (*AudioStream, error) {
	return core.SubscribeAudio(ctx, client, ch)
}

// WendyLiteBoards returns installable boards in catalog order.
func WendyLiteBoards() ([]WendyLiteBoard, error) { return core.WendyLiteBoards() }

// WendyLiteTargets returns chip families in catalog order.
func WendyLiteTargets() ([]WendyLiteTarget, error) { return core.WendyLiteTargets() }

// WendyLiteFirmwareID returns the published firmware identifier for a board.
func WendyLiteFirmwareID(board string) (string, error) { return core.WendyLiteFirmwareID(board) }

// WendyLiteTargetForBoard returns the chip family for a board.
func WendyLiteTargetForBoard(board string) (string, error) {
	return core.WendyLiteTargetForBoard(board)
}

// BoardsWithFirmware filters boards to a published channel.
func BoardsWithFirmware(boards []WendyLiteBoard, firmware map[string]Firmware, nightly bool) []WendyLiteBoard {
	return core.BoardsWithFirmware(boards, firmware, nightly)
}
