// Package pb exposes Core's Lite wire types without registering duplicate
// protobuf descriptors. Hosts can retain their own generated protobuf types.
package pb

import core "github.com/wendylabsinc/WendyOS/go/wendy-core/core/lite/pb"

// VideoFormat_Codec is Core's Lite wire type.
type VideoFormat_Codec = core.VideoFormat_Codec

// AudioFormat_Codec is Core's Lite wire type.
type AudioFormat_Codec = core.AudioFormat_Codec

// VideoFormat is Core's Lite wire type.
type VideoFormat = core.VideoFormat

// AudioFormat is Core's Lite wire type.
type AudioFormat = core.AudioFormat

// SensorFormat is Core's Lite wire type.
type SensorFormat = core.SensorFormat

// SensorDescriptor is Core's Lite wire type.
type SensorDescriptor = core.SensorDescriptor

// SensorDescriptor_Video is Core's Lite wire type.
type SensorDescriptor_Video = core.SensorDescriptor_Video

// SensorDescriptor_Audio is Core's Lite wire type.
type SensorDescriptor_Audio = core.SensorDescriptor_Audio

// SensorDescriptor_Sensor is Core's Lite wire type.
type SensorDescriptor_Sensor = core.SensorDescriptor_Sensor

// SensorManifest is Core's Lite wire type.
type SensorManifest = core.SensorManifest

// GetSensorManifest is Core's Lite wire type.
type GetSensorManifest = core.GetSensorManifest

// Subscribe is Core's Lite wire type.
type Subscribe = core.Subscribe

// Unsubscribe is Core's Lite wire type.
type Unsubscribe = core.Unsubscribe

// SensorData is Core's Lite wire type.
type SensorData = core.SensorData

// Ping is Core's Lite wire type.
type Ping = core.Ping

// Envelope is Core's Lite wire type.
type Envelope = core.Envelope

// Envelope_Manifest is Core's Lite wire type.
type Envelope_Manifest = core.Envelope_Manifest

// Envelope_Subscribe is Core's Lite wire type.
type Envelope_Subscribe = core.Envelope_Subscribe

// Envelope_Data is Core's Lite wire type.
type Envelope_Data = core.Envelope_Data

// Envelope_Ping is Core's Lite wire type.
type Envelope_Ping = core.Envelope_Ping

// WendyComAppType is Core's Lite wire type.
type WendyComAppType = core.WendyComAppType

// WendyComConfPushMode is Core's Lite wire type.
type WendyComConfPushMode = core.WendyComConfPushMode

// WendyComConsoleIo is Core's Lite wire type.
type WendyComConsoleIo = core.WendyComConsoleIo

// WendyComResult is Core's Lite wire type.
type WendyComResult = core.WendyComResult

// WendyComChannelErrorReason is Core's Lite wire type.
type WendyComChannelErrorReason = core.WendyComChannelErrorReason

// WendyComProtocolVersion is Core's Lite wire type.
type WendyComProtocolVersion = core.WendyComProtocolVersion

// WendyComHandshake is Core's Lite wire type.
type WendyComHandshake = core.WendyComHandshake

// WendyComPingParams is Core's Lite wire type.
type WendyComPingParams = core.WendyComPingParams

// WendyComRebootParams is Core's Lite wire type.
type WendyComRebootParams = core.WendyComRebootParams

// WendyComAppPushBeginParams is Core's Lite wire type.
type WendyComAppPushBeginParams = core.WendyComAppPushBeginParams

// WendyComAppPushDataParams is Core's Lite wire type.
type WendyComAppPushDataParams = core.WendyComAppPushDataParams

// WendyComAppPushEndParams is Core's Lite wire type.
type WendyComAppPushEndParams = core.WendyComAppPushEndParams

// WendyComAppStartParams is Core's Lite wire type.
type WendyComAppStartParams = core.WendyComAppStartParams

// WendyComAppStopParams is Core's Lite wire type.
type WendyComAppStopParams = core.WendyComAppStopParams

// WendyComConfPushBeginParams is Core's Lite wire type.
type WendyComConfPushBeginParams = core.WendyComConfPushBeginParams

// WendyComConfPushDataParams is Core's Lite wire type.
type WendyComConfPushDataParams = core.WendyComConfPushDataParams

// WendyComConfPushEndParams is Core's Lite wire type.
type WendyComConfPushEndParams = core.WendyComConfPushEndParams

// WendyComGetDeviceIdentityParams is Core's Lite wire type.
type WendyComGetDeviceIdentityParams = core.WendyComGetDeviceIdentityParams

// WendyComDeviceIdentity is Core's Lite wire type.
type WendyComDeviceIdentity = core.WendyComDeviceIdentity

// WendyComGetDeviceInfoParams is Core's Lite wire type.
type WendyComGetDeviceInfoParams = core.WendyComGetDeviceInfoParams

// WendyComEnrollmentChallengeParams is Core's Lite wire type.
type WendyComEnrollmentChallengeParams = core.WendyComEnrollmentChallengeParams

// WendyComEnrollmentChallenge is Core's Lite wire type.
type WendyComEnrollmentChallenge = core.WendyComEnrollmentChallenge

// WendyComEnrollmentResetParams is Core's Lite wire type.
type WendyComEnrollmentResetParams = core.WendyComEnrollmentResetParams

// WendyComSyncTimeParams is Core's Lite wire type.
type WendyComSyncTimeParams = core.WendyComSyncTimeParams

// WendyComSyncTimeResult is Core's Lite wire type.
type WendyComSyncTimeResult = core.WendyComSyncTimeResult

// WendyComConsoleAttachParams is Core's Lite wire type.
type WendyComConsoleAttachParams = core.WendyComConsoleAttachParams

// WendyComConsoleDetachParams is Core's Lite wire type.
type WendyComConsoleDetachParams = core.WendyComConsoleDetachParams

// WendyComConsoleBegin is Core's Lite wire type.
type WendyComConsoleBegin = core.WendyComConsoleBegin

// WendyComConsoleData is Core's Lite wire type.
type WendyComConsoleData = core.WendyComConsoleData

// WendyComConsoleEnd is Core's Lite wire type.
type WendyComConsoleEnd = core.WendyComConsoleEnd

// WendyComDeviceInfo is Core's Lite wire type.
type WendyComDeviceInfo = core.WendyComDeviceInfo

// WendyComCommand is Core's Lite wire type.
type WendyComCommand = core.WendyComCommand

// WendyComCommand_Ping is Core's Lite wire type.
type WendyComCommand_Ping = core.WendyComCommand_Ping

// WendyComCommand_Reboot is Core's Lite wire type.
type WendyComCommand_Reboot = core.WendyComCommand_Reboot

// WendyComCommand_AppPushBegin is Core's Lite wire type.
type WendyComCommand_AppPushBegin = core.WendyComCommand_AppPushBegin

// WendyComCommand_AppPushData is Core's Lite wire type.
type WendyComCommand_AppPushData = core.WendyComCommand_AppPushData

// WendyComCommand_AppPushEnd is Core's Lite wire type.
type WendyComCommand_AppPushEnd = core.WendyComCommand_AppPushEnd

// WendyComCommand_AppStart is Core's Lite wire type.
type WendyComCommand_AppStart = core.WendyComCommand_AppStart

// WendyComCommand_AppStop is Core's Lite wire type.
type WendyComCommand_AppStop = core.WendyComCommand_AppStop

// WendyComCommand_GetDeviceIdentity is Core's Lite wire type.
type WendyComCommand_GetDeviceIdentity = core.WendyComCommand_GetDeviceIdentity

// WendyComCommand_GetDeviceInfo is Core's Lite wire type.
type WendyComCommand_GetDeviceInfo = core.WendyComCommand_GetDeviceInfo

// WendyComCommand_ConsoleAttach is Core's Lite wire type.
type WendyComCommand_ConsoleAttach = core.WendyComCommand_ConsoleAttach

// WendyComCommand_ConsoleDetach is Core's Lite wire type.
type WendyComCommand_ConsoleDetach = core.WendyComCommand_ConsoleDetach

// WendyComCommand_ConfPushBegin is Core's Lite wire type.
type WendyComCommand_ConfPushBegin = core.WendyComCommand_ConfPushBegin

// WendyComCommand_ConfPushData is Core's Lite wire type.
type WendyComCommand_ConfPushData = core.WendyComCommand_ConfPushData

// WendyComCommand_ConfPushEnd is Core's Lite wire type.
type WendyComCommand_ConfPushEnd = core.WendyComCommand_ConfPushEnd

// WendyComCommand_SensorLinkGetManifest is Core's Lite wire type.
type WendyComCommand_SensorLinkGetManifest = core.WendyComCommand_SensorLinkGetManifest

// WendyComCommand_SensorLinkSubscribe is Core's Lite wire type.
type WendyComCommand_SensorLinkSubscribe = core.WendyComCommand_SensorLinkSubscribe

// WendyComCommand_SensorLinkUnsubscribe is Core's Lite wire type.
type WendyComCommand_SensorLinkUnsubscribe = core.WendyComCommand_SensorLinkUnsubscribe

// WendyComCommand_EnrollmentChallenge is Core's Lite wire type.
type WendyComCommand_EnrollmentChallenge = core.WendyComCommand_EnrollmentChallenge

// WendyComCommand_SyncTime is Core's Lite wire type.
type WendyComCommand_SyncTime = core.WendyComCommand_SyncTime

// WendyComCommand_EnrollmentReset is Core's Lite wire type.
type WendyComCommand_EnrollmentReset = core.WendyComCommand_EnrollmentReset

// WendyComResponse is Core's Lite wire type.
type WendyComResponse = core.WendyComResponse

// WendyComResponse_DeviceIdentity is Core's Lite wire type.
type WendyComResponse_DeviceIdentity = core.WendyComResponse_DeviceIdentity

// WendyComResponse_DeviceInfo is Core's Lite wire type.
type WendyComResponse_DeviceInfo = core.WendyComResponse_DeviceInfo

// WendyComResponse_SensorLinkManifest is Core's Lite wire type.
type WendyComResponse_SensorLinkManifest = core.WendyComResponse_SensorLinkManifest

// WendyComResponse_EnrollmentChallenge is Core's Lite wire type.
type WendyComResponse_EnrollmentChallenge = core.WendyComResponse_EnrollmentChallenge

// WendyComResponse_SyncTime is Core's Lite wire type.
type WendyComResponse_SyncTime = core.WendyComResponse_SyncTime

// WendyComEvent is Core's Lite wire type.
type WendyComEvent = core.WendyComEvent

// WendyComEvent_ConsoleBegin is Core's Lite wire type.
type WendyComEvent_ConsoleBegin = core.WendyComEvent_ConsoleBegin

// WendyComEvent_ConsoleData is Core's Lite wire type.
type WendyComEvent_ConsoleData = core.WendyComEvent_ConsoleData

// WendyComEvent_ConsoleEnd is Core's Lite wire type.
type WendyComEvent_ConsoleEnd = core.WendyComEvent_ConsoleEnd

// WendyComOpenChannel is Core's Lite wire type.
type WendyComOpenChannel = core.WendyComOpenChannel

// WendyComCloseChannel is Core's Lite wire type.
type WendyComCloseChannel = core.WendyComCloseChannel

// WendyComChannelOpen is Core's Lite wire type.
type WendyComChannelOpen = core.WendyComChannelOpen

// WendyComChannelClose is Core's Lite wire type.
type WendyComChannelClose = core.WendyComChannelClose

// WendyComChannelError is Core's Lite wire type.
type WendyComChannelError = core.WendyComChannelError

// WendyComChannelState is Core's Lite wire type.
type WendyComChannelState = core.WendyComChannelState

// WendyComChannelState_Open is Core's Lite wire type.
type WendyComChannelState_Open = core.WendyComChannelState_Open

// WendyComChannelState_Close is Core's Lite wire type.
type WendyComChannelState_Close = core.WendyComChannelState_Close

// WendyComChannelState_Error is Core's Lite wire type.
type WendyComChannelState_Error = core.WendyComChannelState_Error

// WendyComService is Core's Lite wire type.
type WendyComService = core.WendyComService

// WendyComService_OpenChannel is Core's Lite wire type.
type WendyComService_OpenChannel = core.WendyComService_OpenChannel

// WendyComService_CloseChannel is Core's Lite wire type.
type WendyComService_CloseChannel = core.WendyComService_CloseChannel

// WendyComService_ChannelState is Core's Lite wire type.
type WendyComService_ChannelState = core.WendyComService_ChannelState

// WendyComMessage is Core's Lite wire type.
type WendyComMessage = core.WendyComMessage

// WendyComMessage_Handshake is Core's Lite wire type.
type WendyComMessage_Handshake = core.WendyComMessage_Handshake

// WendyComMessage_Service is Core's Lite wire type.
type WendyComMessage_Service = core.WendyComMessage_Service

// WendyComMessage_Command is Core's Lite wire type.
type WendyComMessage_Command = core.WendyComMessage_Command

// WendyComMessage_Response is Core's Lite wire type.
type WendyComMessage_Response = core.WendyComMessage_Response

// WendyComMessage_Event is Core's Lite wire type.
type WendyComMessage_Event = core.WendyComMessage_Event

// WendyComMessage_SensorData is Core's Lite wire type.
type WendyComMessage_SensorData = core.WendyComMessage_SensorData

// WendyConfWifiSecurity is Core's Lite wire type.
type WendyConfWifiSecurity = core.WendyConfWifiSecurity

// WendyConfWifiNetwork is Core's Lite wire type.
type WendyConfWifiNetwork = core.WendyConfWifiNetwork

// WendyConfWifi is Core's Lite wire type.
type WendyConfWifi = core.WendyConfWifi

// WendyConfCloudProvisioning is Core's Lite wire type.
type WendyConfCloudProvisioning = core.WendyConfCloudProvisioning

// WendyConfEnrollment is Core's Lite wire type.
type WendyConfEnrollment = core.WendyConfEnrollment

// WendyConf is Core's Lite wire type.
type WendyConf = core.WendyConf

// Lite protocol enum values retain Core's wire numbers.
const (
	VideoFormat_CODEC_UNSPECIFIED                                      = core.VideoFormat_CODEC_UNSPECIFIED
	VideoFormat_MJPEG                                                  = core.VideoFormat_MJPEG
	VideoFormat_H264                                                   = core.VideoFormat_H264
	AudioFormat_CODEC_UNSPECIFIED                                      = core.AudioFormat_CODEC_UNSPECIFIED
	AudioFormat_PCM_S16LE                                              = core.AudioFormat_PCM_S16LE
	AudioFormat_OPUS                                                   = core.AudioFormat_OPUS
	WendyComAppType_WENDY_COM_APP_TYPE_WASM                            = core.WendyComAppType_WENDY_COM_APP_TYPE_WASM
	WendyComAppType_WENDY_COM_APP_TYPE_NATIVE                          = core.WendyComAppType_WENDY_COM_APP_TYPE_NATIVE
	WendyComConfPushMode_WENDY_COM_CONF_PUSH_MODE_REPLACE              = core.WendyComConfPushMode_WENDY_COM_CONF_PUSH_MODE_REPLACE
	WendyComConfPushMode_WENDY_COM_CONF_PUSH_MODE_UPDATE               = core.WendyComConfPushMode_WENDY_COM_CONF_PUSH_MODE_UPDATE
	WendyComConsoleIo_WENDY_COM_CONSOLE_IO_STANDARD_INPUT              = core.WendyComConsoleIo_WENDY_COM_CONSOLE_IO_STANDARD_INPUT
	WendyComConsoleIo_WENDY_COM_CONSOLE_IO_STANDARD_OUTPUT             = core.WendyComConsoleIo_WENDY_COM_CONSOLE_IO_STANDARD_OUTPUT
	WendyComConsoleIo_WENDY_COM_CONSOLE_IO_STANDARD_ERROR              = core.WendyComConsoleIo_WENDY_COM_CONSOLE_IO_STANDARD_ERROR
	WendyComResult_WENDY_COM_RESULT_OK                                 = core.WendyComResult_WENDY_COM_RESULT_OK
	WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR                      = core.WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR
	WendyComResult_WENDY_COM_RESULT_BAD_PROTOCOL_VERSION               = core.WendyComResult_WENDY_COM_RESULT_BAD_PROTOCOL_VERSION
	WendyComResult_WENDY_COM_RESULT_BAD_STATE                          = core.WendyComResult_WENDY_COM_RESULT_BAD_STATE
	WendyComResult_WENDY_COM_RESULT_BUSY                               = core.WendyComResult_WENDY_COM_RESULT_BUSY
	WendyComResult_WENDY_COM_RESULT_BAD_APP_TYPE                       = core.WendyComResult_WENDY_COM_RESULT_BAD_APP_TYPE
	WendyComResult_WENDY_COM_RESULT_BAD_APP_SIZE                       = core.WendyComResult_WENDY_COM_RESULT_BAD_APP_SIZE
	WendyComResult_WENDY_COM_RESULT_BAD_CONF_SIZE                      = core.WendyComResult_WENDY_COM_RESULT_BAD_CONF_SIZE
	WendyComChannelErrorReason_WENDY_COM_CHANNEL_ERROR_REASON_NOT_OPEN = core.WendyComChannelErrorReason_WENDY_COM_CHANNEL_ERROR_REASON_NOT_OPEN
	WendyComChannelErrorReason_WENDY_COM_CHANNEL_ERROR_REASON_REJECTED = core.WendyComChannelErrorReason_WENDY_COM_CHANNEL_ERROR_REASON_REJECTED
	WendyConfWifiSecurity_WENDY_CONF_WIFI_SECURITY_UNSPECIFIED         = core.WendyConfWifiSecurity_WENDY_CONF_WIFI_SECURITY_UNSPECIFIED
	WendyConfWifiSecurity_WENDY_CONF_WIFI_SECURITY_OPEN                = core.WendyConfWifiSecurity_WENDY_CONF_WIFI_SECURITY_OPEN
	WendyConfWifiSecurity_WENDY_CONF_WIFI_SECURITY_WPA2                = core.WendyConfWifiSecurity_WENDY_CONF_WIFI_SECURITY_WPA2
	WendyConfWifiSecurity_WENDY_CONF_WIFI_SECURITY_WPA3                = core.WendyConfWifiSecurity_WENDY_CONF_WIFI_SECURITY_WPA3
)
