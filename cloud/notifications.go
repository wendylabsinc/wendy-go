package cloud

import core "github.com/wendylabsinc/WendyOS/go/wendy-core/core/cloud"

// Notification is Core's basic inbox model, including canonical notification and
// organization IDs, metadata, timestamps and a validated wendy:// deep link.
// ReadStatus derives the read state from ReadAt. Rich content remains inactive.
type Notification = core.Notification

// NotificationQuery selects severity and read status; nil fields include all.
type NotificationQuery = core.NotificationQuery

// NotificationPage selects a newest-first stable window. BeforeID and AfterID
// are independent optional anchors and may be combined. A nil Limit defaults to
// 30; an explicit limit must be between 1 and 100.
type NotificationPage = core.NotificationPage

// NotificationBatch contains one bounded page and its server continuation flag.
type NotificationBatch = core.NotificationBatch

// NotificationSeverity retains the Cloud v2 notification importance values.
type NotificationSeverity = core.NotificationSeverity

// NotificationSeverityUnspecified represents an unknown severity, not a filter.
const NotificationSeverityUnspecified = core.NotificationSeverityUnspecified

// NotificationSeverityInfo identifies informational notifications.
const NotificationSeverityInfo = core.NotificationSeverityInfo

// NotificationSeverityWarning identifies warning notifications.
const NotificationSeverityWarning = core.NotificationSeverityWarning

// NotificationSeverityError identifies error notifications.
const NotificationSeverityError = core.NotificationSeverityError

// NotificationSeverityCritical identifies critical notifications.
const NotificationSeverityCritical = core.NotificationSeverityCritical

// NotificationReadStatus is a notification's read state, independent of deletion.
type NotificationReadStatus = core.NotificationReadStatus

// NotificationRead selects notifications with a server read timestamp.
const NotificationRead = core.NotificationRead

// NotificationUnread selects notifications without a server read timestamp.
const NotificationUnread = core.NotificationUnread

// NotificationError preserves Core's validation failures and timeout causes.
// Unwrap retains the original host error, including RPC status and metadata.
type NotificationError = core.NotificationError

// NotificationErrorKind identifies an inbox validation or timeout failure.
type NotificationErrorKind = core.NotificationErrorKind

// NotificationMissingID identifies a response without a canonical notification ID.
const NotificationMissingID = core.NotificationMissingID

// NotificationInvalidID identifies a malformed or mismatched notification ID.
const NotificationInvalidID = core.NotificationInvalidID

// NotificationInvalidOrganization identifies an invalid or mismatched tenant.
const NotificationInvalidOrganization = core.NotificationInvalidOrganization

// NotificationInvalidDeepLink identifies an unsafe notification deep link.
const NotificationInvalidDeepLink = core.NotificationInvalidDeepLink

// NotificationInvalidLimit identifies a page limit outside 1 through 100.
const NotificationInvalidLimit = core.NotificationInvalidLimit

// NotificationInvalidSeverity identifies an invalid severity filter.
const NotificationInvalidSeverity = core.NotificationInvalidSeverity

// NotificationInvalidReadStatus identifies an invalid read state.
const NotificationInvalidReadStatus = core.NotificationInvalidReadStatus

// NotificationTimedOut identifies a request timeout and retains its cause.
const NotificationTimedOut = core.NotificationTimedOut
