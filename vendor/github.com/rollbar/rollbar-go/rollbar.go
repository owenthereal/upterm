package rollbar

import (
	"context"
	"net/http"
	"os"
	"regexp"
)

const (
	// NAME is the name of this notifier sent with the payload to Rollbar.
	NAME = "rollbar/rollbar-go"
	// VERSION is the version of this notifier sent with the payload to Rollbar.
	VERSION = "1.0.1"

	// CRIT is the critial severity level.
	CRIT = "critical"
	// ERR is the error severity level.
	ERR = "error"
	// WARN is the warning severity level.
	WARN = "warning"
	// INFO is the info severity level.
	INFO = "info"
	// DEBUG is the debug severity level.
	DEBUG = "debug"

	// FILTERED is the string used to replace values that are scrubbed based on the configured headers
	// and fields used for scrubbing.
	FILTERED = "[FILTERED]"
)

var (
	hostname, _ = os.Hostname()
	std         = NewAsync("", "development", "", hostname, "")
	nilErrTitle = "<nil>"
)

// SetEnabled sets whether or not the managed Client instance is enabled.
// If this is true then this library works as normal.
// If this is false then no calls will be made to the network.
// One place where this is useful is for turning off reporting in tests.
func SetEnabled(enabled bool) {
	std.SetEnabled(enabled)
}

// SetToken sets the token on the managed Client instance. The value is a Rollbar access token
// with scope "post_server_item". It is required to set this value before any of the other
// functions herein will be able to work properly.
func SetToken(token string) {
	std.SetToken(token)
}

// SetEnvironment sets the environment on the managed Client instance.
// All errors and messages will be submitted under this environment.
func SetEnvironment(environment string) {
	std.SetEnvironment(environment)
}

// SetEndpoint sets the endpoint on the managed Client instance.
// The endpoint to post items to.
// The default value is https://api.rollbar.com/api/1/item/
func SetEndpoint(endpoint string) {
	std.SetEndpoint(endpoint)
}

// SetPlatform sets the platform on the managed Client instance.
// The platform is reported for all Rollbar items. The default is
// the running operating system (darwin, freebsd, linux, etc.) but it can
// also be application specific (client, heroku, etc.).
func SetPlatform(platform string) {
	std.SetPlatform(platform)
}

// SetCodeVersion sets the code version on the managed Client instance.
// The code version is a string describing the running code version on the server.
func SetCodeVersion(codeVersion string) {
	std.SetCodeVersion(codeVersion)
}

// SetServerHost sets the host value on the managed Client instance.
// Server host is the hostname sent with all Rollbar items. The value will be indexed.
func SetServerHost(serverHost string) {
	std.SetServerHost(serverHost)
}

// SetServerRoot sets the code root value on the managed Client instance.
// Path to the application code root, not including the final slash.
// Used to collapse non-project code when displaying tracebacks.
func SetServerRoot(serverRoot string) {
	std.SetServerRoot(serverRoot)
}

// SetCustom sets custom data on the managed Client instance.
// The data set is any arbitrary metadata you want to send with every subsequently sent item.
func SetCustom(custom map[string]interface{}) {
	std.SetCustom(custom)
}

// SetScrubHeaders sets the headers to scrub on the managed Client instance.
// The value is a regular expression used to match headers for scrubbing.
// The default value is regexp.MustCompile("Authorization").
func SetScrubHeaders(headers *regexp.Regexp) {
	std.SetScrubHeaders(headers)
}

// SetScrubFields sets the fields to scrub on the managed Client instance.
// The value is a regular expression to match keys in the item payload for scrubbing.
// The default vlaue is regexp.MustCompile("password|secret|token").
func SetScrubFields(fields *regexp.Regexp) {
	std.SetScrubFields(fields)
}

// SetTransform sets the transform function called after the entire payload has been built before it
// is sent to the API.
// The structure of the final payload sent to the API is:
//   {
//       "access_token": "YOUR_ACCESS_TOKEN",
//       "data": { ... }
//   }
// This function takes a map[string]interface{} which is the value of the data key in the payload
// described above. You can modify this object in-place to make any arbitrary changes you wish to
// make before it is finally sent. Be careful with the modifications you make as they could lead to
// the payload being malformed from the perspective of the API.
func SetTransform(transform func(map[string]interface{})) {
	std.SetTransform(transform)
}

// SetCheckIgnore sets the checkIgnore function on the managed Client instance.
// CheckIgnore is called during the recovery process of a panic that
// occurred inside a function wrapped by Wrap or WrapAndWait.
// Return true if you wish to ignore this panic, false if you wish to
// report it to Rollbar. If an error is the argument to the panic, then
// this function is called with the result of calling Error(), otherwise
// the string representation of the value is passed to this function.
func SetCheckIgnore(checkIgnore func(string) bool) {
	std.SetCheckIgnore(checkIgnore)
}

// SetPerson information for identifying a user associated with
// any subsequent errors or messages. Only id is required to be
// non-empty.
func SetPerson(id, username, email string) {
	std.SetPerson(id, username, email)
}

// ClearPerson clears any previously set person information. See `SetPerson` for more information.
func ClearPerson() {
	std.ClearPerson()
}

// SetFingerprint sets whether or not to use custom client-side fingerprinting on the managed Client
// instance. This custom fingerprinting is based on a CRC32 checksum. The alternative is to let
// the server compute a fingerprint for each item. The default is false.
func SetFingerprint(fingerprint bool) {
	std.SetFingerprint(fingerprint)
}

// SetLogger sets an alternative logger to be used by the underlying transport layer on the managed
// Client instance.
func SetLogger(logger ClientLogger) {
	std.SetLogger(logger)
}

// SetCaptureIp sets what level of IP address information to capture from requests.
// CaptureIpFull means capture the entire address without any modification.
// CaptureIpAnonymize means apply a pseudo-anonymization.
// CaptureIpNone means do not capture anything.
func SetCaptureIp(captureIp captureIp) {
	std.SetCaptureIp(captureIp)
}

// SetRetryAttempts sets how many times to attempt to retry sending an item if the http transport
// experiences temporary error conditions. By default this is equal to DefaultRetryAttempts.
// Temporary errors include timeouts and rate limit responses.
func SetRetryAttempts(retryAttempts int) {
	std.SetRetryAttempts(retryAttempts)
}

// SetPrintPayloadOnError sets whether or not to output the payload to stderr if an error occurs
// during transport to the Rollbar API. For example, if you hit your rate limit and we run out
// of retry attempts, then if this is true we will output the item to stderr rather than the
// item disappearing completely.
// By default this is true.
func SetPrintPayloadOnError(printPayloadOnError bool) {
	std.SetPrintPayloadOnError(printPayloadOnError)
}

// -- Getters

// Token returns the currently set Rollbar access token on the managed Client instance.
func Token() string {
	return std.Token()
}

// Environment is the environment currently set on the managed Client instance.
func Environment() string {
	return std.Environment()
}

// Endpoint is the currently configured endpoint to send items on the managed Client instance.
func Endpoint() string {
	return std.Endpoint()
}

// Platform is the platform reported for all Rollbar items. The default is
// the running operating system (darwin, freebsd, linux, etc.) but it can
// also be application specific (client, heroku, etc.).
func Platform() string {
	return std.Platform()
}

// CodeVersion is the string describing the running code version on the server that is currently set
// on the managed Client instance.
func CodeVersion() string {
	return std.CodeVersion()
}

// ServerHost is the currently set hostname on the managed Client instance. The value will be
// indexed.
func ServerHost() string {
	return std.ServerHost()
}

// ServerRoot is the currently set path to the code root set on the managed Client instance.
// This should be a path to the application code root, not including the final slash.
// It is used to collapse non-project code when displaying tracebacks.
func ServerRoot() string {
	return std.ServerRoot()
}

// Custom is the currently set extra metadata on the managed Client instance.
func Custom() map[string]interface{} {
	return std.Custom()
}

// Fingerprint is whether or not the current managed Client instance uses a custom client-side
// fingerprint. The default is false.
func Fingerprint() bool {
	return std.Fingerprint()
}

// CaptureIp is the currently set level of IP address information to capture from requests.
func CaptureIp() captureIp {
	return std.CaptureIp()
}

// -- Reporting

// Critical reports an item with level `critical`. This function recognizes arguments with the following types:
//    *http.Request
//    error
//    string
//    map[string]interface{}
//    int
// The string and error types are mutually exclusive.
// If an error is present then a stack trace is captured. If an int is also present then we skip
// that number of stack frames. If the map is present it is used as extra custom data in the
// item. If a string is present without an error, then we log a message without a stack
// trace. If a request is present we extract as much relevant information from it as we can.
func Critical(interfaces ...interface{}) {
	Log(CRIT, interfaces...)
}

// Error reports an item with level `error`. This function recognizes arguments with the following types:
//    *http.Request
//    error
//    string
//    map[string]interface{}
//    int
// The string and error types are mutually exclusive.
// If an error is present then a stack trace is captured. If an int is also present then we skip
// that number of stack frames. If the map is present it is used as extra custom data in the
// item. If a string is present without an error, then we log a message without a stack
// trace. If a request is present we extract as much relevant information from it as we can.
func Error(interfaces ...interface{}) {
	Log(ERR, interfaces...)
}

// Warning reports an item with level `warning`. This function recognizes arguments with the following types:
//    *http.Request
//    error
//    string
//    map[string]interface{}
//    int
// The string and error types are mutually exclusive.
// If an error is present then a stack trace is captured. If an int is also present then we skip
// that number of stack frames. If the map is present it is used as extra custom data in the
// item. If a string is present without an error, then we log a message without a stack
// trace. If a request is present we extract as much relevant information from it as we can.
func Warning(interfaces ...interface{}) {
	Log(WARN, interfaces...)
}

// Info reports an item with level `info`. This function recognizes arguments with the following types:
//    *http.Request
//    error
//    string
//    map[string]interface{}
//    int
// The string and error types are mutually exclusive.
// If an error is present then a stack trace is captured. If an int is also present then we skip
// that number of stack frames. If the map is present it is used as extra custom data in the
// item. If a string is present without an error, then we log a message without a stack
// trace. If a request is present we extract as much relevant information from it as we can.
func Info(interfaces ...interface{}) {
	Log(INFO, interfaces...)
}

// Debug reports an item with level `debug`. This function recognizes arguments with the following types:
//    *http.Request
//    error
//    string
//    map[string]interface{}
//    int
// The string and error types are mutually exclusive.
// If an error is present then a stack trace is captured. If an int is also present then we skip
// that number of stack frames. If the map is present it is used as extra custom data in the
// item. If a string is present without an error, then we log a message without a stack
// trace. If a request is present we extract as much relevant information from it as we can.
func Debug(interfaces ...interface{}) {
	Log(DEBUG, interfaces...)
}

// Log reports an item with the given level. This function recognizes arguments with the following types:
//    *http.Request
//    error
//    string
//    map[string]interface{}
//    int
// The string and error types are mutually exclusive.
// If an error is present then a stack trace is captured. If an int is also present then we skip
// that number of stack frames. If the map is present it is used as extra custom data in the
// item. If a string is present without an error, then we log a message without a stack
// trace. If a request is present we extract as much relevant information from it as we can.
func Log(level string, interfaces ...interface{}) {
	var r *http.Request
	var err error
	var skip int
	skipSet := false
	var extras map[string]interface{}
	var msg string
	ctx := context.TODO()
	for _, ival := range interfaces {
		switch val := ival.(type) {
		case *http.Request:
			r = val
		case error:
			err = val
		case int:
			skip = val
			skipSet = true
		case string:
			msg = val
		case map[string]interface{}:
			extras = val
		case context.Context:
			ctx = val
		default:
			rollbarError(std.Transport.(*AsyncTransport).Logger, "Unknown input type: %T", val)
		}
	}
	if !skipSet {
		skip = 2
	}
	if err != nil {
		if r == nil {
			std.ErrorWithStackSkipWithExtrasAndContext(ctx, level, err, skip, extras)
		} else {
			std.RequestErrorWithStackSkipWithExtrasAndContext(ctx, level, r, err, skip, extras)
		}
	} else {
		if r == nil {
			std.MessageWithExtrasAndContext(ctx, level, msg, extras)
		} else {
			std.RequestMessageWithExtrasAndContext(ctx, level, r, msg, extras)
		}
	}
}

// -- Error reporting

// ErrorWithLevel asynchronously sends an error to Rollbar with the given severity level.
func ErrorWithLevel(level string, err error) {
	std.ErrorWithLevel(level, err)
}

// Errorf sends an error to Rollbar with the given level using the format string and arguments.
func Errorf(level string, format string, args ...interface{}) {
	std.Errorf(level, format, args...)
}

// ErrorWithExtras asynchronously sends an error to Rollbar with the given
// severity level with extra custom data.
func ErrorWithExtras(level string, err error, extras map[string]interface{}) {
	std.ErrorWithExtras(level, err, extras)
}

// ErrorWithExtrasAndContext asynchronously sends an error to Rollbar with the given
// severity level with extra custom data, within the given context.
func ErrorWithExtrasAndContext(ctx context.Context, level string, err error, extras map[string]interface{}) {
	std.ErrorWithExtrasAndContext(ctx, level, err, extras)
}

// RequestError asynchronously sends an error to Rollbar with the given
// severity level and request-specific information.
func RequestError(level string, r *http.Request, err error) {
	std.RequestError(level, r, err)
}

// RequestErrorWithExtras asynchronously sends an error to Rollbar with the given
// severity level and request-specific information with extra custom data.
func RequestErrorWithExtras(level string, r *http.Request, err error, extras map[string]interface{}) {
	std.RequestErrorWithExtras(level, r, err, extras)
}

// RequestErrorWithExtrasAndContext asynchronously sends an error to Rollbar with the given
// severity level and request-specific information with extra custom data.
func RequestErrorWithExtrasAndContext(ctx context.Context, level string, r *http.Request, err error, extras map[string]interface{}) {
	std.RequestErrorWithExtrasAndContext(ctx, level, r, err, extras)
}

// ErrorWithStackSkip asynchronously sends an error to Rollbar with the given
// severity level and a given number of stack trace frames skipped.
func ErrorWithStackSkip(level string, err error, skip int) {
	std.ErrorWithStackSkip(level, err, skip)
}

// ErrorWithStackSkipWithExtras asynchronously sends an error to Rollbar with the given
// severity level and a given number of stack trace frames skipped with extra custom data.
func ErrorWithStackSkipWithExtras(level string, err error, skip int, extras map[string]interface{}) {
	std.ErrorWithStackSkipWithExtras(level, err, skip, extras)
}

// ErrorWithStackSkipWithExtrasAndContext asynchronously sends an error to Rollbar with the given
// severity level and a given number of stack trace frames skipped with extra custom data, within
// the given context.
func ErrorWithStackSkipWithExtrasAndContext(ctx context.Context, level string, err error, skip int, extras map[string]interface{}) {
	std.ErrorWithStackSkipWithExtrasAndContext(ctx, level, err, skip, extras)
}

// RequestErrorWithStackSkip asynchronously sends an error to Rollbar with the
// RequestErrorWithStackSkip asynchronously sends an error to Rollbar with the
// given severity level and a given number of stack trace frames skipped, in
// addition to extra request-specific information.
func RequestErrorWithStackSkip(level string, r *http.Request, err error, skip int) {
	std.RequestErrorWithStackSkip(level, r, err, skip)
}

// RequestErrorWithStackSkipWithExtras asynchronously sends an error to Rollbar
// with the given severity level and a given number of stack trace frames skipped,
// in addition to extra request-specific information and extra custom data.
func RequestErrorWithStackSkipWithExtras(level string, r *http.Request, err error, skip int, extras map[string]interface{}) {
	std.RequestErrorWithStackSkipWithExtras(level, r, err, skip, extras)
}

// RequestErrorWithStackSkipWithExtrasAndContext asynchronously sends an error to Rollbar
// with the given severity level and a given number of stack trace frames skipped,
// in addition to extra request-specific information and extra custom data, within the given context.
func RequestErrorWithStackSkipWithExtrasAndContext(ctx context.Context, level string, r *http.Request, err error, skip int, extras map[string]interface{}) {
	std.RequestErrorWithStackSkipWithExtrasAndContext(ctx, level, r, err, skip, extras)
}

// -- Message reporting

// Message asynchronously sends a message to Rollbar with the given severity
// level. Rollbar request is asynchronous.
func Message(level string, msg string) {
	std.Message(level, msg)
}

// MessageWithExtras asynchronously sends a message to Rollbar with the given severity
// level with extra custom data. Rollbar request is asynchronous.
func MessageWithExtras(level string, msg string, extras map[string]interface{}) {
	std.MessageWithExtras(level, msg, extras)
}

// MessageWithExtrasAndContext asynchronously sends a message to Rollbar with the given severity
// level with extra custom data, within the given context. Rollbar request is asynchronous.
func MessageWithExtrasAndContext(ctx context.Context, level string, msg string, extras map[string]interface{}) {
	std.MessageWithExtrasAndContext(ctx, level, msg, extras)
}

// RequestMessage asynchronously sends a message to Rollbar with the given
// severity level and request-specific information.
func RequestMessage(level string, r *http.Request, msg string) {
	std.RequestMessage(level, r, msg)
}

// RequestMessageWithExtras asynchronously sends a message to Rollbar with the given severity
// level with extra custom data in addition to extra request-specific information.
// Rollbar request is asynchronous.
func RequestMessageWithExtras(level string, r *http.Request, msg string, extras map[string]interface{}) {
	std.RequestMessageWithExtras(level, r, msg, extras)
}

// RequestMessageWithExtrasAndContext asynchronously sends a message to Rollbar with the given severity
// level with extra custom data in addition to extra request-specific information, within the given
// context. Rollbar request is asynchronous.
func RequestMessageWithExtrasAndContext(ctx context.Context, level string, r *http.Request, msg string, extras map[string]interface{}) {
	std.RequestMessageWithExtrasAndContext(ctx, level, r, msg, extras)
}

// Wait will block until the queue of errors / messages is empty.
func Wait() {
	std.Wait()
}

// Wrap calls f and then recovers and reports a panic to Rollbar if it occurs.
// If an error is captured it is subsequently returned.
func Wrap(f func()) interface{} {
	return std.Wrap(f)
}

// WrapAndWait calls f, and recovers and reports a panic to Rollbar if it occurs.
// This also waits before returning to ensure the message was reported.
// If an error is captured it is subsequently returned.
func WrapAndWait(f func()) interface{} {
	return std.WrapAndWait(f)
}

// CauseStacker is an interface that errors can implement to create a trace_chain.
// Callers are required to call BuildStack on their own at the time the cause is wrapped.
type CauseStacker interface {
	error
	Cause() error
	Stack() Stack
}
