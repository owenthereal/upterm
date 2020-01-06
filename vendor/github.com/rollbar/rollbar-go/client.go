package rollbar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"runtime"
)

// A Client can be used to interact with Rollbar via the configured Transport.
// The functions at the root of the `rollbar` package are the recommend way of using a Client. One
// should not need to manage instances of the Client type manually in most normal scenarios.
// However, if you want to customize the underlying transport layer, or you need to have
// independent instances of a Client, then you can use the constructors provided for this
// type.
type Client struct {
	io.Closer
	// Transport used to send data to the Rollbar API. By default an asynchronous
	// implementation of the Transport interface is used.
	Transport     Transport
	configuration configuration
	diagnostic    diagnostic
}

// New returns the default implementation of a Client.
// This uses the AsyncTransport.
func New(token, environment, codeVersion, serverHost, serverRoot string) *Client {
	return NewAsync(token, environment, codeVersion, serverHost, serverRoot)
}

// NewAsync builds a Client with the asynchronous implementation of the transport interface.
func NewAsync(token, environment, codeVersion, serverHost, serverRoot string) *Client {
	configuration := createConfiguration(token, environment, codeVersion, serverHost, serverRoot)
	transport := NewTransport(token, configuration.endpoint)
	diagnostic := createDiagnostic()
	return &Client{
		Transport:     transport,
		configuration: configuration,
		diagnostic:    diagnostic,
	}
}

// NewSync builds a Client with the synchronous implementation of the transport interface.
func NewSync(token, environment, codeVersion, serverHost, serverRoot string) *Client {
	configuration := createConfiguration(token, environment, codeVersion, serverHost, serverRoot)
	transport := NewSyncTransport(token, configuration.endpoint)
	diagnostic := createDiagnostic()
	return &Client{
		Transport:     transport,
		configuration: configuration,
		diagnostic:    diagnostic,
	}
}

// SetEnabled sets whether or not Rollbar is enabled.
// If this is true then this library works as normal.
// If this is false then no calls will be made to the network.
// One place where this is useful is for turning off reporting in tests.
func (c *Client) SetEnabled(enabled bool) {
	c.configuration.enabled = enabled
}

// SetToken sets the token used by this client.
// The value is a Rollbar access token with scope "post_server_item".
// It is required to set this value before any of the other functions herein will be able to work
// properly. This also configures the underlying Transport.
func (c *Client) SetToken(token string) {
	c.configuration.token = token
	c.Transport.SetToken(token)
}

// SetEnvironment sets the environment under which all errors and messages will be submitted.
func (c *Client) SetEnvironment(environment string) {
	c.diagnostic.configuredOptions["environment"] = environment
	c.configuration.environment = environment
}

// SetEndpoint sets the endpoint to post items to. This also configures the underlying Transport.
func (c *Client) SetEndpoint(endpoint string) {
	c.diagnostic.configuredOptions["endpoint"] = endpoint
	c.configuration.endpoint = endpoint
	c.Transport.SetEndpoint(endpoint)
}

// SetPlatform sets the platform to be reported for all items.
func (c *Client) SetPlatform(platform string) {
	c.diagnostic.configuredOptions["platform"] = platform
	c.configuration.platform = platform
}

// SetCodeVersion sets the string describing the running code version on the server.
func (c *Client) SetCodeVersion(codeVersion string) {
	c.diagnostic.configuredOptions["codeVersion"] = codeVersion
	c.configuration.codeVersion = codeVersion
}

// SetServerHost sets the hostname sent with each item. This value will be indexed.
func (c *Client) SetServerHost(serverHost string) {
	c.diagnostic.configuredOptions["serverHost"] = serverHost
	c.configuration.serverHost = serverHost
}

// SetServerRoot sets the path to the application code root, not including the final slash.
// This is used to collapse non-project code when displaying tracebacks.
func (c *Client) SetServerRoot(serverRoot string) {
	c.diagnostic.configuredOptions["serverRoot"] = serverRoot
	c.configuration.serverRoot = serverRoot
}

// SetCustom sets any arbitrary metadata you want to send with every item.
func (c *Client) SetCustom(custom map[string]interface{}) {
	c.configuration.custom = custom
}

// SetPerson information for identifying a user associated with
// any subsequent errors or messages. Only id is required to be
// non-empty.
func (c *Client) SetPerson(id, username, email string) {
	person := Person{
		Id:       id,
		Username: username,
		Email:    email,
	}

	c.diagnostic.configuredOptions["person"] = map[string]string{
		"Id": id,
		"Username": username,
		"Email": email,
	}
	c.configuration.person = person
}

// ClearPerson clears any previously set person information. See `SetPerson` for more
// information.
func (c *Client) ClearPerson() {
	person := Person{}

	c.diagnostic.configuredOptions["person"] = map[string]string{}
	c.configuration.person = person
}

// SetFingerprint sets whether or not to use a custom client-side fingerprint. The default value is
// false.
func (c *Client) SetFingerprint(fingerprint bool) {
	c.diagnostic.configuredOptions["fingerprint"] = fingerprint
	c.configuration.fingerprint = fingerprint
}

// SetLogger sets the logger on the underlying transport. By default log.Printf is used.
func (c *Client) SetLogger(logger ClientLogger) {
	c.Transport.SetLogger(logger)
}

// SetScrubHeaders sets the regular expression used to match headers for scrubbing.
// The default value is regexp.MustCompile("Authorization")
func (c *Client) SetScrubHeaders(headers *regexp.Regexp) {
	c.diagnostic.configuredOptions["scrubHeaders"] = headers
	c.configuration.scrubHeaders = headers
}

// SetScrubFields sets the regular expression to match keys in the item payload for scrubbing.
// The default vlaue is regexp.MustCompile("password|secret|token"),
func (c *Client) SetScrubFields(fields *regexp.Regexp) {
	c.diagnostic.configuredOptions["scrubFields"] = fields
	c.configuration.scrubFields = fields
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
func (c *Client) SetTransform(transform func(map[string]interface{})) {
	c.diagnostic.configuredOptions["transform"] = functionToString(transform)
	c.configuration.transform = transform
}

// SetUnwrapper sets the UnwrapperFunc used by the client. The unwrapper function
// is used to extract wrapped errors from enhanced error types. This feature can be used to add
// support for custom error types that do not yet implement the Unwrap method specified in Go 1.13.
// See the documentation of UnwrapperFunc for more details.
//
// In order to preserve the default unwrapping behavior, callers of SetUnwrapper may wish to include
// a call to DefaultUnwrapper in their custom unwrapper function. See the example on the SetUnwrapper function.
func (c *Client) SetUnwrapper(unwrapper UnwrapperFunc) {
	c.diagnostic.configuredOptions["unwrapper"] = functionToString(unwrapper)
	c.configuration.unwrapper = unwrapper
}

// SetStackTracer sets the StackTracerFunc used by the client. The stack tracer
// function is used to extract the stack trace from enhanced error types. This feature can be used
// to add support for custom error types that do not implement the Stacker interface.
// See the documentation of StackTracerFunc for more details.
//
// In order to preserve the default stack tracing behavior, callers of SetStackTracer may wish
// to include a call to DefaultStackTracer in their custom tracing function. See the example
// on the SetStackTracer function.
func (c *Client) SetStackTracer(stackTracer StackTracerFunc) {
	c.diagnostic.configuredOptions["stackTracer"] = functionToString(stackTracer)
	c.configuration.stackTracer = stackTracer
}

// SetCheckIgnore sets the checkIgnore function which is called during the recovery
// process of a panic that occurred inside a function wrapped by Wrap or WrapAndWait.
// Return true if you wish to ignore this panic, false if you wish to
// report it to Rollbar. If an error is the argument to the panic, then
// this function is called with the result of calling Error(), otherwise
// the string representation of the value is passed to this function.
func (c *Client) SetCheckIgnore(checkIgnore func(string) bool) {
	c.diagnostic.configuredOptions["checkIgnore"] = functionToString(checkIgnore)
	c.configuration.checkIgnore = checkIgnore
}

// SetCaptureIp sets what level of IP address information to capture from requests.
// CaptureIpFull means capture the entire address without any modification.
// CaptureIpAnonymize means apply a pseudo-anonymization.
// CaptureIpNone means do not capture anything.
func (c *Client) SetCaptureIp(captureIp captureIp) {
	c.diagnostic.configuredOptions["captureIp"] = captureIp
	c.configuration.captureIp = captureIp
}

// SetRetryAttempts sets how many times to attempt to retry sending an item if the http transport
// experiences temporary error conditions. By default this is equal to DefaultRetryAttempts.
// Temporary errors include timeouts and rate limit responses.
func (c *Client) SetRetryAttempts(retryAttempts int) {
	c.Transport.SetRetryAttempts(retryAttempts)
}

// SetPrintPayloadOnError sets whether or not to output the payload to the set logger or to
// stderr if an error occurs during transport to the Rollbar API. For example, if you hit
// your rate limit and we run out of retry attempts, then if this is true we will output the
// item to stderr rather than the item disappearing completely.
func (c *Client) SetPrintPayloadOnError(printPayloadOnError bool) {
	c.Transport.SetPrintPayloadOnError(printPayloadOnError)
}

// Token is the currently set Rollbar access token.
func (c *Client) Token() string {
	return c.configuration.token
}

// Environment is the currently set environment underwhich all errors and
// messages will be submitted.
func (c *Client) Environment() string {
	return c.configuration.environment
}

// Endpoint is the currently set endpoint used for posting items.
func (c *Client) Endpoint() string {
	return c.configuration.endpoint
}

// Platform is the currently set platform reported for all Rollbar items. The default is
// the running operating system (darwin, freebsd, linux, etc.) but it can
// also be application specific (client, heroku, etc.).
func (c *Client) Platform() string {
	return c.configuration.platform
}

// CodeVersion is the currently set string describing the running code version on the server.
func (c *Client) CodeVersion() string {
	return c.configuration.codeVersion
}

// ServerHost is the currently set server hostname. This value will be indexed.
func (c *Client) ServerHost() string {
	return c.configuration.serverHost
}

// ServerRoot is the currently set path to the application code root, not including the final slash.
// This is used to collapse non-project code when displaying tracebacks.
func (c *Client) ServerRoot() string {
	return c.configuration.serverRoot
}

// Custom is the currently set arbitrary metadata you want to send with every subsequently sent item.
func (c *Client) Custom() map[string]interface{} {
	return c.configuration.custom
}

// Fingerprint specifies whether or not to use a custom client-side fingerprint.
func (c *Client) Fingerprint() bool {
	return c.configuration.fingerprint
}

// ScrubHeaders is the currently set regular expression used to match headers for scrubbing.
func (c *Client) ScrubHeaders() *regexp.Regexp {
	return c.configuration.scrubHeaders
}

// ScrubFields is the currently set regular expression to match keys in the item payload for scrubbing.
func (c *Client) ScrubFields() *regexp.Regexp {
	return c.configuration.scrubFields
}

// CaptureIp is the currently set level of IP address information to capture from requests.
func (c *Client) CaptureIp() captureIp {
	return c.configuration.captureIp
}

// -- Error reporting

var noExtras map[string]interface{}

// ErrorWithLevel sends an error to Rollbar with the given severity level.
func (c *Client) ErrorWithLevel(level string, err error) {
	c.ErrorWithExtras(level, err, noExtras)
}

// Errorf sends an error to Rollbar with the given format string and arguments.
func (c *Client) Errorf(level string, format string, args ...interface{}) {
	c.ErrorWithStackSkipWithExtras(level, fmt.Errorf(format, args...), 1, noExtras)
}

// ErrorWithExtras sends an error to Rollbar with the given severity
// level with extra custom data.
func (c *Client) ErrorWithExtras(level string, err error, extras map[string]interface{}) {
	c.ErrorWithStackSkipWithExtras(level, err, 1, extras)
}

// ErrorWithExtrasAndContext sends an error to Rollbar with the given severity
// level with extra custom data, within the given context.
func (c *Client) ErrorWithExtrasAndContext(ctx context.Context, level string, err error, extras map[string]interface{}) {
	c.ErrorWithStackSkipWithExtrasAndContext(ctx, level, err, 1, extras)
}

// RequestError sends an error to Rollbar with the given severity level
// and request-specific information.
func (c *Client) RequestError(level string, r *http.Request, err error) {
	c.RequestErrorWithExtras(level, r, err, noExtras)
}

// RequestErrorWithExtras sends an error to Rollbar with the given
// severity level and request-specific information with extra custom data.
func (c *Client) RequestErrorWithExtras(level string, r *http.Request, err error, extras map[string]interface{}) {
	c.RequestErrorWithStackSkipWithExtras(level, r, err, 1, extras)
}

// RequestErrorWithExtrasAndContext sends an error to Rollbar with the given
// severity level and request-specific information with extra custom data, within the given
// context.
func (c *Client) RequestErrorWithExtrasAndContext(ctx context.Context, level string, r *http.Request, err error, extras map[string]interface{}) {
	c.RequestErrorWithStackSkipWithExtrasAndContext(ctx, level, r, err, 1, extras)
}

// ErrorWithStackSkip sends an error to Rollbar with the given severity
// level and a given number of stack trace frames skipped.
func (c *Client) ErrorWithStackSkip(level string, err error, skip int) {
	c.ErrorWithStackSkipWithExtras(level, err, skip, noExtras)
}

// ErrorWithStackSkipWithExtras sends an error to Rollbar with the given
// severity level and a given number of stack trace frames skipped with
// extra custom data.
func (c *Client) ErrorWithStackSkipWithExtras(level string, err error, skip int, extras map[string]interface{}) {
	c.ErrorWithStackSkipWithExtrasAndContext(context.TODO(), level, err, skip, extras)
}

// ErrorWithStackSkipWithExtrasAndContext sends an error to Rollbar with the given
// severity level and a given number of stack trace frames skipped with
// extra custom data, within the given context.
func (c *Client) ErrorWithStackSkipWithExtrasAndContext(ctx context.Context, level string, err error, skip int, extras map[string]interface{}) {
	if !c.configuration.enabled {
		return
	}
	body := c.buildBody(ctx, level, err.Error(), extras)
	addErrorToBody(c.configuration, body, err, skip)
	c.push(body)
}

// RequestErrorWithStackSkip sends an error to Rollbar with the given
// severity level and a given number of stack trace frames skipped, in
// addition to extra request-specific information.
func (c *Client) RequestErrorWithStackSkip(level string, r *http.Request, err error, skip int) {
	c.RequestErrorWithStackSkipWithExtras(level, r, err, skip, noExtras)
}

// RequestErrorWithStackSkipWithExtras sends an error to Rollbar with
// the given severity level and a given number of stack trace frames
// skipped, in addition to extra request-specific information and extra
// custom data.
func (c *Client) RequestErrorWithStackSkipWithExtras(level string, r *http.Request, err error, skip int, extras map[string]interface{}) {
	c.RequestErrorWithStackSkipWithExtrasAndContext(context.TODO(), level, r, err, skip, extras)
}

// RequestErrorWithStackSkipWithExtrasAndContext sends an error to Rollbar with
// the given severity level and a given number of stack trace frames
// skipped, in addition to extra request-specific information and extra
// custom data, within the given context.
func (c *Client) RequestErrorWithStackSkipWithExtrasAndContext(ctx context.Context, level string, r *http.Request, err error, skip int, extras map[string]interface{}) {
	if !c.configuration.enabled {
		return
	}
	body := c.buildBody(ctx, level, err.Error(), extras)
	data := addErrorToBody(c.configuration, body, err, skip)
	data["request"] = c.requestDetails(r)
	c.push(body)
}

// -- Message reporting

// Message sends a message to Rollbar with the given severity level.
func (c *Client) Message(level string, msg string) {
	c.MessageWithExtras(level, msg, noExtras)
}

// MessageWithExtras sends a message to Rollbar with the given severity
// level with extra custom data.
func (c *Client) MessageWithExtras(level string, msg string, extras map[string]interface{}) {
	c.MessageWithExtrasAndContext(context.TODO(), level, msg, extras)
}

// MessageWithExtrasAndContext sends a message to Rollbar with the given severity
// level with extra custom data, within the given context.
func (c *Client) MessageWithExtrasAndContext(ctx context.Context, level string, msg string, extras map[string]interface{}) {
	if !c.configuration.enabled {
		return
	}
	body := c.buildBody(ctx, level, msg, extras)
	data := body["data"].(map[string]interface{})
	data["body"] = messageBody(msg)
	c.push(body)
}

// RequestMessage sends a message to Rollbar with the given severity level
// and request-specific information.
func (c *Client) RequestMessage(level string, r *http.Request, msg string) {
	c.RequestMessageWithExtras(level, r, msg, noExtras)
}

// RequestMessageWithExtras sends a message to Rollbar with the given
// severity level and request-specific information with extra custom data.
func (c *Client) RequestMessageWithExtras(level string, r *http.Request, msg string, extras map[string]interface{}) {
	c.RequestMessageWithExtrasAndContext(context.TODO(), level, r, msg, extras)
}

// RequestMessageWithExtrasAndContext sends a message to Rollbar with the given
// severity level and request-specific information with extra custom data, within the given
// context.
func (c *Client) RequestMessageWithExtrasAndContext(ctx context.Context, level string, r *http.Request, msg string, extras map[string]interface{}) {
	if !c.configuration.enabled {
		return
	}
	body := c.buildBody(ctx, level, msg, extras)
	data := body["data"].(map[string]interface{})
	data["body"] = messageBody(msg)
	data["request"] = c.requestDetails(r)
	c.push(body)
}

// -- Panics

// LogPanic accepts an error value returned by recover() and
// handles logging to Rollbar with stack info.
func (c *Client) LogPanic(err interface{}, wait bool) {
	switch val := err.(type) {
	case nil:
		return
	case error:
		if c.configuration.checkIgnore(val.Error()) {
			return
		}
		c.ErrorWithStackSkip(CRIT, val, 2)
	default:
		str := fmt.Sprint(val)
		if c.configuration.checkIgnore(str) {
			return
		}
		errValue := errors.New(str)
		c.ErrorWithStackSkip(CRIT, errValue, 2)
	}
	if wait {
		c.Wait()
	}
}

// WrapWithArgs calls f with the supplied args and reports a panic to Rollbar if it occurs.
// If wait is true, this also waits before returning to ensure the message was reported.
// If an error is captured it is subsequently returned.
// WrapWithArgs is compatible with any return type for f, but does not return its return value(s).
func (c *Client) WrapWithArgs(f interface{}, wait bool, inArgs ...interface{}) (err interface{}) {
	if f == nil {
		err = fmt.Errorf("function is nil")
		return
	}
	funcType := reflect.TypeOf(f)
	funcValue := reflect.ValueOf(f)

	if funcType.Kind() != reflect.Func {
		err = fmt.Errorf("function kind %s is not %s", funcType.Kind(), reflect.Func)
		return
	}

	argValues := make([]reflect.Value, len(inArgs))
	for i, v := range inArgs {
		argValues[i] = reflect.ValueOf(v)
	}

	handler := func(args []reflect.Value) []reflect.Value {
		defer func() {
			err = recover()
			c.LogPanic(err, wait)
		}()

		return funcValue.Call(args)
	}

	handler(argValues)

	return
}

// Wrap calls f and then recovers and reports a panic to Rollbar if it occurs.
// If an error is captured it is subsequently returned.
func (c *Client) Wrap(f interface{}, args ...interface{}) (err interface{}) {
	return c.WrapWithArgs(f, false, args...)
}

// WrapAndWait calls f, and recovers and reports a panic to Rollbar if it occurs.
// This also waits before returning to ensure the message was reported
// If an error is captured it is subsequently returned.
func (c *Client) WrapAndWait(f interface{}, args ...interface{}) (err interface{}) {
	return c.WrapWithArgs(f, true, args...)
}

// LambdaWrapper calls handlerFunc with arguments, and recovers and reports a
// panic to Rollbar if it occurs. This functions as a passthrough wrapper for
// lambda.Start(). This also waits before returning to ensure all messages completed.
func (c *Client) LambdaWrapper(handlerFunc interface{}) interface{} {
	if handlerFunc == nil {
		return lambdaErrorHandler(fmt.Errorf("handler is nil"))
	}
	handlerType := reflect.TypeOf(handlerFunc)
	handlerValue := reflect.ValueOf(handlerFunc)

	if handlerType.Kind() != reflect.Func {
		return lambdaErrorHandler(fmt.Errorf("handler kind %s is not %s", handlerType.Kind(), reflect.Func))
	}

	handler := func(args []reflect.Value) []reflect.Value {
		defer func() {
			err := recover()
			c.LogPanic(err, true)
		}()

		ret := handlerValue.Call(args)
		c.Wait()
		return ret
	}

	fn := reflect.MakeFunc(handlerValue.Type(), handler).Interface()
	return fn
}

type lambdaHandler func(context.Context, []byte) (interface{}, error)

func lambdaErrorHandler(e error) lambdaHandler {
	return func(ctx context.Context, payload []byte) (interface{}, error) {
		return nil, e
	}
}

// Wait will call the Wait method of the Transport. If using an asynchronous
// transport then this will block until the queue of
// errors / messages is empty. If using a synchronous transport then there
// is no queue so this will be a no-op.
func (c *Client) Wait() {
	c.Transport.Wait()
}

// Close delegates to the Close method of the Transport. For the asynchronous
// transport this is an alias for Wait, and is a no-op for the synchronous
// transport.
func (c *Client) Close() error {
	return c.Transport.Close()
}

func (c *Client) buildBody(ctx context.Context, level, title string, extras map[string]interface{}) map[string]interface{} {
	return buildBody(ctx, c.configuration, c.diagnostic, level, title, extras)
}

func (c *Client) requestDetails(r *http.Request) map[string]interface{} {
	return requestDetails(c.configuration, r)
}

func (c *Client) push(body map[string]interface{}) error {
	data := body["data"].(map[string]interface{})
	c.configuration.transform(data)
	return c.Transport.Send(body)
}

type Person struct {
	Id       string
	Username string
	Email    string
}

type pkey int

var personKey pkey

// NewPersonContext returns a new Context that carries the person as a value.
func NewPersonContext(ctx context.Context, p *Person) context.Context {
	return context.WithValue(ctx, personKey, p)
}

// PersonFromContext returns the Person value stored in ctx, if any.
func PersonFromContext(ctx context.Context) (*Person, bool) {
	p, ok := ctx.Value(personKey).(*Person)
	return p, ok
}

type captureIp int

const (
	// CaptureIpFull means capture the entire address without any modification.
	CaptureIpFull captureIp = iota
	// CaptureIpAnonymize means apply a pseudo-anonymization.
	CaptureIpAnonymize
	// CaptureIpNone means do not capture anything.
	CaptureIpNone
)

type configuration struct {
	enabled      bool
	token        string
	environment  string
	platform     string
	codeVersion  string
	serverHost   string
	serverRoot   string
	endpoint     string
	custom       map[string]interface{}
	fingerprint  bool
	scrubHeaders *regexp.Regexp
	scrubFields  *regexp.Regexp
	checkIgnore  func(string) bool
	transform    func(map[string]interface{})
	unwrapper    UnwrapperFunc
	stackTracer  StackTracerFunc
	person       Person
	captureIp    captureIp
}

func createConfiguration(token, environment, codeVersion, serverHost, serverRoot string) configuration {
	hostname := serverHost
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	return configuration{
		enabled:      true,
		token:        token,
		environment:  environment,
		platform:     runtime.GOOS,
		endpoint:     "https://api.rollbar.com/api/1/item/",
		scrubHeaders: regexp.MustCompile("Authorization"),
		scrubFields:  regexp.MustCompile("password|secret|token"),
		codeVersion:  codeVersion,
		serverHost:   hostname,
		serverRoot:   serverRoot,
		fingerprint:  false,
		checkIgnore:  func(_s string) bool { return false },
		transform:    func(_d map[string]interface{}) {},
		unwrapper:    DefaultUnwrapper,
		stackTracer:  DefaultStackTracer,
		person:       Person{},
		captureIp:    CaptureIpFull,
	}
}

type diagnostic struct {
	languageVersion string
	configuredOptions map[string]interface{}
}

func createDiagnostic() diagnostic {
	return diagnostic{
		languageVersion: runtime.Version(),
		configuredOptions: map[string]interface{}{},
	}
}

// clientPost returns an error which indicates the type of error that occured while attempting to
// send the body input to the endpoint given, or nil if no error occurred. If error is not nil, the
// boolean return parameter indicates whether the error is temporary or not. If this boolean return
// value is true then the caller could call this function again with the same input and possibly
// see a non-error response.
func clientPost(token, endpoint string, body map[string]interface{}, logger ClientLogger) (error, bool) {
	if len(token) == 0 {
		rollbarError(logger, "empty token")
		return nil, false
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		rollbarError(logger, "failed to encode payload: %s", err.Error())
		return err, false
	}

	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		rollbarError(logger, "POST failed: %s", err.Error())
		return err, isTemporary(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		rollbarError(logger, "received response: %s", resp.Status)
		// http.StatusTooManyRequests is only defined in Go 1.6+ so we use 429 directly
		isRateLimit := resp.StatusCode == 429
		return ErrHTTPError(resp.StatusCode), isRateLimit
	}

	return nil, false
}

// isTemporary returns true if we should consider the error returned from http.Post to be temporary
// in nature and possibly resolvable by simplying trying the request again.
// https://github.com/grpc/grpc-go/blob/25b4a426b40c26c07c80af674b03db90b5bd4a60/transport/http2_client.go#L125
func isTemporary(err error) bool {
	switch err {
	case io.EOF:
		// Connection closures may be resolved upon retry, and are thus
		// treated as temporary.
		return true
	case context.DeadlineExceeded:
		// In Go 1.7, context.DeadlineExceeded implements Timeout(), and this
		// special case is not needed. Until then, we need to keep this
		// clause.
		return true
	}

	switch err := err.(type) {
	case interface {
		Temporary() bool
	}:
		return err.Temporary()
	case interface {
		Timeout() bool
	}:
		// Timeouts may be resolved upon retry, and are thus treated as
		// temporary.
		return err.Timeout()
	}
	return false
}

func functionToString(function interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(function).Pointer()).Name()
}
