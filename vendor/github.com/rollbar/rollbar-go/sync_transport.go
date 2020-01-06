package rollbar

// SyncTransport is a concrete implementation of the Transport type which communicates with the
// Rollbar API synchronously.
type SyncTransport struct {
	// Rollbar access token used by this transport for communication with the Rollbar API.
	Token string
	// Endpoint to post items to.
	Endpoint string
	// Logger used to report errors when sending data to Rollbar, e.g.
	// when the Rollbar API returns 409 Too Many Requests response.
	// If not set, the client will use the standard log.Printf by default.
	Logger ClientLogger
	// RetryAttempts is how often to attempt to resend an item when a temporary network error occurs
	// This defaults to DefaultRetryAttempts
	// Set this value to 0 if you do not want retries to happen
	RetryAttempts int
	// PrintPayloadOnError is whether or not to output the payload to the set logger or to stderr if
	// an error occurs during transport to the Rollbar API.
	PrintPayloadOnError bool
}

// NewSyncTransport builds a synchronous transport which sends data to the Rollbar API at the
// specified endpoint using the given access token.
func NewSyncTransport(token, endpoint string) *SyncTransport {
	return &SyncTransport{
		Token:               token,
		Endpoint:            endpoint,
		RetryAttempts:       DefaultRetryAttempts,
		PrintPayloadOnError: true,
	}
}

// Send the body to Rollbar.
// Returns errors associated with the http request if any.
// If the access token has not been set or is empty then this will
// not send anything and will return nil.
func (t *SyncTransport) Send(body map[string]interface{}) error {
	return t.doSend(body, t.RetryAttempts)
}

func (t *SyncTransport) doSend(body map[string]interface{}, retriesLeft int) error {
	err, canRetry := clientPost(t.Token, t.Endpoint, body, t.Logger)
	if err != nil {
		if !canRetry || retriesLeft <= 0 {
			if t.PrintPayloadOnError {
				writePayloadToStderr(t.Logger, body)
			}
			return err
		}
		return t.doSend(body, retriesLeft-1)
	}
	return nil
}

// Wait is a no-op for the synchronous transport.
func (t *SyncTransport) Wait() {}

// Close is a no-op for the synchronous transport.
func (t *SyncTransport) Close() error {
	return nil
}

// SetToken updates the token to use for future API requests.
func (t *SyncTransport) SetToken(token string) {
	t.Token = token
}

// SetEndpoint updates the API endpoint to send items to.
func (t *SyncTransport) SetEndpoint(endpoint string) {
	t.Endpoint = endpoint
}

// SetLogger updates the logger that this transport uses for reporting errors that occur while
// processing items.
func (t *SyncTransport) SetLogger(logger ClientLogger) {
	t.Logger = logger
}

// SetRetryAttempts is how often to attempt to resend an item when a temporary network error occurs
// This defaults to DefaultRetryAttempts
// Set this value to 0 if you do not want retries to happen
func (t *SyncTransport) SetRetryAttempts(retryAttempts int) {
	t.RetryAttempts = retryAttempts
}

// SetPrintPayloadOnError is whether or not to output the payload to stderr if an error occurs during
// transport to the Rollbar API.
func (t *SyncTransport) SetPrintPayloadOnError(printPayloadOnError bool) {
	t.PrintPayloadOnError = printPayloadOnError
}
