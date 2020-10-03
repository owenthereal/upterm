package rollbar

import (
	"sync"
)

// AsyncTransport is a concrete implementation of the Transport type which communicates with the
// Rollbar API asynchronously using a buffered channel.
type AsyncTransport struct {
	// Rollbar access token used by this transport for communication with the Rollbar API.
	Token string
	// Endpoint to post items to.
	Endpoint string
	// Logger used to report errors when sending data to Rollbar, e.g.
	// when the Rollbar API returns 409 Too Many Requests response.
	// If not set, the client will use the standard log.Printf by default.
	Logger ClientLogger
	// Buffer is the size of the channel used for queueing asynchronous payloads for sending to
	// Rollbar.
	Buffer int
	// RetryAttempts is how often to attempt to resend an item when a temporary network error occurs
	// This defaults to DefaultRetryAttempts
	// Set this value to 0 if you do not want retries to happen
	RetryAttempts int
	// PrintPayloadOnError is whether or not to output the payload to the set logger or to stderr
	// if an error occurs during transport to the Rollbar API.
	PrintPayloadOnError bool
	bodyChannel         chan payload
	waitGroup           sync.WaitGroup
}

type payload struct {
	body        map[string]interface{}
	retriesLeft int
}

// NewAsyncTransport builds an asynchronous transport which sends data to the Rollbar API at the
// specified endpoint using the given access token. The channel is limited to the size of the input
// buffer argument.
func NewAsyncTransport(token string, endpoint string, buffer int) *AsyncTransport {
	transport := &AsyncTransport{
		Token:               token,
		Endpoint:            endpoint,
		Buffer:              buffer,
		RetryAttempts:       DefaultRetryAttempts,
		PrintPayloadOnError: true,
		bodyChannel:         make(chan payload, buffer),
	}

	go func() {
		for p := range transport.bodyChannel {
			err, canRetry := transport.post(p)
			if err != nil {
				if canRetry && p.retriesLeft > 0 {
					p.retriesLeft -= 1
					select {
					case transport.bodyChannel <- p:
					default:
						// This can happen if the bodyChannel had an item added to it from another
						// thread while we are processing such that the channel is now full. If we try
						// to send the payload back to the channel without this select statement we
						// could deadlock. Instead we consider this a retry failure.
						if transport.PrintPayloadOnError {
							writePayloadToStderr(transport.Logger, p.body)
						}
						transport.waitGroup.Done()
					}
				} else {
					if transport.PrintPayloadOnError {
						writePayloadToStderr(transport.Logger, p.body)
					}
					transport.waitGroup.Done()
				}
			} else {
				transport.waitGroup.Done()
			}
		}
	}()
	return transport
}

// Send the body to Rollbar if the channel is not currently full.
// Returns ErrBufferFull if the underlying channel is full.
func (t *AsyncTransport) Send(body map[string]interface{}) error {
	if len(t.bodyChannel) < t.Buffer {
		t.waitGroup.Add(1)
		p := payload{
			body:        body,
			retriesLeft: t.RetryAttempts,
		}
		t.bodyChannel <- p
	} else {
		err := ErrBufferFull{}
		rollbarError(t.Logger, err.Error())
		if t.PrintPayloadOnError {
			writePayloadToStderr(t.Logger, body)
		}
		return err
	}
	return nil
}

// Wait blocks until all of the items currently in the queue have been sent.
func (t *AsyncTransport) Wait() {
	t.waitGroup.Wait()
}

// Close is an alias for Wait for the asynchronous transport
func (t *AsyncTransport) Close() error {
	t.Wait()
	return nil
}

// SetToken updates the token to use for future API requests.
// Any request that is currently in the queue will use this
// updated token value. If you want to change the token without
// affecting the items currently in the queue, use Wait first
// to flush the queue.
func (t *AsyncTransport) SetToken(token string) {
	t.Token = token
}

// SetEndpoint updates the API endpoint to send items to.
// Any request that is currently in the queue will use this
// updated endpoint value. If you want to change the endpoint without
// affecting the items currently in the queue, use Wait first
// to flush the queue.
func (t *AsyncTransport) SetEndpoint(endpoint string) {
	t.Endpoint = endpoint
}

// SetLogger updates the logger that this transport uses for reporting errors that occur while
// processing items.
func (t *AsyncTransport) SetLogger(logger ClientLogger) {
	t.Logger = logger
}

// SetRetryAttempts is how often to attempt to resend an item when a temporary network error occurs
// This defaults to DefaultRetryAttempts
// Set this value to 0 if you do not want retries to happen
func (t *AsyncTransport) SetRetryAttempts(retryAttempts int) {
	t.RetryAttempts = retryAttempts
}

// SetPrintPayloadOnError is whether or not to output the payload to stderr if an error occurs during
// transport to the Rollbar API.
func (t *AsyncTransport) SetPrintPayloadOnError(printPayloadOnError bool) {
	t.PrintPayloadOnError = printPayloadOnError
}

func (t *AsyncTransport) post(p payload) (error, bool) {
	return clientPost(t.Token, t.Endpoint, p.body, t.Logger)
}
