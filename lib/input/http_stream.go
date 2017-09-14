/*
Copyright (c) 2017 Ashley Jeffs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package input

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jeffail/benthos/lib/types"
	"github.com/jeffail/util/log"
	"github.com/jeffail/util/metrics"
)

//------------------------------------------------------------------------------

func init() {
	constructors["http_stream_client"] = typeSpec{
		constructor: NewHTTPStreamClient,
		description: `
Benthos can receive messages through an HTTP 1.1 client stream connection.
Messages will be read as line separated message parts, with the line separators
removed.

You should set a sensible number of max retries and retry delays so as to not
stress your target server.

Other notable parameters:

	username     => For basic auth.
	password     => ^
	payload      => Used for POST/PUT requests, can be left empty.
	content_type => Used for POST/PUT requests, can be left empty.
	parts        => Number of message parts for each message.
`,
	}
}

//------------------------------------------------------------------------------

// OAuthConfig holds the configuration parameters for an OAuth exchange.
type OAuthConfig struct {
	ConsumerKey       string `json:"consumer_key" yaml:"consumer_key"`
	ConsumerSecret    string `json:"consumer_secret" yaml:"consumer_secret"`
	AccessToken       string `json:"access_token" yaml:"access_token"`
	AccessTokenSecret string `json:"access_token_secret" yaml:"access_token_secret"`
	RequestURL        string `json:"request_url" yaml:"request_url"`
	Enabled           bool   `json:"enabled" yaml:"enabled"`
}

// NewOAuthConfig returns a new OAuthConfig with default values.
func NewOAuthConfig() OAuthConfig {
	return OAuthConfig{
		ConsumerKey:       "",
		ConsumerSecret:    "",
		AccessToken:       "",
		AccessTokenSecret: "",
		RequestURL:        "",
		Enabled:           false,
	}
}

// Sign method to sign an HTTP request for an OAuth exchange.
func (oauth OAuthConfig) Sign(req *http.Request) error {
	nonceGenerator := rand.New(rand.NewSource(time.Now().UnixNano()))
	nonce := strconv.FormatInt(nonceGenerator.Int63(), 10)
	ts := fmt.Sprintf("%d", time.Now().Unix())

	params := &url.Values{}
	params.Add("oauth_consumer_key", oauth.ConsumerKey)
	params.Add("oauth_nonce", nonce)
	params.Add("oauth_signature_method", "HMAC-SHA1")
	params.Add("oauth_timestamp", ts)
	params.Add("oauth_token", oauth.AccessToken)
	params.Add("oauth_version", "1.0")

	sig, err := oauth.getSignature(req, params)
	if err != nil {
		return err
	}

	str := fmt.Sprintf(
		`OAuth oauth_consumer_key="%s", oauth_nonce="%s", oauth_signature="%s", oauth_signature_method="%s", oauth_timestamp="%s", oauth_token="%s", oauth_version="%s"`,
		url.QueryEscape(oauth.ConsumerKey),
		nonce,
		url.QueryEscape(sig),
		"HMAC-SHA1",
		ts,
		url.QueryEscape(oauth.AccessToken),
		"1.0",
	)
	req.Header.Add("Authorization", str)

	return nil
}

func (oauth OAuthConfig) getSignature(req *http.Request, params *url.Values) (string, error) {
	baseSignatureString := req.Method + "&" + url.QueryEscape(req.URL.String()) + "&" + url.QueryEscape(params.Encode())
	signingKey := url.QueryEscape(oauth.ConsumerSecret) + "&" + url.QueryEscape(oauth.AccessTokenSecret)
	return oauth.computeHMAC(baseSignatureString, signingKey)
}

func (oauth OAuthConfig) computeHMAC(message string, key string) (string, error) {
	h := hmac.New(sha1.New, []byte(key))
	if _, err := h.Write([]byte(message)); nil != err {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

//------------------------------------------------------------------------------

// HTTPStreamClientConfig - Configuration for the HTTPStreamClient input type.
type HTTPStreamClientConfig struct {
	URL          string      `json:"url" yaml:"url"`
	RequestType  string      `json:"request_type" yaml:"request_type"`
	Username     string      `json:"username" yaml:"username"`
	Password     string      `json:"password" yaml:"password"`
	Payload      string      `json:"payload" yaml:"payload"`
	ContentType  string      `json:"content_type" yaml:"content_type"`
	MaxBufSize   int         `json:"max_buffer_size" yaml:"max_buffer_size"`
	Parts        int         `json:"parts" yaml:"parts"`
	TimeoutMS    int         `json:"timeout_ms" yaml:"timeout_ms"`
	NumRetries   int         `json:"num_retries" yaml:"num_retries"`
	RetryDelayMS int         `json:"retry_delay_ms" yaml:"retry_delay_ms"`
	OAuth        OAuthConfig `json:"oauth" yaml:"oauth"`
}

// NewHTTPStreamClientConfig - Creates a new HTTPStreamClientConfig with default
// values.
func NewHTTPStreamClientConfig() HTTPStreamClientConfig {
	return HTTPStreamClientConfig{
		URL:          "http://localhost:8080/stream",
		RequestType:  "GET",
		Username:     "",
		Password:     "",
		Payload:      "",
		ContentType:  "application/octet-stream",
		MaxBufSize:   10 * 1024 * 1024,
		Parts:        1,
		TimeoutMS:    5000,
		NumRetries:   5,
		RetryDelayMS: 1000,
		OAuth:        NewOAuthConfig(),
	}
}

//------------------------------------------------------------------------------

// HTTPStreamClient - An input type that connects to an HTTP stream server.
type HTTPStreamClient struct {
	running int32

	conf  Config
	stats metrics.Type
	log   log.Modular

	internalMessages chan [][]byte

	messages  chan types.Message
	responses <-chan types.Response

	closeChan  chan struct{}
	closedChan chan struct{}
}

// NewHTTPStreamClient - Create a new HTTPStreamClient input type.
func NewHTTPStreamClient(conf Config, log log.Modular, stats metrics.Type) (Type, error) {
	h := HTTPStreamClient{
		running:          1,
		conf:             conf,
		stats:            stats,
		log:              log.NewModule(".input.http_stream_client"),
		internalMessages: make(chan [][]byte),
		messages:         make(chan types.Message),
		responses:        nil,
		closeChan:        make(chan struct{}),
		closedChan:       make(chan struct{}),
	}
	return &h, nil
}

//------------------------------------------------------------------------------

func (h *HTTPStreamClient) connectStream() (*bufio.Scanner, error) {
	conf := h.conf.HTTPStream

	h.log.Infof("Attempting to connect to HTTP stream service at: %s\n", conf.URL)

	var reqBody io.Reader
	if len(conf.Payload) > 0 {
		reqBody = strings.NewReader(conf.Payload)
	}

	request, err := http.NewRequest(conf.RequestType, conf.URL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("Failed to create request: %v", err)
	}

	if len(conf.Username) > 0 {
		h.log.Infof("Using HTTP Basic Auth with user: %s\n", conf.Username)
		request.SetBasicAuth(conf.Username, conf.Password)
	}

	if conf.OAuth.Enabled {
		if err = conf.OAuth.Sign(request); err != nil {
			return nil, fmt.Errorf("Failed to sign OAuth request: %v", err)
		}
	}

	if len(conf.ContentType) > 0 {
		request.Header.Add("Content-Type", strings.ToLower(conf.ContentType))
	}

	client := &http.Client{}
	for i := 0; i < conf.NumRetries; i++ {
		var resp *http.Response

		if resp, err = client.Do(request); err != nil {
			h.log.Errorf("Failed to connect: %v\n", err)
			<-time.After(time.Duration(conf.RetryDelayMS) * time.Millisecond)
			continue
		}

		scanner := bufio.NewScanner(resp.Body)

		buf := make([]byte, conf.MaxBufSize)
		scanner.Buffer(buf, conf.MaxBufSize)
		return scanner, nil
	}

	return nil, err
}

func (h *HTTPStreamClient) readMessage(scanner *bufio.Scanner) (parts [][]byte, err error) {
	for i := 0; i < h.conf.HTTPStream.Parts; i++ {
		if scanner.Scan() {
			parts = append(parts, scanner.Bytes())
		} else {
			err = scanner.Err()
			return nil, err
		}
	}
	return
}

func (h *HTTPStreamClient) scannerLoop() {
	defer func() {
		atomic.StoreInt32(&h.running, 0)
		close(h.internalMessages)
	}()

	var data [][]byte

	var scanner *bufio.Scanner
	var err error

	for atomic.LoadInt32(&h.running) == 1 {
		if scanner == nil {
			scanner, err = h.connectStream()
			if err != nil {
				h.log.Errorln("Shutting down input due to failed connection")
				return
			}
		}
		if data == nil {
			data, err = h.readMessage(scanner)
			if err != nil {
				h.log.Errorf("Lost HTTP stream: %v, attempting to reconnect", err)
				err = nil
				scanner = nil
			}
		}
		if data != nil {
			select {
			case h.internalMessages <- data:
			case <-h.closeChan:
				return
			}
		}
	}
}

func (h *HTTPStreamClient) loop() {
	defer func() {
		atomic.StoreInt32(&h.running, 0)

		close(h.messages)
		close(h.closedChan)
	}()

	var data [][]byte
	var open bool

	go h.scannerLoop()

	for atomic.LoadInt32(&h.running) == 1 {
		if data == nil {
			select {
			case data, open = <-h.internalMessages:
				if !open {
					return
				}
			case <-h.closeChan:
				return
			}
		}
		if data != nil {
			select {
			case h.messages <- types.Message{Parts: data}:
			case <-h.closeChan:
				return
			}

			var res types.Response
			select {
			case res, open = <-h.responses:
				if !open {
					return
				}
			case <-h.closeChan:
				return
			}
			if res.Error() == nil {
				data = nil
			}
		}
	}
}

// StartListening - Sets the channel used by the input to validate message
// receipt.
func (h *HTTPStreamClient) StartListening(responses <-chan types.Response) error {
	if h.responses != nil {
		return types.ErrAlreadyStarted
	}
	h.responses = responses
	go h.loop()
	return nil
}

// MessageChan - Returns the messages channel.
func (h *HTTPStreamClient) MessageChan() <-chan types.Message {
	return h.messages
}

// CloseAsync - Shuts down the HTTPStreamClient input.
func (h *HTTPStreamClient) CloseAsync() {
	if atomic.CompareAndSwapInt32(&h.running, 1, 0) {
		close(h.closeChan)
	}
}

// WaitForClose - Blocks until the HTTPStreamClient input has closed down.
func (h *HTTPStreamClient) WaitForClose(timeout time.Duration) error {
	select {
	case <-h.closedChan:
	case <-time.After(timeout):
		return types.ErrTimeout
	}
	return nil
}

//------------------------------------------------------------------------------
