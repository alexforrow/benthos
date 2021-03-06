// Copyright (c) 2018 Ashley Jeffs
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package writer

import (
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Jeffail/benthos/lib/log"
	"github.com/Jeffail/benthos/lib/metrics"
	"github.com/Jeffail/benthos/lib/types"
	"github.com/Jeffail/benthos/lib/util/http/auth"
	"github.com/gorilla/websocket"
)

//------------------------------------------------------------------------------

// WebsocketConfig is configuration for the Websocket output type.
type WebsocketConfig struct {
	URL         string `json:"url" yaml:"url"`
	auth.Config `json:",inline" yaml:",inline"`
}

// NewWebsocketConfig creates a new WebsocketConfig with default values.
func NewWebsocketConfig() WebsocketConfig {
	return WebsocketConfig{
		URL:    "ws://localhost:4195/post/ws",
		Config: auth.NewConfig(),
	}
}

//------------------------------------------------------------------------------

// Websocket is an output type that serves Websocket messages.
type Websocket struct {
	log   log.Modular
	stats metrics.Type

	lock *sync.Mutex

	conf   WebsocketConfig
	client *websocket.Conn
}

// NewWebsocket creates a new Websocket output type.
func NewWebsocket(
	conf WebsocketConfig,
	log log.Modular,
	stats metrics.Type,
) (*Websocket, error) {
	ws := &Websocket{
		log:   log.NewModule(".output.websocket"),
		stats: stats,
		lock:  &sync.Mutex{},
		conf:  conf,
	}
	return ws, nil
}

//------------------------------------------------------------------------------

func (w *Websocket) getWS() *websocket.Conn {
	w.lock.Lock()
	ws := w.client
	w.lock.Unlock()
	return ws
}

//------------------------------------------------------------------------------

// Connect establishes a connection to an Websocket server.
func (w *Websocket) Connect() error {
	w.lock.Lock()
	defer w.lock.Unlock()

	if w.client != nil {
		return nil
	}

	headers := http.Header{}

	purl, err := url.Parse(w.conf.URL)
	if err != nil {
		return err
	}

	if err = w.conf.Sign(&http.Request{
		URL:    purl,
		Header: headers,
	}); err != nil {
		return err
	}

	var client *websocket.Conn
	if client, _, err = websocket.DefaultDialer.Dial(w.conf.URL, headers); err != nil {
		return err
	}

	go func(c *websocket.Conn) {
		for {
			if _, _, cerr := c.NextReader(); cerr != nil {
				c.Close()
				break
			}
		}
	}(client)

	w.client = client
	return nil
}

//------------------------------------------------------------------------------

// Write attempts to write a message by pushing it to an Websocket broker.
func (w *Websocket) Write(msg types.Message) error {
	client := w.getWS()
	if client == nil {
		return types.ErrNotConnected
	}

	for _, part := range msg.GetAll() {
		if err := client.WriteMessage(websocket.BinaryMessage, part); err != nil {
			w.lock.Lock()
			w.client = nil
			w.lock.Unlock()
			if err == websocket.ErrCloseSent {
				return types.ErrNotConnected
			}
			return err
		}
	}

	return nil
}

// CloseAsync shuts down the Websocket output and stops processing messages.
func (w *Websocket) CloseAsync() {
	w.lock.Lock()
	if w.client != nil {
		w.client.Close()
		w.client = nil
	}
	w.lock.Unlock()
}

// WaitForClose blocks until the Websocket output has closed down.
func (w *Websocket) WaitForClose(timeout time.Duration) error {
	return nil
}

//------------------------------------------------------------------------------
