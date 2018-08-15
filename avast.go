// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package avast Golang Avast client
Avast - Golang Avast client
*/
package avast

import (
	"fmt"
	"net/textproto"
	"os"
	"sync"
	"time"
)

const (
	defaultTimeout = 15 * time.Second
	defaultSleep   = 1 * time.Second
	avastSock      = "/var/run/avast/scan.sock"
)

const (
	// Scan sends the SCAN request
	Scan Command = iota + 1
	// Vps sends the VPS request
	Vps
	// Pack sends the PACK request
	Pack
	// Flags sends the FLAGS request
	Flags
	// Sensitivity sends the SENSITIVITY request
	Sensitivity
	// Exclude sends the EXCLUDE request
	Exclude
	// CheckURL sends the CHECKURL request
	CheckURL
	// Quit sends the QUIT request
	Quit
)

// A Command represents an Avast Command
type Command int

func (c Command) String() (s string) {
	n := [...]string{
		"",
		"SCAN",
		"VPS",
		"PACK",
		"FLAGS",
		"SENSITIVITY",
		"EXCLUDE",
		"CHECKURL",
		"QUIT",
	}
	if c < Scan || c > Quit {
		s = ""
		return
	}
	s = n[c]
	return
}

// Response represents the response from the server
type Response struct {
	Filename    string
	ArchiveItem string
	Signature   string
	Status      string
	Infected    bool
	Raw         string
}

// A Client represents an Avast client.
type Client struct {
	address     string
	connTimeout time.Duration
	connRetries int
	connSleep   time.Duration
	cmdTimeout  time.Duration
	tc          *textproto.Conn
	m           sync.Mutex
}

// SetConnTimeout sets the connection timeout
func (c *Client) SetConnTimeout(t time.Duration) {
	c.connTimeout = t
}

// SetCmdTimeout sets the cmd timeout
func (c *Client) SetCmdTimeout(t time.Duration) {
	c.cmdTimeout = t
}

// SetConnRetries sets the number of times
// connection is retried
func (c *Client) SetConnRetries(s int) {
	if s < 0 {
		s = 0
	}
	c.connRetries = s
}

// SetConnSleep sets the connection retry sleep
// duration in seconds
func (c *Client) SetConnSleep(s time.Duration) {
	c.connSleep = s
}

// Scan submits a path for scanning
func (c *Client) Scan(p string) (r []*Response, err error) {
	return
}

// Vps returns the virus definitions (VPS) version
func (c *Client) Vps() (v int, err error) {
	return
}

// GetPack returns packer options
func (c *Client) GetPack() (err error) {
	return
}

// SetPack sets packer options
func (c *Client) SetPack() (err error) {
	return
}

// GetFlags returns scan flags
func (c *Client) GetFlags() (err error) {
	return
}

// SetFlags sets scan flags
func (c *Client) SetFlags() (err error) {
	return
}

// GetSensitivity returns scan sensitivity
func (c *Client) GetSensitivity() (err error) {
	return
}

// SetSensitivity sets scan sensitivity
func (c *Client) SetSensitivity() (err error) {
	return
}

// Exclude excludes path from scans
func (c *Client) Exclude() (err error) {
	return
}

// CheckURL checks whether a given URL is malicious
func (c *Client) CheckURL(u string) (r bool, err error) {
	return
}

// NewClient creates and returns a new instance of Client
func NewClient(address string) (c *Client, err error) {
	if address == "" {
		address = avastSock
	}

	if _, err = os.Stat(address); os.IsNotExist(err) {
		err = fmt.Errorf("The unix socket: %s does not exist", address)
		return
	}

	c = &Client{
		address:     address,
		connTimeout: defaultTimeout,
		connSleep:   defaultSleep,
	}

	return
}
