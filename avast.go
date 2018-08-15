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
	"net"
	"net/textproto"
	"os"
	"strconv"
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

const (
	// Mime represents mime option
	Mime PackOption = iota + 1
	// Zip represents zip pack option
	Zip
	// Arj represents arj pack option
	Arj
	// Rar represents rar pack option
	Rar
	// Cab represents cab pack option
	Cab
	// Tar represents tar pack option
	Tar
	// Gz represents gz pack option
	Gz
	// Bzip2 represents bzip2 pack option
	Bzip2
	// Ace represents ace pack option
	Ace
	// Arc represents arc pack option
	Arc
	// Zoo represents zoo pack option
	Zoo
	// Lharc represents lharc pack option
	Lharc
	// Chm represents chm pack option
	Chm
	// Cpio represents cpio pack option
	Cpio
	// Rpm represents rpm pack option
	Rpm
	// Szip represents 7zip pack option
	Szip
	// Iso represents iso pack option
	Iso
	// Tnef represents tnef pack option
	Tnef
	// Dbx represents dbx pack option
	Dbx
	// Sys represents sys pack option
	Sys
	// Ole represents ole pack option
	Ole
	// Exec represents exec pack option
	Exec
	// WinExec represents winexec pack option
	WinExec
	// Install represents install option
	Install
	// Dmg represents dmg pack option
	Dmg
)

const (
	// FullFiles is fullfiles
	FullFiles Flag = iota + 1
	// AllFiles is allfiles
	AllFiles
	// ScanDevices is scandevices
	ScanDevices
)

const (
	// Worm represents worm
	Worm SensiOption = iota + 1
	// Trojan represents trojan
	Trojan
	// Adware represents adware
	Adware
	// Spyware represents spyware
	Spyware
	// Dropper represents dropper
	Dropper
	// Kit represents kit
	Kit
	// Joke represents joke
	Joke
	// Dangerous represents dangerous
	Dangerous
	// Dialer represents dialer
	Dialer
	// Rootkit represents rootkit
	Rootkit
	// Exploit represents exploit
	Exploit
	// Pup represents pup
	Pup
	// Suspicious represents suspicious
	Suspicious
	// Pube represents pube
	Pube
)

// SensiOption represents Avast Sensitivity options
type SensiOption int

func (so SensiOption) String() (s string) {
	n := [...]string{
		"",
		"worm",
		"trojan",
		"adware",
		"spyware",
		"dropper",
		"kit",
		"joke",
		"dangerous",
		"dialer",
		"rootkit",
		"exploit",
		"pup",
		"suspicious",
		"pube",
	}
	if so < Worm || so > Pube {
		s = ""
		return
	}

	s = n[so]

	return
}

// Enable returns enabled option string
func (so SensiOption) Enable() (s string) {
	s = fmt.Sprintf("+%s", so)

	return
}

// Disable returns disabled option string
func (so SensiOption) Disable() (s string) {
	s = fmt.Sprintf("-%s", so)

	return
}

// A Flag represents Avast flags
type Flag int

func (f Flag) String() (s string) {
	n := [...]string{
		"",
		"fullfiles",
		"allfiles",
		"scandevices",
	}
	if f < FullFiles || f > ScanDevices {
		s = ""
		return
	}
	s = n[f]
	return
}

// Enable returns enabled option string
func (f Flag) Enable() (s string) {
	s = fmt.Sprintf("+%s", f)

	return
}

// Disable returns disabled option string
func (f Flag) Disable() (s string) {
	s = fmt.Sprintf("-%s", f)

	return
}

// A PackOption represents Avast PACK options
type PackOption int

func (p PackOption) String() (s string) {
	n := [...]string{
		"",
		"mime",
		"zip",
		"arj",
		"rar",
		"cab",
		"tar",
		"gz",
		"bzip2",
		"ace",
		"arc",
		"zoo",
		"lharc",
		"chm",
		"cpio",
		"rpm",
		"7zip",
		"iso",
		"tnef",
		"dbx",
		"sys",
		"ole",
		"exec",
		"winexec",
		"install",
		"dmg",
	}
	if p < Mime || p > Dmg {
		s = ""
		return
	}
	s = n[p]
	return
}

// Enable returns enabled option string
func (p PackOption) Enable() (s string) {
	s = fmt.Sprintf("+%s", p)

	return
}

// Disable returns disabled option string
func (p PackOption) Disable() (s string) {
	s = fmt.Sprintf("-%s", p)

	return
}

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
	var l int
	var s string

	s, err = c.basicCmd(Vps, "")
	if err != nil {
		return
	}

	l = len(s)
	if l < 4 || s[0] != 'V' && s[1] != 'P' && s[2] != 'S' && s[3] != ' ' {
		err = fmt.Errorf("Invalid Server Response: %s", s)
		return
	}

	if v, err = strconv.Atoi(s[4:]); err != nil {
		err = fmt.Errorf("Invalid Server Response: %s", s)
		return
	}

	return
}

// GetPack returns packer options
func (c *Client) GetPack() (p string, err error) {
	var l int
	var s string
	s, err = c.basicCmd(Pack, "")
	if err != nil {
		return
	}

	l = len(s)
	if l < 5 || s[0] != 'P' && s[3] != 'K' && s[4] != ' ' {
		err = fmt.Errorf("Invalid Server Response: %s", s)
		return
	}

	p = s[5:]
	return
}

// SetPack sets packer options
func (c *Client) SetPack(o PackOption, v bool) (err error) {
	var s string
	if v {
		s = o.Enable()
	} else {
		s = o.Disable()
	}

	_, err = c.basicCmd(Pack, s)
	return
}

// GetFlags returns scan flags
func (c *Client) GetFlags() (f string, err error) {
	var l int
	var s string
	s, err = c.basicCmd(Flags, "")
	if err != nil {
		return
	}

	l = len(s)
	if l < 6 || s[0] != 'F' && s[4] != 'K' && s[5] != ' ' {
		err = fmt.Errorf("Invalid Server Response: %s", s)
		return
	}

	f = s[6:]
	return
}

// SetFlags sets scan flags
func (c *Client) SetFlags(o Flag, v bool) (err error) {
	var s string
	if v {
		s = o.Enable()
	} else {
		s = o.Disable()
	}

	_, err = c.basicCmd(Flags, s)
	return
}

// GetSensitivity returns scan sensitivity options
func (c *Client) GetSensitivity() (f string, err error) {
	var l int
	var s string
	s, err = c.basicCmd(Sensitivity, "")
	if err != nil {
		return
	}

	l = len(s)
	if l < 12 || s[0] != 'S' && s[10] != 'Y' && s[11] != ' ' {
		err = fmt.Errorf("Invalid Server Response: %s", s)
		return
	}

	f = s[11:]
	return
}

// SetSensitivity sets scan sensitivity
func (c *Client) SetSensitivity(o SensiOption, v bool) (err error) {
	var s string
	if v {
		s = o.Enable()
	} else {
		s = o.Disable()
	}

	_, err = c.basicCmd(Sensitivity, s)
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

// Close closes the server connection
func (c *Client) Close() (err error) {
	_, err = c.basicCmd(Quit, "")

	c.tc.Close()

	return
}

func (c *Client) dial() (conn net.Conn, err error) {
	d := &net.Dialer{}

	if c.connTimeout > 0 {
		d.Timeout = c.connTimeout
	}

	for i := 0; i <= c.connRetries; i++ {
		conn, err = d.Dial("unix", c.address)
		if e, ok := err.(net.Error); ok && e.Timeout() {
			time.Sleep(c.connSleep)
			continue
		}
		break
	}
	return
}

func (c *Client) basicCmd(cmd Command, o string) (r string, err error) {
	var id uint
	if o == "" {
		id, err = c.tc.Cmd("%s", cmd)
	} else {
		id, err = c.tc.Cmd("%s %s", cmd, o)
	}

	if err != nil {
		return
	}

	c.tc.StartResponse(id)
	defer c.tc.EndResponse(id)

	if cmd == Quit {
		return
	}

	// Read Opening response
	if _, _, err = c.tc.ReadCodeLine(210); err != nil {
		return
	}

	// Read actual response
	if r, err = c.tc.ReadLine(); err != nil {
		return
	}

	// Read Closing response
	if _, _, err = c.tc.ReadCodeLine(200); err != nil {
		return
	}

	return
}

// NewClient creates and returns a new instance of Client
func NewClient(address string) (c *Client, err error) {
	var conn net.Conn
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

	c.m.Lock()
	defer c.m.Unlock()

	if c.tc == nil {
		if conn, err = c.dial(); err != nil {
			return
		}

		c.tc = textproto.NewConn(conn)
	}

	if _, _, err = c.tc.ReadCodeLine(220); err != nil {
		return
	}

	return
}
