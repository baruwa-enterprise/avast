// Copyright (C) 2018-2021 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package avast Golang Avast client
Avast - Golang Avast client
*/
package avast

import (
	"context"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	unixSockErr    = "The unix socket: %s does not exist"
	invalidRespErr = "Invalid server response: %s"
	excludeOKResp  = "200 EXCLUDE OK"
	scanOkResp     = "200 SCAN OK"
	urlBlockedResp = "URL blocked"
	// DefaultTimeout is the default connection timeout
	DefaultTimeout = 15 * time.Second
	// DefaultCmdTimeout is the default IO timeout
	DefaultCmdTimeout = 1 * time.Minute
	// DefaultSleep is the default sleep period
	DefaultSleep = 1 * time.Second
	// AvastSock is the default socket location
	AvastSock = "/var/run/avast/scan.sock"
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

var (
	// ZeroTime holds the zero value of time
	ZeroTime   time.Time
	responseRe = regexp.MustCompile(`^SCAN (?P<filename>[^\t]+)\t(?:\[(?P<status>[+LE])\])(?P<depth>\d\.\d)(?:\t(?P<signature>.+))?$`)
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

// Len returns the length of the string
func (c Command) Len() (l int) {
	l = len(c.String())
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
	conn        net.Conn
}

// SetConnTimeout sets the connection timeout
func (c *Client) SetConnTimeout(t time.Duration) {
	if t > 0 {
		c.connTimeout = t
	}
}

// SetCmdTimeout sets the cmd timeout
func (c *Client) SetCmdTimeout(t time.Duration) {
	if t > 0 {
		c.cmdTimeout = t
	}
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
	if s > 0 {
		c.connSleep = s
	}
}

// Scan submits a path for scanning
func (c *Client) Scan(p string) (r []*Response, err error) {
	r, err = c.fileCmd(p)
	return
}

// Vps returns the virus definitions (VPS) version
func (c *Client) Vps() (v int, err error) {
	var s string

	if s, err = c.basicCmd(Vps, ""); err != nil {
		return
	}

	if !strings.HasPrefix(s, Vps.String()) {
		err = fmt.Errorf(invalidRespErr, s)
		return
	}

	if v, err = strconv.Atoi(s[4:]); err != nil {
		err = fmt.Errorf(invalidRespErr, s)
		return
	}

	return
}

// GetPack returns packer options
func (c *Client) GetPack() (p string, err error) {
	var s string

	if s, err = c.basicCmd(Pack, ""); err != nil {
		return
	}

	if !strings.HasPrefix(s, Pack.String()) {
		err = fmt.Errorf(invalidRespErr, s)
		return
	}

	p = s[Pack.Len():]

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
	var s string

	if s, err = c.basicCmd(Flags, ""); err != nil {
		return
	}

	if !strings.HasPrefix(s, Flags.String()) {
		err = fmt.Errorf(invalidRespErr, s)
		return
	}

	f = s[Flags.Len():]

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
	var s string

	if s, err = c.basicCmd(Sensitivity, ""); err != nil {
		return
	}

	if !strings.HasPrefix(s, Sensitivity.String()) {
		err = fmt.Errorf(invalidRespErr, s)
		return
	}

	f = s[Sensitivity.Len():]

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

// GetExclude returns excluded path from scans
func (c *Client) GetExclude() (r string, err error) {
	var s string

	if s, err = c.basicCmd(Exclude, ""); err != nil {
		return
	}

	if s == "" {
		return
	}

	if !strings.HasPrefix(s, Exclude.String()) {
		err = fmt.Errorf(invalidRespErr, s)
		return
	}

	r = s[Exclude.Len()+1:]

	return
}

// SetExclude returns excluded path from scans
func (c *Client) SetExclude(p string) (err error) {
	_, err = c.basicCmd(Exclude, p)
	return
}

// CheckURL checks whether a given URL is malicious
func (c *Client) CheckURL(u string) (r bool, err error) {
	var s string

	if s, err = c.basicCmd(CheckURL, u); err != nil {
		return
	}

	r = strings.HasSuffix(s, urlBlockedResp)

	return
}

// Close closes the server connection
func (c *Client) Close() (err error) {
	_, err = c.basicCmd(Quit, "")

	c.tc.Close()

	return
}

func (c *Client) dial(ctx context.Context) (conn net.Conn, err error) {
	d := &net.Dialer{
		Timeout: c.connTimeout,
	}

	for i := 0; i <= c.connRetries; i++ {
		conn, err = d.DialContext(ctx, "unix", c.address)
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
	defer c.conn.SetDeadline(ZeroTime)

	if cmd == Quit {
		return
	}

	if cmd == CheckURL {
		c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
		if r, err = c.tc.ReadLine(); err != nil {
			return
		}
		return
	}

	// Read Opening response
	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if _, _, err = c.tc.ReadCodeLine(210); err != nil {
		return
	}

	// Read actual response
	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if r, err = c.tc.ReadLine(); err != nil {
		return
	}

	if cmd == Exclude {
		if r == excludeOKResp {
			r = ""
			return
		}
	}

	// Read Closing response
	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if _, _, err = c.tc.ReadCodeLine(200); err != nil {
		return
	}

	return
}

func (c *Client) fileCmd(p string) (r []*Response, err error) {
	var id uint
	var l string
	var gerr error

	if id, err = c.tc.Cmd("%s %s", Scan, p); err != nil {
		return
	}

	c.tc.StartResponse(id)
	defer c.tc.EndResponse(id)
	defer c.conn.SetDeadline(ZeroTime)

	// Read Opening response
	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if _, _, err = c.tc.ReadCodeLine(210); err != nil {
		return
	}

	// Read actual response
	for {
		c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
		if l, err = c.tc.ReadLine(); err != nil {
			return
		}
		if strings.HasPrefix(l, Scan.String()) {
			if mb := responseRe.FindStringSubmatch(l); mb == nil {
				gerr = fmt.Errorf(invalidRespErr, l)
				continue
			} else {
				rs := Response{}
				if strings.HasPrefix(mb[3], "0.") {
					rs.Filename = mb[1]
				} else {
					pts := strings.SplitN(mb[1], "|", 2)
					rs.Filename = pts[0]
					rs.ArchiveItem = pts[1]
				}
				rs.Status = mb[2]
				rs.Infected = mb[2] == "L"
				if rs.Infected {
					rs.Signature = strings.TrimPrefix(mb[4], "0 ")
				} else {
					rs.Signature = mb[4]
				}
				rs.Raw = l

				r = append(r, &rs)
			}
		} else if l == scanOkResp {
			break
		} else {
			gerr = fmt.Errorf(invalidRespErr, l)
		}
	}

	if err == nil && gerr != nil {
		err = gerr
	}
	return
}

// NewClient creates and returns a new instance of Client
func NewClient(ctx context.Context, address string, connTimeOut, ioTimeOut time.Duration) (c *Client, err error) {
	if address == "" {
		address = AvastSock
	}

	if _, err = os.Stat(address); os.IsNotExist(err) {
		err = fmt.Errorf(unixSockErr, address)
		return
	}

	if connTimeOut == 0 {
		connTimeOut = DefaultTimeout
	}

	if ioTimeOut == 0 {
		ioTimeOut = DefaultCmdTimeout
	}

	c = &Client{
		address:     address,
		connTimeout: connTimeOut,
		connSleep:   DefaultSleep,
		cmdTimeout:  ioTimeOut,
	}

	c.m.Lock()
	defer c.m.Unlock()

	if c.conn, err = c.dial(ctx); err != nil {
		return
	}

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	defer c.conn.SetDeadline(ZeroTime)

	c.tc = textproto.NewConn(c.conn)

	if _, _, err = c.tc.ReadCodeLine(220); err != nil {
		c.tc.Close()
		return
	}

	return
}
