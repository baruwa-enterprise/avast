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
	"os"
	"strings"
	"testing"
	"time"
)

const (
	localSock = "/Users/andrew/avast.sock"
)

type CommandTestKey struct {
	in  Command
	out string
}

type SensiOptionTestKey struct {
	in  SensiOption
	out string
}

type FlagTestKey struct {
	in  Flag
	out string
}

type PackOptionTestKey struct {
	in  PackOption
	out string
}

var TestCommands = []CommandTestKey{
	{Scan, "SCAN"},
	{Vps, "VPS"},
	{Pack, "PACK"},
	{Flags, "FLAGS"},
	{Sensitivity, "SENSITIVITY"},
	{Exclude, "EXCLUDE"},
	{CheckURL, "CHECKURL"},
	{Quit, "QUIT"},
	{Command(100), ""},
}

var TestSensiOptions = []SensiOptionTestKey{
	{Worm, "worm"},
	{Trojan, "trojan"},
	{Adware, "adware"},
	{Spyware, "spyware"},
	{Dropper, "dropper"},
	{Kit, "kit"},
	{Joke, "joke"},
	{Dangerous, "dangerous"},
	{Dialer, "dialer"},
	{Rootkit, "rootkit"},
	{Exploit, "exploit"},
	{Pup, "pup"},
	{Suspicious, "suspicious"},
	{Pube, "pube"},
	{SensiOption(100), ""},
}

var TestFlags = []FlagTestKey{
	{FullFiles, "fullfiles"},
	{AllFiles, "allfiles"},
	{ScanDevices, "scandevices"},
	{Flag(100), ""},
}

var TestPackOptions = []PackOptionTestKey{
	{Mime, "mime"},
	{Zip, "zip"},
	{Arj, "arj"},
	{Rar, "rar"},
	{Cab, "cab"},
	{Tar, "tar"},
	{Gz, "gz"},
	{Bzip2, "bzip2"},
	{Ace, "ace"},
	{Arc, "arc"},
	{Zoo, "zoo"},
	{Lharc, "lharc"},
	{Chm, "chm"},
	{Cpio, "cpio"},
	{Rpm, "rpm"},
	{Szip, "7zip"},
	{Iso, "iso"},
	{Tnef, "tnef"},
	{Dbx, "dbx"},
	{Sys, "sys"},
	{Ole, "ole"},
	{Exec, "exec"},
	{WinExec, "winexec"},
	{Install, "install"},
	{Dmg, "dmg"},
	{PackOption(100), ""},
}

func TestCommand(t *testing.T) {
	for _, tt := range TestCommands {
		if s := tt.in.String(); s != tt.out {
			t.Errorf("%q.String() = %q, want %q", tt.in, s, tt.out)
		}
		if l := tt.in.Len(); l != len(tt.out) {
			t.Errorf("%q.String() = %q, want %q", tt.in, l, len(tt.out))
		}
	}
}

func TestSensiOption(t *testing.T) {
	for _, tt := range TestSensiOptions {
		if s := tt.in.String(); s != tt.out {
			t.Errorf("%q.String() = %q, want %q", tt.in, s, tt.out)
		}
		if s := tt.in.Enable(); s != "+"+tt.out {
			t.Errorf("%q.Enable() = %q, want %q", tt.in, s, "+"+tt.out)
		}
		if s := tt.in.Disable(); s != "-"+tt.out {
			t.Errorf("%q.Enable() = %q, want %q", tt.in, s, "-"+tt.out)
		}
	}
}

func TestFlag(t *testing.T) {
	for _, tt := range TestFlags {
		if s := tt.in.String(); s != tt.out {
			t.Errorf("%q.String() = %q, want %q", tt.in, s, tt.out)
		}
		if s := tt.in.Enable(); s != "+"+tt.out {
			t.Errorf("%q.Enable() = %q, want %q", tt.in, s, "+"+tt.out)
		}
		if s := tt.in.Disable(); s != "-"+tt.out {
			t.Errorf("%q.Enable() = %q, want %q", tt.in, s, "-"+tt.out)
		}
	}
}

func TestPackOption(t *testing.T) {
	for _, tt := range TestPackOptions {
		if s := tt.in.String(); s != tt.out {
			t.Errorf("%q.String() = %q, want %q", tt.in, s, tt.out)
		}
		if s := tt.in.Enable(); s != "+"+tt.out {
			t.Errorf("%q.Enable() = %q, want %q", tt.in, s, "+"+tt.out)
		}
		if s := tt.in.Disable(); s != "-"+tt.out {
			t.Errorf("%q.Enable() = %q, want %q", tt.in, s, "-"+tt.out)
		}
	}
}

func TestBasics(t *testing.T) {
	address := os.Getenv("AVAST_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		if c.address != address {
			t.Errorf("Got %q want %q", c.address, address)
		}
		if _, e = NewClient("fe80::879:d85f:f836:1b56%en1", 5*time.Second, 10*time.Second); e == nil {
			t.Fatalf("An error should be returned")
		}
		expect := fmt.Sprintf(unixSockErr, "fe80::879:d85f:f836:1b56%en1")
		if e.Error() != expect {
			t.Errorf("Got %q want %q", e, expect)
		}
	} else {
		t.Skip("skipping test; $AVAST_ADDRESS not set")
	}
}

func TestConnTimeOut(t *testing.T) {
	address := os.Getenv("AVAST_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		if c.connTimeout != 5*time.Second {
			t.Errorf("The default conn timeout should be set")
		}
		expected := 2 * time.Second
		c.SetConnTimeout(expected)
		if c.connTimeout != expected {
			t.Errorf("Calling c.SetConnTimeout(%q) failed", expected)
		}
	} else {
		t.Skip("skipping test; $AVAST_ADDRESS not set")
	}
}

func TestConnSleep(t *testing.T) {
	address := os.Getenv("AVAST_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		if c.connSleep != DefaultSleep {
			t.Errorf("The default conn sleep should be set")
		}
		expected := 2 * time.Second
		c.SetConnSleep(expected)
		if c.connSleep != expected {
			t.Errorf("Calling c.SetConnSleep(%q) failed", expected)
		}
	} else {
		t.Skip("skipping test; $AVAST_ADDRESS not set")
	}
}

func TestCmdTimeOut(t *testing.T) {
	address := os.Getenv("AVAST_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		expected := 2 * time.Second
		c.SetCmdTimeout(expected)
		if c.cmdTimeout != expected {
			t.Errorf("Calling c.SetCmdTimeout(%q) failed", expected)
		}
	} else {
		t.Skip("skipping test; $AVAST_ADDRESS not set")
	}
}

func TestConnRetries(t *testing.T) {
	address := os.Getenv("AVAST_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		if c.connRetries != 0 {
			t.Errorf("The default conn retries should be set")
		}
		c.SetConnRetries(2)
		if c.connRetries != 2 {
			t.Errorf("Calling c.SetConnRetries(%q) failed", 2)
		}
		c.SetConnRetries(-2)
		if c.connRetries != 0 {
			t.Errorf("Preventing negative values in c.SetConnRetries(%q) failed", -2)
		}
	} else {
		t.Skip("skipping test; $AVAST_ADDRESS not set")
	}
}

func TestBasicError(t *testing.T) {
	_, e := NewClient("", 5*time.Second, 10*time.Second)
	if e == nil {
		t.Fatalf("An error should not be returned")
	}
	expected := fmt.Sprintf(unixSockErr, AvastSock)
	if e.Error() != expected {
		t.Errorf("Got %q want %q", e, expected)
	}
}

func TestScan(t *testing.T) {
	address := os.Getenv("AVAST_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		fn := "/var/spool/testfiles/eicar.tar.bz2"
		s, e := c.Scan(fn)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		for _, rt := range s {
			if rt.Filename != fn {
				t.Errorf("c.Scan(%q) = %q, want %q", fn, rt.Filename, fn)
			}
		}
	} else {
		t.Skip("skipping test; $AVAST_ADDRESS not set")
	}
}

func TestVps(t *testing.T) {
	address := os.Getenv("AVAST_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		i, e := c.Vps()
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if i == 0 {
			t.Errorf("Vps() should not return 0")
		}
	} else {
		t.Skip("skipping test; $AVAST_ADDRESS not set")
	}
}

func TestPack(t *testing.T) {
	address := os.Getenv("AVAST_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		i, e := c.GetPack()
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if strings.HasPrefix(i, Mime.Enable()) {
			t.Errorf("c.GetPack() = %q, should start with %q", i, Mime.Enable())
		}
		e = c.SetPack(Mime, false)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		i, e = c.GetPack()
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if strings.HasPrefix(i, Mime.Disable()) {
			t.Errorf("c.GetPack() = %q, should start with %q", i, Mime.Disable())
		}
		e = c.SetPack(Mime, true)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		i, e = c.GetPack()
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if strings.HasPrefix(i, Mime.Enable()) {
			t.Errorf("c.GetPack() = %q, should start with %q", i, Mime.Enable())
		}
	} else {
		t.Skip("skipping test; $AVAST_ADDRESS not set")
	}
}

func TestFlagsOp(t *testing.T) {
	address := os.Getenv("AVAST_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		i, e := c.GetFlags()
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if strings.HasPrefix(i, FullFiles.Disable()) {
			t.Errorf("c.GetFlags() = %q, should start with %q", i, FullFiles.Disable())
		}
		e = c.SetFlags(FullFiles, true)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		i, e = c.GetFlags()
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if strings.HasPrefix(i, FullFiles.Enable()) {
			t.Errorf("c.GetFlags() = %q, should start with %q", i, FullFiles.Enable())
		}
		e = c.SetFlags(FullFiles, false)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		i, e = c.GetFlags()
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if strings.HasPrefix(i, FullFiles.Disable()) {
			t.Errorf("c.GetFlags() = %q, should start with %q", i, FullFiles.Disable())
		}
	} else {
		t.Skip("skipping test; $AVAST_ADDRESS not set")
	}
}

func TestSensitivityOp(t *testing.T) {
	address := os.Getenv("AVAST_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		i, e := c.GetSensitivity()
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if strings.HasPrefix(i, Worm.Enable()) {
			t.Errorf("c.GetSensitivity() = %q, want %q", i, Worm.Enable())
		}
		e = c.SetSensitivity(Worm, false)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		i, e = c.GetSensitivity()
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if strings.HasPrefix(i, Worm.Disable()) {
			t.Errorf("c.GetSensitivity() = %q, want %q", i, Worm.Disable())
		}
		e = c.SetSensitivity(Worm, true)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		i, e = c.GetSensitivity()
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if strings.HasPrefix(i, Worm.Enable()) {
			t.Errorf("c.GetSensitivity() = %q, want %q", i, Worm.Enable())
		}
	} else {
		t.Skip("skipping test; $AVAST_ADDRESS not set")
	}
}

func TestExclude(t *testing.T) {
	address := os.Getenv("AVAST_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		i, e := c.GetExclude()
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if i != "" {
			t.Errorf("c.GetExclude() = %q, want %q", i, "")
		}
		fp := "/root"
		e = c.SetExclude(fp)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		i, e = c.GetExclude()
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if i != fp {
			t.Errorf("c.GetExclude() = %q, want %q", i, fp)
		}
	} else {
		t.Skip("skipping test; $AVAST_ADDRESS not set")
	}
}

func TestCheckURL(t *testing.T) {
	address := os.Getenv("AVAST_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		i, e := c.CheckURL("http://www.google.com")
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if i {
			t.Errorf(`CheckURL("http://www.google.com") should not return false`)
		}
		i, e = c.CheckURL("http://www.avast.com/eng/test-url-blocker.html")
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if !i {
			t.Errorf(`CheckURL("http://www.avast.com/eng/test-url-blocker.html") should not return true`)
		}
	} else {
		t.Skip("skipping test; $AVAST_ADDRESS not set")
	}
}
