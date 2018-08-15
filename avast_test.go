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
	"go/build"
	"os"
	"path"
	"testing"
	"time"
)

type CommandTestKey struct {
	in  Command
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

func TestCommand(t *testing.T) {
	for _, tt := range TestCommands {
		if s := tt.in.String(); s != tt.out {
			t.Errorf("%q.String() = %q, want %q", tt.in, s, tt.out)
		}
	}
}

func TestBasics(t *testing.T) {
	c, e := NewClient("")
	if e == nil {
		t.Errorf("An error should be returned")
	}
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = build.Default.GOPATH
	}
	fn := path.Join(gopath, "src/github.com/baruwa-enterprise/avast/README.md")
	c, e = NewClient(fn)
	if e != nil {
		t.Errorf("An error should not be returned")
	}
	if c.address != fn {
		t.Errorf("Got %q want %q", c.address, fn)
	}
	if c.connTimeout != defaultTimeout {
		t.Errorf("The default conn timeout should be set")
	}
	if c.connSleep != defaultSleep {
		t.Errorf("The default conn sleep should be set")
	}
	if c.connRetries != 0 {
		t.Errorf("The default conn retries should be set")
	}
	expected := 2 * time.Second
	c.SetConnTimeout(expected)
	if c.connTimeout != expected {
		t.Errorf("Calling c.SetConnTimeout(%q) failed", expected)
	}
	c.SetCmdTimeout(expected)
	if c.cmdTimeout != expected {
		t.Errorf("Calling c.SetCmdTimeout(%q) failed", expected)
	}
	c.SetConnSleep(expected)
	if c.connSleep != expected {
		t.Errorf("Calling c.SetConnSleep(%q) failed", expected)
	}
	c.SetConnRetries(2)
	if c.connRetries != 2 {
		t.Errorf("Calling c.SetConnRetries(%q) failed", 2)
	}
	c.SetConnRetries(-2)
	if c.connRetries != 0 {
		t.Errorf("Preventing negative values in c.SetConnRetries(%q) failed", -2)
	}
	if _, e = NewClient("fe80::879:d85f:f836:1b56%en1"); e == nil {
		t.Errorf("An error should be returned")
	} else {
		expect := "The unix socket: fe80::879:d85f:f836:1b56%en1 does not exist"
		if e.Error() != expect {
			t.Errorf("Got %q want %q", e, expect)
		}
	}
}
