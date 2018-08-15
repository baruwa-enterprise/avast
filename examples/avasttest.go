// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package main Golang Avast client
Avast - Golang Avast test program
*/
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"sync"
	"time"

	"github.com/baruwa-enterprise/avast"
	flag "github.com/spf13/pflag"
)

var (
	address string
	cmdName string
)

func init() {
	cmdName = path.Base(os.Args[0])
	flag.StringVarP(&address, "address", "S", "/Users/andrew/avast.sock",
		`Specify Avast unix socket to connect to.`)
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", cmdName)
	fmt.Fprint(os.Stderr, "\nOptions:\n")
	flag.PrintDefaults()
}

func version(c *avast.Client) {
	v, e := c.Vps()
	if e != nil {
		log.Println("ERROR:", e)
		return
	}
	fmt.Println("VPS=>", v)
}

func versiongr(c *avast.Client, w *sync.WaitGroup) {
	defer func() {
		w.Done()
	}()
	version(c)
}

func pack(c *avast.Client) {
	p, e := c.GetPack()
	if e != nil {
		log.Println("ERROR:", e)
		return
	}
	fmt.Println("PACK=>", p)
}

func getflag(c *avast.Client) {
	f, e := c.GetFlags()
	if e != nil {
		log.Println("ERROR:", e)
		return
	}
	fmt.Println("FLAGS=>", f)
}

func getSensi(c *avast.Client) {
	f, e := c.GetSensitivity()
	if e != nil {
		log.Println("ERROR:", e)
		return
	}
	fmt.Println("SENSI=>", f)
}

func setPack(c *avast.Client, v bool) {
	e := c.SetPack(avast.Mime, v)
	if e != nil {
		log.Println("SET PACK ERROR:", e)
		return
	}
}

func setFlag(c *avast.Client, v bool) {
	e := c.SetFlags(avast.FullFiles, v)
	if e != nil {
		log.Println("SET FLAGS ERROR:", e)
		return
	}
}

func setSensi(c *avast.Client, v bool) {
	e := c.SetSensitivity(avast.Worm, v)
	if e != nil {
		log.Println("SET SENSI ERROR:", e)
		return
	}
}

func packgr(c *avast.Client, w *sync.WaitGroup) {
	defer func() {
		w.Done()
	}()

	pack(c)
}

func main() {
	// var s string
	flag.Usage = usage
	flag.ErrHelp = errors.New("")
	flag.CommandLine.SortFlags = false
	flag.Parse()
	c, e := avast.NewClient(address)
	if e != nil {
		log.Println(e)
		return
	}
	defer c.Close()
	c.SetConnTimeout(5 * time.Second)
	var wg sync.WaitGroup
	wg.Add(1)
	go versiongr(c, &wg)
	wg.Add(1)
	go packgr(c, &wg)
	wg.Wait()

	// Run in main goroutine
	version(c)
	pack(c)
	setPack(c, false)
	pack(c)
	setPack(c, true)
	pack(c)
	getflag(c)
	setFlag(c, true)
	getflag(c)
	setFlag(c, false)
	getflag(c)
	getSensi(c)
	setSensi(c, false)
	getSensi(c)
	setSensi(c, true)
	getSensi(c)
	fmt.Println("Done")
}