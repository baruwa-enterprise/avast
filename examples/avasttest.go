// Copyright (C) 2018-2021 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package main Golang Avast client
Avast - Golang Avast test program
*/
package main

import (
	"context"
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

func getExclude(c *avast.Client) {
	f, e := c.GetExclude()
	if e != nil {
		log.Println("ERROR:", e)
		return
	}
	fmt.Println("EXCLUDE=>", f)
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

func setExclude(c *avast.Client) {
	e := c.SetExclude("/root")
	if e != nil {
		log.Println("SET EXCLUDE ERROR:", e)
		return
	}
}

func checkURL(c *avast.Client, u string) {
	b, e := c.CheckURL(u)
	if e != nil {
		log.Println("CheckURL ERROR:", e)
		return
	}
	if b {
		fmt.Println("CheckURL", u, "is blocked")
	} else {
		fmt.Println("CheckURL", u, "is not blocked")
	}
}

func packgr(c *avast.Client, w *sync.WaitGroup) {
	defer func() {
		w.Done()
	}()

	pack(c)
}

func scanv(c *avast.Client) {
	s, e := c.Scan("/var/spool/testfiles/eicar.tar.bz2")
	if e != nil {
		log.Println("ERROR:", e)
		return
	}
	for _, rt := range s {
		fmt.Printf("Scan:\t\t%s\naname\t\t=>\t%s\nstatus\t\t=>\t%s\nsignature\t\t=>\t%s\ninfected\t\t=>\t%t\n",
			rt.Filename, rt.ArchiveItem, rt.Status, rt.Signature, rt.Infected)
		// fmt.Println("RAW=>", rt.Raw)
	}
}

func scan(c *avast.Client, w *sync.WaitGroup) {
	defer func() {
		w.Done()
	}()

	s, e := c.Scan("/var/spool/testfiles")
	if e != nil {
		log.Println("ERROR:", e)
		return
	}
	for _, rt := range s {
		fmt.Printf("Scan:\t\t%s\naname\t\t=>\t%s\nstatus\t\t=>\t%s\nsignature\t\t=>\t%s\ninfected\t\t=>\t%t\n",
			rt.Filename, rt.ArchiveItem, rt.Status, rt.Signature, rt.Infected)
		// fmt.Println("RAW=>", rt.Raw)
	}
}

func main() {
	// var s string
	flag.Usage = usage
	flag.ErrHelp = errors.New("")
	flag.CommandLine.SortFlags = false
	flag.Parse()
	ctx := context.Background()
	c, e := avast.NewClient(ctx, address, avast.DefaultTimeout, 30*time.Second)
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
	wg.Add(1)
	go scan(c, &wg)
	wg.Wait()

	// Run in main goroutine
	scanv(c)
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
	getExclude(c)
	setExclude(c)
	getExclude(c)
	checkURL(c, "http://www.google.com")
	checkURL(c, "http://www.avast.com/eng/test-url-blocker.html")
	fmt.Println("Done")
}
