# avast

Golang Avast Client

[![Build Status](https://travis-ci.org/baruwa-enterprise/avast.svg?branch=master)](https://travis-ci.org/baruwa-enterprise/avast)
[![Go Report Card](https://goreportcard.com/badge/github.com/baruwa-enterprise/avast)](https://goreportcard.com/report/github.com/baruwa-enterprise/avast)
[![GoDoc](https://godoc.org/github.com/baruwa-enterprise/avast?status.svg)](https://godoc.org/github.com/baruwa-enterprise/avast)
[![MPLv2 License](https://img.shields.io/badge/license-MPLv2-blue.svg?style=flat-square)](https://www.mozilla.org/MPL/2.0/)

## Description

avast is a Golang library and cmdline tool that implements the
Avast client protocol.

## Requirements

* Golang 1.10.x or higher

## Getting started

### Avast client

The avast client can be installed as follows

```console
$ go get github.com/baruwa-enterprise/avast/cmd/avastscan
```

Or by cloning the repo and then running

```console
$ make build
$ ./bin/avastscan
```

### Avast library

To install the library

```console
go get get github.com/baruwa-enterprise/avast
```

You can then import it in your code

```golang
import "github.com/baruwa-enterprise/avast"
```

### Testing

Set `AVAST_ADDRESS` to point to your avast socket

```consule
AVAST_ADDRESS="/var/run/avast/scan.sock"
make test
```

## License

MPL-2.0
