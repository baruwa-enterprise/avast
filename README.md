# avastd

Golang Avastd Client

[![Build Status](https://travis-ci.org/baruwa-enterprise/avastd.svg?branch=master)](https://travis-ci.org/baruwa-enterprise/avastd)
[![GoDoc](https://godoc.org/github.com/baruwa-enterprise/avastd?status.svg)](https://godoc.org/github.com/baruwa-enterprise/avastd)
[![MPLv2 License](https://img.shields.io/badge/license-MPLv2-blue.svg?style=flat-square)](https://www.mozilla.org/MPL/2.0/)

## Description

avastd is a Golang library and cmdline tool that implements the
Avastd client protocol.

## Requirements

* Golang 1.10.x or higher

## Getting started

### Avastd client

The avastd client can be installed as follows

```console
$ go get github.com/baruwa-enterprise/avastd/cmd/avastdscan
```

Or by cloning the repo and then running

```console
$ make build
$ ./bin/avastdscan
```

### Avastd library

To install the library

```console
go get get github.com/baruwa-enterprise/avastd
```

You can then import it in your code

```golang
import "github.com/baruwa-enterprise/avastd"
```

### Testing

``make test``

## License

MPL-2.0
