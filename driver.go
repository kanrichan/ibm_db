package main

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/kanrichan/ibm_db/drda"
)

//go:generate go run generator/drda.go

type Driver struct{}

func init() {
	sql.Register("ibm_db", &Driver{})
}

// Open returns a new connection to the database.
// The name is a string in a driver-specific format.
//
// Open may return a cached connection (one previously
// closed), but doing so is unnecessary; the sql package
// maintains a pool of idle connections for efficient re-use.
//
// The returned connection is only used by one goroutine at a
// time.
// HOSTNAME=host;DATABASE=name;PORT=number;UID=username;PWD=password
func (driver *Driver) Open(name string) (driver.Conn, error) {
	var (
		hostname string = "127.0.0.1"
		database string
		port     int = 50000
		username string
		password string
	)
	var namespace = strings.Split(name, ";")
	for i := range namespace {
		kv := strings.Split(namespace[i], "=")
		if len(kv) != 2 {
			return nil, errors.New("invalid data source name string")
		}
		switch kv[0] {
		case "HOSTNAME":
			hostname = kv[1]
		case "DATABASE":
			database = kv[1]
		case "PORT":
			port, _ = strconv.Atoi(kv[1])
		case "UID":
			username = kv[1]
		case "PWD":
			password = kv[1]
		}
	}
	if database == "" || username == "" {
		return nil, errors.New("invalid data source name string")
	}
	conn, err := drda.NewConnect(
		fmt.Sprintf("%s:%d", hostname, port),
		database, username, password,
	)
	if err != nil {
		return nil, err
	}
	return &Conn{conn}, conn.Login()
}
