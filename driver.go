package main

import (
	"database/sql"
	"database/sql/driver"
)

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
func (driver *Driver) Open(name string) (driver.Conn, error) {
	return &Conn{}, nil
}
