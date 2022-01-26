package main

import "database/sql/driver"

type Conn struct{}

// Prepare returns a prepared statement, bound to this connection.
func (conn *Conn) Prepare(query string) (driver.Stmt, error) {
	return &Stmt{}, nil
}

// Close invalidates and potentially stops any current
// prepared statements and transactions, marking this
// connection as no longer in use.
//
// Because the sql package maintains a free pool of
// connections and only calls Close when there's a surplus of
// idle connections, it shouldn't be necessary for drivers to
// do their own connection caching.
//
// Drivers must ensure all network calls made by Close
// do not block indefinitely (e.g. apply a timeout).
func (conn *Conn) Close() error {
	return nil
}

// Begin starts and returns a new transaction.
//
// Deprecated: Drivers should implement ConnBeginTx instead (or additionally).
func (conn *Conn) Begin() (driver.Tx, error) {
	return &Tx{}, nil
}
