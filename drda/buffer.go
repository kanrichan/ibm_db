package drda

import "bytes"

type Reader bytes.Reader

func (r *Reader) ReadByte() (byte, error) {
	return (*bytes.Reader)(r).ReadByte()
}

func (r *Reader) ReadUint8() (uint8, error) {
	b, err := (*bytes.Reader)(r).ReadByte()
	return uint8(b), err
}

// func (r *Reader) ReadUint16() (uint16, error) {

// }
