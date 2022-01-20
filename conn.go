package drda

import (
	"bytes"
	"errors"
	"net"
)

type Conn struct {
	conn net.Conn
}

func NewConnect(addr string) (*Conn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Conn{conn}, nil
}

func (conn *Conn) Write(drda *DRDA) error {
	var dbuf = bytes.NewBuffer(make([]byte, 0))
	dbuf.WriteByte(0x00)
	dbuf.WriteByte(0x00)            // Length
	dbuf.WriteByte(drda.DDM.Magic)  // Magic
	dbuf.WriteByte(drda.DDM.Format) // Format
	dbuf.WriteByte(byte((drda.DDM.CorrelId & 0xFF00) >> 8))
	dbuf.WriteByte(byte(drda.DDM.CorrelId & 0x00FF)) // CorrelId
	dbuf.WriteByte(0x00)
	dbuf.WriteByte(0x00) // Length2
	dbuf.WriteByte(byte((drda.DDM.CodePoint & 0xff00) >> 8))
	dbuf.WriteByte(byte(drda.DDM.CodePoint & 0x00ff)) // codePoint
	for _, parameter := range drda.Parameters {
		var pbuf = bytes.NewBuffer(make([]byte, 0))
		pbuf.WriteByte(0x00)
		pbuf.WriteByte(0x00) // Length
		pbuf.WriteByte(byte((parameter.CodePoint & 0xff00) >> 8))
		pbuf.WriteByte(byte(parameter.CodePoint & 0x00ff)) // CodePoint
		pbuf.Write(parameter.Payload)                      // Payload
		var b = pbuf.Bytes()
		var l = len(b)
		b[0] = byte((l & 0xff00) >> 8)
		b[1] = byte(l & 0x00ff) // Length
		dbuf.Write(b)
	}
	var b = dbuf.Bytes()
	var l1 = len(b)
	b[0] = byte((l1 & 0xff00) >> 8)
	b[1] = byte(l1 & 0x00ff) // Length
	b[6] = byte(((l1 - 6) & 0xff00) >> 8)
	b[7] = byte((l1 - 6) & 0x00ff) // Length2
	conn.conn.Write(b)
	return nil
}

func (conn *Conn) Read() (*DRDA, error) {
	var b1 = make([]byte, 2)
	conn.conn.Read(b1)
	var length = (int32(b1[0]) << 8) | int32(b1[1])
	var b2 = make([]byte, length-2)
	n, err := conn.conn.Read(b2)
	if err != nil {
		return &DRDA{}, err
	}
	if n != int(length-2) {
		return &DRDA{}, errors.New("Read DRDA payload not enough length")
	}
	var ddm = &DDM{
		Length:    length,
		Magic:     b2[0],
		Format:    b2[1],
		CorrelId:  (int32(b2[2]) << 8) | int32(b2[3]),
		Length2:   (int32(b2[4]) << 8) | int32(b2[5]),
		CodePoint: (int32(b2[6]) << 8) | int32(b2[7]),
	}
	var drda = DRDA{
		DDM:        ddm,
		Parameters: make([]*Parameter, 0),
	}
	for i := 8; i < len(b2); {
		var pl = (int32(b2[i]) << 8) | int32(b2[i+1])
		drda.Parameters = append(drda.Parameters,
			&Parameter{
				Length:    pl,
				CodePoint: (int32(b2[i+2]) << 8) | int32(b2[i+3]),
				Payload:   b2[i+4 : i+int(pl)],
			},
		)
		i += int(pl)
	}
	return &drda, nil
}

func (conn *Conn) Close() error {
	return conn.conn.Close()
}
