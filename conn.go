package main

import (
	"bytes"
	"errors"
	"net"
)

type Conn struct {
	conn net.Conn

	addr   string
	dbname string
	userid string
	passwd string
}

func NewConnect(addr, dbname, userid, passwd string) (*Conn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Conn{
		conn:   conn,
		dbname: dbname,
		userid: userid,
		passwd: passwd,
	}, nil
}

func (conn *Conn) Write(drdas ...*DRDA) error {
	var buf = bytes.NewBuffer(make([]byte, 0))
	var point int
	for _, drda := range drdas {
		point = buf.Len()
		buf.WriteByte(0x00)
		buf.WriteByte(0x00)            // Length
		buf.WriteByte(drda.DDM.Magic)  // Magic
		buf.WriteByte(drda.DDM.Format) // Format
		buf.WriteByte(byte((drda.DDM.CorrelId & 0xFF00) >> 8))
		buf.WriteByte(byte(drda.DDM.CorrelId & 0x00FF)) // CorrelId
		buf.WriteByte(0x00)
		buf.WriteByte(0x00) // Length2
		buf.WriteByte(byte((drda.DDM.CodePoint & 0xff00) >> 8))
		buf.WriteByte(byte(drda.DDM.CodePoint & 0x00ff)) // codePoint
		var subpoint int
		for _, parameter := range drda.Parameters {
			subpoint = buf.Len()
			buf.WriteByte(0x00)
			buf.WriteByte(0x00) // Length
			buf.WriteByte(byte((parameter.CodePoint & 0xff00) >> 8))
			buf.WriteByte(byte(parameter.CodePoint & 0x00ff)) // CodePoint
			buf.Write(parameter.Payload)                      // Payload
			var b = buf.Bytes()
			var l = len(b) - subpoint
			b[subpoint] = byte((l & 0xff00) >> 8)
			b[subpoint+1] = byte(l & 0x00ff) // Length
		}
		var b = buf.Bytes()
		var l1 = len(b) - point
		b[point] = byte((l1 & 0xff00) >> 8)
		b[point+1] = byte(l1 & 0x00ff) // Length
		b[point+6] = byte(((l1 - 6) & 0xff00) >> 8)
		b[point+7] = byte((l1 - 6) & 0x00ff) // Length2
	}
	conn.conn.Write(buf.Bytes())
	return nil
}

func (conn *Conn) Read() (*DRDA, error) {
	var b1 = make([]byte, 2)
	n, err := conn.conn.Read(b1)
	if n != 2 {
		return &DRDA{}, errors.New("Read DRDA DMM length declare not 2 bit")
	}
	var length = (int32(b1[0]) << 8) | int32(b1[1])
	var b2 = make([]byte, length-2)
	n, err = conn.conn.Read(b2)
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
		if pl == 0 {
			// DATA
			for ; i+4+int(pl) < len(b2); pl++ {
				if b2[i+4+int(pl)] == 0xff {
					break
				}
			}
		}
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
