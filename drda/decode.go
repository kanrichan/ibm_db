package drda

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Decoder Decoder
type Decoder struct {
	r io.Reader
}

// Unmarshal Unmarshal
func Unmarshal(data []byte, v any) error {
	return NewDecoder(bytes.NewReader(data)).Decode(v)
}

// NewDecoder NewDecoder
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r}
}

// Decode Decode
func (dec *Decoder) Decode(v any) error {
	switch obj := v.(type) {
	case *SQLCAXGRP:
		return dec.DecodeSQLCAXGRP(obj)
	case *SQLCAGRP:
		return dec.DecodeSQLCAGRP(obj)
	case *SQLDHGRP:
		return dec.DecodeSQLDHGRP(obj)
	case *SQLDXGRP:
		return dec.DecodeSQLDXGRP(obj)
	case *SQLUDTGRP:
		return dec.DecodeSQLUDTGRP(obj)
	case *SQLDOPTGRP:
		return dec.DecodeSQLDOPTGRP(obj)
	case *SQLDAGRP:
		return dec.DecodeSQLDAGRP(obj)
	case *SQLDARD:
		return dec.DecodeSQLDARD(obj)
	default:
		return errors.New("unsupported type")
	}
}

// DecodeSQLCAXGRP DecodeSQLCAXGRP
func (dec *Decoder) DecodeSQLCAXGRP(v *SQLCAXGRP) error {
	var err error
	v.ROWSFETCHED, err = dec.ReadUint64()
	if err != nil {
		return errors.New("SQLCAXGRP.ROWSFETCHED " + err.Error())
	}
	v.ROWSUPDATED, err = dec.ReadUint32()
	if err != nil {
		return errors.New("SQLCAXGRP.ROWSUPDATED " + err.Error())
	}
	err = dec.ReadByteArray(v.SQLERRD[:])
	if err != nil {
		return errors.New("SQLCAXGRP.SQLERRD " + err.Error())
	}
	err = dec.ReadByteArray(v.SQLWARN[:])
	if err != nil {
		return errors.New("SQLCAXGRP.SQLWARN " + err.Error())
	}
	v.SQLRDBNAME, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLCAXGRP.SQLRDBNAME " + err.Error())
	}
	v.SQLERRMSGM, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLCAXGRP.SQLERRMSGM " + err.Error())
	}
	v.SQLERRMSGS, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLCAXGRP.SQLERRMSGS " + err.Error())
	}
	return nil
}

// DecodeSQLCAGRP DecodeSQLCAGRP
func (dec *Decoder) DecodeSQLCAGRP(v *SQLCAGRP) error {
	var err error
	err = dec.ReadByteArray(v.SQLSTATE[:])
	if err != nil {
		return errors.New("SQLCAGRP.SQLSTATE " + err.Error())
	}
	err = dec.ReadByteArray(v.SQLERRPROC[:])
	if err != nil {
		return errors.New("SQLCAGRP.SQLERRPROC " + err.Error())
	}
	v.SQLCAXGRPFLAG, err = dec.ReadUint8()
	if err != nil {
		return errors.New("SQLCAGRP.SQLCAXGRPFLAG " + err.Error())
	}
	if v.SQLCAXGRPFLAG != 0xFF {
		v.SQLCAXGRP = &SQLCAXGRP{}
		err = dec.DecodeSQLCAXGRP(v.SQLCAXGRP)
		if err != nil {
			return errors.New("SQLCAGRP.SQLCAXGRP " + err.Error())
		}
	}
	return nil
}

// DecodeSQLDHGRP DecodeSQLDHGRP
func (dec *Decoder) DecodeSQLDHGRP(v *SQLDHGRP) error {
	var err error
	v.SQLDHOLD, err = dec.ReadUint16()
	if err != nil {
		return errors.New("SQLDHGRP.SQLDHOLD " + err.Error())
	}
	v.SQLDRETURN, err = dec.ReadUint16()
	if err != nil {
		return errors.New("SQLDHGRP.SQLDRETURN " + err.Error())
	}
	v.SQLDSCROLL, err = dec.ReadUint16()
	if err != nil {
		return errors.New("SQLDHGRP.SQLDSCROLL " + err.Error())
	}
	v.SQLDSENSITIVE, err = dec.ReadUint16()
	if err != nil {
		return errors.New("SQLDHGRP.SQLDSENSITIVE " + err.Error())
	}
	v.SQLDFCODE, err = dec.ReadUint16()
	if err != nil {
		return errors.New("SQLDHGRP.SQLDFCODE " + err.Error())
	}
	v.SQLDKEYTYPE, err = dec.ReadUint16()
	if err != nil {
		return errors.New("SQLDHGRP.SQLDKEYTYPE " + err.Error())
	}
	v.SQLDRDBNAM, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDHGRP.SQLDRDBNAM " + err.Error())
	}
	v.SQLDSCHEMAM, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDHGRP.SQLDSCHEMAM " + err.Error())
	}
	v.SQLDSCHEMAS, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDHGRP.SQLDSCHEMAS " + err.Error())
	}
	return nil
}

// DecodeSQLDXGRP DecodeSQLDXGRP
func (dec *Decoder) DecodeSQLDXGRP(v *SQLDXGRP) error {
	var err error
	v.SQLXKEYMEM, err = dec.ReadInt16()
	if err != nil {
		return errors.New("SQLDXGRP.SQLXKEYMEM " + err.Error())
	}
	v.SQLXUPDATEABLE, err = dec.ReadInt16()
	if err != nil {
		return errors.New("SQLDXGRP.SQLXUPDATEABLE " + err.Error())
	}
	v.SQLXGENERATED, err = dec.ReadInt16()
	if err != nil {
		return errors.New("SQLDXGRP.SQLXGENERATED " + err.Error())
	}
	v.SQLXPARMMODE, err = dec.ReadInt16()
	if err != nil {
		return errors.New("SQLDXGRP.SQLXPARMMODE " + err.Error())
	}
	v.SQLXRDBNAM, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDXGRP.SQLXRDBNAM " + err.Error())
	}
	v.SQLXCORNAMEM, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDXGRP.SQLXCORNAMEM " + err.Error())
	}
	v.SQLXCORNAMES, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDXGRP.SQLXCORNAMES " + err.Error())
	}
	v.SQLXBASENAMEM, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDXGRP.SQLXBASENAMEM " + err.Error())
	}
	v.SQLXBASENAMES, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDXGRP.SQLXBASENAMES " + err.Error())
	}
	v.SQLXSCHEMAM, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDXGRP.SQLXSCHEMAM " + err.Error())
	}
	v.SQLXSCHEMAS, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDXGRP.SQLXSCHEMAS " + err.Error())
	}
	v.SQLXNAMEM, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDXGRP.SQLXNAMEM " + err.Error())
	}
	v.SQLXNAMES, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDXGRP.SQLXNAMES " + err.Error())
	}
	return nil
}

// DecodeSQLUDTGRP DecodeSQLUDTGRP
func (dec *Decoder) DecodeSQLUDTGRP(v *SQLUDTGRP) error {
	var err error
	v.SQLUDTXTYPE, err = dec.ReadInt16()
	if err != nil {
		return errors.New("SQLUDTGRP.SQLUDTXTYPE " + err.Error())
	}
	v.SQLUDTRDB, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLUDTGRP.SQLUDTRDB " + err.Error())
	}
	v.SQLUDTSCHEMAM, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLUDTGRP.SQLUDTSCHEMAM " + err.Error())
	}
	v.SQLUDTSCHEMAS, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLUDTGRP.SQLUDTSCHEMAS " + err.Error())
	}
	v.SQLUDTNAMEM, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLUDTGRP.SQLUDTNAMEM " + err.Error())
	}
	v.SQLUDTNAMES, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLUDTGRP.SQLUDTNAMES " + err.Error())
	}
	v.SQLDXGRPFLAG, err = dec.ReadUint8()
	if err != nil {
		return errors.New("SQLUDTGRP.SQLDXGRPFLAG " + err.Error())
	}
	if v.SQLDXGRPFLAG != 0xFF {
		v.SQLDXGRP = &SQLDXGRP{}
		err = dec.DecodeSQLDXGRP(v.SQLDXGRP)
		if err != nil {
			return errors.New("SQLUDTGRP.SQLDXGRP " + err.Error())
		}
	}
	return nil
}

// DecodeSQLDOPTGRP DecodeSQLDOPTGRP
func (dec *Decoder) DecodeSQLDOPTGRP(v *SQLDOPTGRP) error {
	var err error
	v.SQLUNNAMED, err = dec.ReadUint16()
	if err != nil {
		return errors.New("SQLDOPTGRP.SQLUNNAMED " + err.Error())
	}
	v.SQLNAMEM, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDOPTGRP.SQLNAMEM " + err.Error())
	}
	v.SQLNAMES, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDOPTGRP.SQLNAMES " + err.Error())
	}
	var bbb = make([]byte, 1024)
	dec.r.Read(bbb)
	fmt.Printf("% x\n", bbb)
	v.SQLLABELM, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDOPTGRP.SQLLABELM " + err.Error())
	}
	v.SQLLABELS, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDOPTGRP.SQLLABELS " + err.Error())
	}
	v.SQLCOMMENTSM, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDOPTGRP.SQLCOMMENTSM " + err.Error())
	}
	v.SQLCOMMENTSS, err = dec.ReadString()
	if err != nil {
		return errors.New("SQLDOPTGRP.SQLCOMMENTSS " + err.Error())
	}
	v.SQLUDTGRPFLAG, err = dec.ReadUint8()
	if err != nil {
		return errors.New("SQLDOPTGRP.SQLUDTGRPFLAG " + err.Error())
	}
	if v.SQLUDTGRPFLAG != 0xFF {
		v.SQLUDTGRP = &SQLUDTGRP{}
		err = dec.DecodeSQLUDTGRP(v.SQLUDTGRP)
		if err != nil {
			return errors.New("SQLDOPTGRP.SQLUDTGRP " + err.Error())
		}
	}
	return nil
}

// DecodeSQLDAGRP DecodeSQLDAGRP
func (dec *Decoder) DecodeSQLDAGRP(v *SQLDAGRP) error {
	var err error
	v.SQLPRECISION, err = dec.ReadUint16()
	if err != nil {
		return errors.New("SQLDAGRP.SQLPRECISION " + err.Error())
	}
	v.SQLSCALE, err = dec.ReadUint16()
	if err != nil {
		return errors.New("SQLDAGRP.SQLSCALE " + err.Error())
	}
	v.SQLLENGTH, err = dec.ReadUint64()
	if err != nil {
		return errors.New("SQLDAGRP.SQLLENGTH " + err.Error())
	}
	v.SQLTYPE, err = dec.ReadUint16()
	if err != nil {
		return errors.New("SQLDAGRP.SQLTYPE " + err.Error())
	}
	v.SQLCCSID, err = dec.ReadUint16()
	if err != nil {
		return errors.New("SQLDAGRP.SQLCCSID " + err.Error())
	}
	v.SQLDOPTGRPFLAG, err = dec.ReadUint8()
	if err != nil {
		return errors.New("SQLDAGRP.SQLDOPTGRPFLAG " + err.Error())
	}
	if v.SQLDOPTGRPFLAG != 0xFF {
		v.SQLDOPTGRP = &SQLDOPTGRP{}
		err = dec.DecodeSQLDOPTGRP(v.SQLDOPTGRP)
		if err != nil {
			return errors.New("SQLDAGRP.SQLDOPTGRP " + err.Error())
		}
	}
	return nil
}

// DecodeSQLDARD DecodeSQLDARD
func (dec *Decoder) DecodeSQLDARD(v *SQLDARD) error {
	var err error
	v.SQLCAGRPFLAG, err = dec.ReadUint8()
	if err != nil {
		return errors.New("SQLDARD.SQLCAGRPFLAG " + err.Error())
	}
	if v.SQLCAGRPFLAG != 0xFF {
		v.SQLCAGRP = &SQLCAGRP{}
		err = dec.DecodeSQLCAGRP(v.SQLCAGRP)
		if err != nil {
			return errors.New("SQLDARD.SQLCAGRP " + err.Error())
		}
	}
	v.SQLDHGRPFLAG, err = dec.ReadUint8()
	if err != nil {
		return errors.New("SQLDARD.SQLDHGRPFLAG " + err.Error())
	}
	if v.SQLDHGRPFLAG != 0xFF {
		v.SQLDHGRP = &SQLDHGRP{}
		err = dec.DecodeSQLDHGRP(v.SQLDHGRP)
		if err != nil {
			return errors.New("SQLDARD.SQLDHGRP " + err.Error())
		}
	}
	v.SQLNUMBRP, err = dec.ReadUint16()
	if err != nil {
		return errors.New("SQLDARD.SQLNUMBRP " + err.Error())
	}
	v.SQLDAGRP = make([]*SQLDAGRP, v.SQLNUMBRP)
	for i := 0; i < int(v.SQLNUMBRP); i++ {
		v.SQLDAGRP[i] = &SQLDAGRP{}
		err = dec.DecodeSQLDAGRP(v.SQLDAGRP[i])
		if err != nil {
			return errors.New("SQLDARD.SQLDAGRP " + err.Error())
		}
	}
	return nil
}

// ReadBool ReadBool
func (dec *Decoder) ReadBool() (bool, error) {
	u8, err := dec.ReadUint8()
	return u8 != 0, err
}

// ReadInt8 ReadInt8
func (dec *Decoder) ReadInt8() (int8, error) {
	var b = make([]byte, 1)
	n, err := dec.r.Read(b)
	if err != nil {
		return 0, err
	}
	if n != 1 {
		return 0, io.EOF
	}
	return int8(b[0]), nil
}

// ReadInt16 ReadInt16
func (dec *Decoder) ReadInt16() (int16, error) {
	var b = make([]byte, 2)
	n, err := dec.r.Read(b)
	if err != nil {
		return 0, err
	}
	if n != 2 {
		return 0, io.EOF
	}
	return int16(binary.BigEndian.Uint16(b)), nil
}

// ReadInt32 ReadInt32
func (dec *Decoder) ReadInt32() (int32, error) {
	var b = make([]byte, 4)
	n, err := dec.r.Read(b)
	if err != nil {
		return 0, err
	}
	if n != 4 {
		return 0, io.EOF
	}
	return int32(binary.BigEndian.Uint32(b)), nil
}

// ReadInt64 ReadInt64
func (dec *Decoder) ReadInt64() (int64, error) {
	var b = make([]byte, 8)
	n, err := dec.r.Read(b)
	if err != nil {
		return 0, err
	}
	if n != 8 {
		return 0, io.EOF
	}
	return int64(binary.BigEndian.Uint64(b)), nil
}

// ReadUint8 ReadUint8
func (dec *Decoder) ReadUint8() (uint8, error) {
	var b = make([]byte, 1)
	n, err := dec.r.Read(b)
	if err != nil {
		return 0, err
	}
	if n != 1 {
		return 0, io.EOF
	}
	return b[0], nil
}

// ReadUint16 ReadUint16
func (dec *Decoder) ReadUint16() (uint16, error) {
	var b = make([]byte, 2)
	n, err := dec.r.Read(b)
	if err != nil {
		return 0, err
	}
	if n != 2 {
		return 0, io.EOF
	}
	return binary.BigEndian.Uint16(b), nil
}

// ReadUint32 ReadUint32
func (dec *Decoder) ReadUint32() (uint32, error) {
	var b = make([]byte, 4)
	n, err := dec.r.Read(b)
	if err != nil {
		return 0, err
	}
	if n != 4 {
		return 0, io.EOF
	}
	return binary.BigEndian.Uint32(b), nil
}

// ReadUint64 ReadUint64
func (dec *Decoder) ReadUint64() (uint64, error) {
	var b = make([]byte, 8)
	n, err := dec.r.Read(b)
	if err != nil {
		return 0, err
	}
	if n != 8 {
		return 0, io.EOF
	}
	return binary.BigEndian.Uint64(b), nil
}

// ReadByteSlice ReadByteSlice
func (dec *Decoder) ReadByteSlice() ([]byte, error) {
	length, err := dec.ReadInt16()
	if err != nil {
		return nil, err
	}
	var b = make([]byte, int(length))
	n, err := dec.r.Read(b)
	if err != nil {
		return nil, err
	}
	if n != int(length) {
		return nil, io.EOF
	}
	return b, nil
}

// ReadString ReadString
func (dec *Decoder) ReadString() (string, error) {
	b, err := dec.ReadByteSlice()
	return string(b), err
}

// ReadByteArray ReadByteArray
func (dec *Decoder) ReadByteArray(v []byte) error {
	n, err := dec.r.Read(v)
	if err != nil {
		return err
	}
	if n != len(v) {
		return io.EOF
	}
	return nil
}
