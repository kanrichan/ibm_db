package drda

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

const (
	// LOGIN
	// DRDA (Exchange Server Attributes)
	CP_EXCSAT   = 0x1041 // DDM (EXCSAT)
	CP_EXTNAM   = 0x115e // Parameter (External Name)
	CP_MGRLVLLS = 0x1404 // Parameter (Manager-Level List)
	CP_SRVCLSNM = 0x1147 // Parameter (Server Class Name)
	CP_SRVNAM   = 0x116d // Parameter (Server Name)
	CP_SRVRLSLV = 0x115a // Parameter (Server Product Release Level)

	// DRDA (Server Attributes Reply Data)
	CP_EXCSATRD = 0x1443 // DDM (EXCSATRD)

	CP_RDBNFNRM = 0x2211
	CP_SRVDGN   = 0x1153

	CP_SQLCARD = 0x2408

	// DRDA (Access Security)
	CP_ACCSEC = 0x106d // DDM (ACCSEC)
	CP_SECMEC = 0x11a2 // Parameter (Security Mechanism)
	CP_RDBNAM = 0x2110 // Parameter (Relational Database Name)
	CP_SECTKN = 0x11dc // Parameter (Security Token)

	// DRDA (Access Security Reply Data)
	CP_ACCSECRD = 0x14ac // DDM (ACCSECRD)

	CP_SQLERRRM = 0x2213

	// DRDA (Security Check)
	CP_SECCHK   = 0x106e // DDM (SECCHK)
	CP_USRID    = 0x11a0 // Parameter (User ID at the Target System)
	CP_PASSWORD = 0x11a1 // Parameter (Password)
	//CP_SECMEC = 0x11a2 // Parameter (Security Mechanism)
	//CP_RDBNAM = 0x2110 // Parameter (Relational Database Name)

	// DRDA (Access RDB)
	CP_ACCRDB    = 0x2001 // DDM (ACCRDB)
	CP_RDBACCCL  = 0x210f // Parameter (RDB Access Manager Class)
	CP_PRDID     = 0x112e // Parameter (Product-Specific Identifier)
	CP_PRDDTA    = 0x2104 // Parameter (Product-Specific Data)
	CP_TYPDEFNAM = 0x002f // Parameter (Data Type Definition Name)
	CP_TYPDEFOVR = 0x0035 // Parameter (TYPDEF Overrides)
	//CP_RDBNAM = 0x2110 // Parameter (Relational Database Name)

	// SELECT
	// DRDA (Prepare SQL Statement)
	CP_PRPSQLSTT = 0x200d // DDM (PRPSQLSTT)
	CP_PKGNAMCSN = 0x2113 // Parameter (RDB Package Name, Consistency Token, and Section Number)
	CP_RTNSQLDA  = 0x2116 // Parameter (Maximum Result Set Count)
	CP_TYPSQLDA  = 0x2146 // Parameter (Type of SQL Descriptor Area)

	// DRDA (SQL Statement Attributes)
	CP_SQLATTR = 0x2450 // DDM (SQLATTR)
	CP_DATA    = 0x0000 // Parameter (Data)

	// DRDA (SQL Statement)
	CP_SQLSTT = 0x2414 // DDM (SQLSTT)
	//CP_DATA    = 0x0000 // Parameter (Data)

	// DRDA (Open Query)
	CP_OPNQRY    = 0x200c // DDM (OPNQRY)
	CP_QRYBLKSZ  = 0x2114 // Parameter (Query Block Size)
	CP_QRYCLSIMP = 0x215d // Parameter (Query Close Implicit)
	CP_OUTOVROPT = 0x2147 // Parameter (Output Override Option)
	CP_UNKNOWN   = 0x214b // Parameter (Unknown (0x214b))
	//CP_PKGNAMCSN = 0x2113 // Parameter (RDB Package Name, Consistency Token, and Section Number)
	//CP_UNKNOWN   = 0x2137 // Parameter (Unknown (0x214b))
	//CP_UNKNOWN   = 0x2136 // Parameter (Unknown (0x214b))
	//CP_UNKNOWN   = 0x2134 // Parameter (Unknown (0x214b))

	// DRDA (RDB Commit Unit of Work)
	CP_RDBCMM = 0x200e // DDM (RDBCMM)
)

type DRDA struct {
	DDM        *DDM
	Parameters []*Parameter
}

type DDM struct {
	Length    int32
	Magic     byte
	Format    byte
	CorrelId  int32
	Length2   int32
	CodePoint int32
}

type Parameter struct {
	Length    int32
	CodePoint int32
	Payload   []byte
}

func (drda *DRDA) GetParameter(cp int32) *Parameter {
	if drda.Parameters == nil || len(drda.Parameters) == 0 {
		return nil
	}
	for _, param := range drda.Parameters {
		if param.CodePoint == cp {
			return param
		}
	}
	return nil
}

func Int32ToBytes(value int32) []byte {
	return []byte{byte((value & 0xff00) >> 8), byte(value & 0x00ff)}
}

func BytesToInt32(data []byte) int32 {
	if len(data) != 2 {
		return 0
	}
	return (int32(data[0]) << 8) | int32(data[1])
}

func WriteDRDA(drda *DRDA) ([]byte, error) {
	// DDM
	drda.DDM.Length = 10
	// Parameters
	for _, param := range drda.Parameters {
		param.Length = int32(len(param.Payload) + 4)
		drda.DDM.Length += param.Length
	}
	drda.DDM.Length2 = drda.DDM.Length - 6

	var buf = bytes.NewBuffer(make([]byte, 0))
	// DDM
	buf.Write(Int32ToBytes(drda.DDM.Length))    // Length
	buf.WriteByte(drda.DDM.Magic)               // Magic
	buf.WriteByte(drda.DDM.Format)              // Format
	buf.Write(Int32ToBytes(drda.DDM.CorrelId))  // CorrelId
	buf.Write(Int32ToBytes(drda.DDM.Length2))   // Length2
	buf.Write(Int32ToBytes(drda.DDM.CodePoint)) // CodePoint

	// Parameters
	for _, param := range drda.Parameters {
		if param.CodePoint != CP_DATA {
			buf.Write(Int32ToBytes(param.Length)) // Length
		} else {
			buf.WriteByte(0x00)
			buf.WriteByte(0x00)
		}
		buf.Write(Int32ToBytes(param.CodePoint)) // CodePoint
		buf.Write(param.Payload)
	}

	return buf.Bytes(), nil
}

func ReadDRDA(data []byte) (*DRDA, error) {
	var buf = bytes.NewBuffer(data)
	// DDM
	var drda = &DRDA{DDM: &DDM{
		Length:    BytesToInt32(buf.Next(2)), // Length
		Magic:     buf.Next(1)[0],            // Magic
		Format:    buf.Next(1)[0],            // Format
		CorrelId:  BytesToInt32(buf.Next(2)), // CorrelId
		Length2:   BytesToInt32(buf.Next(2)), // Length2
		CodePoint: BytesToInt32(buf.Next(2)), // CodePoint
	}}

	var left = drda.DDM.Length - 10
	// Parameters
	for {
		var para = &Parameter{}
		para.Length = BytesToInt32(buf.Next(2))    // Length
		para.CodePoint = BytesToInt32(buf.Next(2)) // CodePoint
		switch para.CodePoint {
		case CP_DATA:
			para.Payload = buf.Bytes()
			drda.Parameters = append(drda.Parameters, para)
			return drda, nil
		default:
			para.Payload = buf.Next(int(para.Length - 4)) // Payload
			drda.Parameters = append(drda.Parameters, para)
			left -= para.Length
			if left <= 0 {
				return drda, nil
			}
		}
	}
}

type EXCSAT struct {
	DDM        *DDM
	EXTNAM     string
	SRVNAM     string
	SRVCLSNM   string
	SRVRLSLV   string
	AGENT      int
	SQLAM      int
	RDB        int
	SECMGR     int
	CMNTCPIP   int
	UNICODEMGR int
}

func (o *EXCSAT) WriteEXCSAT() (*DRDA, error) {
	if o.DDM.CodePoint != CP_EXCSAT {
		return nil, errors.New("mismatch code point")
	}
	return &DRDA{
		DDM: o.DDM,
		Parameters: []*Parameter{
			{CodePoint: CP_EXTNAM, Payload: ToEBCDIC([]byte(o.EXTNAM))},
			{CodePoint: CP_SRVNAM, Payload: ToEBCDIC([]byte(o.SRVNAM))},
			{CodePoint: CP_SRVCLSNM, Payload: ToEBCDIC([]byte(o.SRVCLSNM))},
			{CodePoint: CP_SRVRLSLV, Payload: ToEBCDIC([]byte(o.SRVRLSLV))},
			{CodePoint: CP_MGRLVLLS, Payload: []byte{
				0x14, 0x03, byte((o.AGENT & 0xff00) >> 8), byte(o.AGENT & 0x00ff), // AGENT
				0x24, 0x07, byte((o.SQLAM & 0xff00) >> 8), byte(o.SQLAM & 0x00ff), // SQLAM
				0x24, 0x0f, byte((o.RDB & 0xff00) >> 8), byte(o.RDB & 0x00ff), // RDB
				0x14, 0x40, byte((o.SECMGR & 0xff00) >> 8), byte(o.SECMGR & 0x00ff), // SECMGR
				0x14, 0x74, byte((o.CMNTCPIP & 0xff00) >> 8), byte(o.CMNTCPIP & 0x00ff), // CMNTCPIP
				0x1c, 0x08, byte((o.UNICODEMGR & 0xff00) >> 8), byte(o.UNICODEMGR & 0x00ff), // UNICODEMGR CCSID_1208 UTF-8
			}},
		},
	}, nil
}

type PRPSQLSTT struct {
	DDM       *DDM
	RDBNAM    string
	RDBCOLID  string // NULLID
	PKGID     string // SYSSH200
	PKGCNSTKN string // SYSLVL01
	PKGSN     int16
}

func (o *PRPSQLSTT) WritePRPSQLSTT() (*DRDA, error) {
	if o.DDM.CodePoint != CP_PRPSQLSTT {
		return nil, errors.New("mismatch code point")
	}
	var buf = bytes.NewBuffer(make([]byte, 0, 64))
	buf.Write(ToEBCDIC([]byte(o.RDBNAM + strings.Repeat(" ", 18-len(o.RDBNAM)))))
	buf.Write(ToEBCDIC([]byte(o.RDBCOLID + strings.Repeat(" ", 18-len(o.RDBCOLID)))))
	buf.Write(ToEBCDIC([]byte(o.PKGID + strings.Repeat(" ", 18-len(o.PKGID)))))
	buf.WriteString(o.PKGCNSTKN)
	buf.WriteByte(byte(o.PKGSN >> 8))
	buf.WriteByte(byte(o.PKGSN))
	return &DRDA{
		DDM: o.DDM,
		Parameters: []*Parameter{
			{CodePoint: CP_PKGNAMCSN, Payload: buf.Bytes()},
			{CodePoint: CP_RTNSQLDA, Payload: []byte{0xf1}},
			{CodePoint: CP_TYPSQLDA, Payload: []byte{0x04}},
		},
	}, nil
}

type SQLSTT struct {
	DDM  *DDM
	DATA string
}

func (o *SQLSTT) WriteSQLSTT() (*DRDA, error) {
	if o.DDM.CodePoint != CP_SQLSTT {
		return nil, errors.New("mismatch code point")
	}
	var buf = bytes.NewBuffer(make([]byte, 0, len(o.DATA)+2))
	buf.WriteByte(byte(len(o.DATA)))
	buf.WriteString(o.DATA)
	buf.WriteByte(0xff)
	return &DRDA{
		DDM: o.DDM,
		Parameters: []*Parameter{
			{CodePoint: CP_DATA, Payload: buf.Bytes()},
		},
	}, nil
}

type OPNQRY struct {
	DDM       *DDM
	RDBNAM    string
	RDBCOLID  string // NULLID
	PKGID     string // SYSSH200
	PKGCNSTKN string // SYSLVL01
	PKGSN     int16
	DYNDTAFMT bool
}

func (o *OPNQRY) WriteOPNQRY() (*DRDA, error) {
	if o.DDM.CodePoint != CP_OPNQRY {
		return nil, errors.New("mismatch code point")
	}
	var buf = bytes.NewBuffer(make([]byte, 0, 64))
	buf.Write(ToEBCDIC([]byte(o.RDBNAM + strings.Repeat(" ", 18-len(o.RDBNAM)))))
	buf.Write(ToEBCDIC([]byte(o.RDBCOLID + strings.Repeat(" ", 18-len(o.RDBCOLID)))))
	buf.Write(ToEBCDIC([]byte(o.PKGID + strings.Repeat(" ", 18-len(o.PKGID)))))
	buf.WriteString(o.PKGCNSTKN)
	buf.WriteByte(byte(o.PKGSN >> 8))
	buf.WriteByte(byte(o.PKGSN))
	var t = &DRDA{
		DDM: o.DDM,
		Parameters: []*Parameter{
			{CodePoint: CP_PKGNAMCSN, Payload: buf.Bytes()},
			{CodePoint: CP_QRYBLKSZ, Payload: []byte{0x00, 0x00, 0x7f, 0xff}}, // 32767
			{CodePoint: CP_QRYCLSIMP, Payload: []byte{0x01}},
		},
	}
	if o.DYNDTAFMT {
		t.Parameters = append(
			t.Parameters,
			&Parameter{CodePoint: CP_QRYCLSIMP, Payload: []byte{0xf1}},
		)
	}
	return t, nil
}

type DSCSQLSTT struct {
	DDM       *DDM
	RDBNAM    string
	RDBCOLID  string // NULLID
	PKGID     string // SYSSH200
	PKGCNSTKN string // SYSLVL01
	PKGSN     int16
}

const CP_DSCSQLSTT = 0x2008

func (o *DSCSQLSTT) WriteDSCSQLSTT() (*DRDA, error) {
	if o.DDM.CodePoint != CP_DSCSQLSTT {
		return nil, errors.New("mismatch code point")
	}
	var buf = bytes.NewBuffer(make([]byte, 0, 64))
	buf.Write(ToEBCDIC([]byte(o.RDBNAM + strings.Repeat(" ", 18-len(o.RDBNAM)))))
	buf.Write(ToEBCDIC([]byte(o.RDBCOLID + strings.Repeat(" ", 18-len(o.RDBCOLID)))))
	buf.Write(ToEBCDIC([]byte(o.PKGID + strings.Repeat(" ", 18-len(o.PKGID)))))
	buf.WriteString(o.PKGCNSTKN)
	buf.WriteByte(byte(o.PKGSN >> 8))
	buf.WriteByte(byte(o.PKGSN))
	return &DRDA{
		DDM: o.DDM,
		Parameters: []*Parameter{
			{CodePoint: CP_PKGNAMCSN, Payload: buf.Bytes()},
			{CodePoint: CP_RTNSQLDA, Payload: []byte{0xf1}},
			{CodePoint: CP_TYPSQLDA, Payload: []byte{0x04}},
		},
	}, nil
}

type SQLDTA struct {
	DDM  *DDM
	Data []struct {
		Type  byte
		Len   int16
		Value []byte
	}
}

const CP_SQLDTA = 0x2412
const CP_FDODSC = 0x0010
const CP_FDODTA = 0x147a

func (o *SQLDTA) WriteSQLDTA() (*DRDA, error) {
	if o.DDM.CodePoint != CP_SQLDTA {
		return nil, errors.New("mismatch code point")
	}
	var dsc = bytes.NewBuffer(make([]byte, 0, len(o.Data)*3+6))
	dsc.WriteByte(byte(len(o.Data)*3 + 3))
	dsc.WriteByte(0x76) // NGDA_TRIPLET_TYPE
	dsc.WriteByte(0xD0) // SQLDTAGRP_LID
	for i := range o.Data {
		dsc.WriteByte(o.Data[i].Type)
		dsc.WriteByte(byte(o.Data[i].Len >> 8))
		dsc.WriteByte(byte(o.Data[i].Len))
	}
	dsc.Write([]byte{0x06, 0x71, 0xE4})
	dsc.Write([]byte{0xD0, 0x00, 0x01})
	var dta = bytes.NewBuffer(make([]byte, 0, 0))
	for i := range o.Data {
		dta.WriteByte(byte(len(o.Data[i].Value) >> 24))
		dsc.WriteByte(byte(len(o.Data[i].Value) >> 16))
		dta.WriteByte(byte(len(o.Data[i].Value) >> 8))
		dsc.WriteByte(byte(len(o.Data[i].Value)))
		dsc.Write(o.Data[i].Value)
	}
	return &DRDA{
		DDM: o.DDM,
		Parameters: []*Parameter{
			{CodePoint: CP_FDODSC, Payload: dsc.Bytes()},
			{CodePoint: CP_FDODTA, Payload: dta.Bytes()},
		},
	}, nil
}

type RDBCMM struct {
	DDM *DDM
}

func (o *RDBCMM) WriteRDBCMM() (*DRDA, error) {
	if o.DDM.CodePoint != CP_RDBCMM {
		return nil, errors.New("mismatch code point")
	}
	return &DRDA{DDM: o.DDM}, nil
}

type SQLCARD struct {
	DDM         *DDM
	SqlState    int64
	SqlErrProc  string
	RowsFetched uint64
	RowsUpdated uint32
	SqlErrs     []byte
	SqlWarn     []byte
	SqlRDBName  string
	SqlMessageM string
	SqlMessageS string
}

func (drda *DRDA) ReadSQLCARD() (*SQLCARD, error) {
	if drda.DDM.CodePoint != CP_SQLCARD {
		return nil, errors.New("mismatch code point")
	}
	data := drda.GetParameter(CP_DATA)
	if data == nil || len(data.Payload) == 0 {
		return nil, errors.New("missing parameter data")
	}
	index := 0
	var sqlcard = &SQLCARD{
		DDM: drda.DDM,
	}
	var err error
	if data.Payload[index] != 0xFF { // SQLCAGRP FLAG
		if len(data.Payload) < index+14 {
			return nil, errors.New("prase sqlcagrp error")
		}
		sqlcard.SqlState, err = strconv.ParseInt(
			string(data.Payload[index+1:index+6]), 10, 64)
		if err != nil {
			return nil, err
		}
		sqlcard.SqlErrProc = string(data.Payload[index+6 : index+14])
		index += 14
	}
	if data.Payload[index] != 0xFF { // SQLCAXGRP FLAG
		if len(data.Payload) < index+36+6 {
			return nil, errors.New("prase sqlcaxgrp error")
		}
		// TODO: INT64?
		sqlcard.RowsFetched = binary.BigEndian.Uint64(data.Payload[index+1 : index+9])
		sqlcard.RowsUpdated = binary.BigEndian.Uint32(data.Payload[index+9 : index+13])
		sqlcard.SqlErrs = data.Payload[index+13 : index+25]
		sqlcard.SqlWarn = data.Payload[index+25 : index+36]
		index += 36
		len1 := binary.BigEndian.Uint16(data.Payload[index : index+2])
		if len(data.Payload) < index+2+int(len1) {
			return nil, errors.New("prase sqlcaxgrp error")
		}
		sqlcard.SqlRDBName = string(data.Payload[index+2 : index+2+int(len1)])
		index += int(len1) + 2
		len2 := binary.BigEndian.Uint16(data.Payload[index : index+2])
		if len(data.Payload) < index+2+int(len2) {
			return nil, errors.New("prase sqlcaxgrp error")
		}
		sqlcard.SqlMessageM = string(data.Payload[index+2 : index+2+int(len2)])
		index += int(len2) + 2
		len3 := binary.BigEndian.Uint16(data.Payload[index : index+2])
		if len(data.Payload) < index+2+int(len3) {
			return nil, errors.New("prase sqlcaxgrp error")
		}
		sqlcard.SqlMessageS = string(data.Payload[index+2 : index+2+int(len3)])
		//index += int(len3) + 2
	}
	return sqlcard, nil
}

const CP_SQLDARD = 0x2411

type SQLDARD struct {
	DDM       *DDM
	SQLCAGRP  *SQLCAGRP
	SQLDHGRP  *SQLDHGRP
	SQLNUMBRP uint16
	SQLDAGRP  []*SQLDAGRP
}

type SQLCAGRP struct {
	FLAG       byte
	SQLSTATE   int64
	SQLERRPROC string
	SQLCAXGRP  *SQLCAXGRP
}

type SQLCAXGRP struct {
	FLAG        byte
	ROWSFETCHED uint64
	ROWSUPDATED uint32
	SQLERRD     []byte
	SQLWARN     []byte
	SQLRDBNAME  string
	SQLERRMSGM  string
	SQLERRMSGS  string
}

type SQLDHGRP struct {
	FLAG          byte
	SQLDHOLD      uint16
	SQLDRETURN    uint16
	SQLDSCROLL    uint16
	SQLDSENSITIVE uint16
	SQLDFCODE     uint16
	SQLDKEYTYPE   uint16
	SQLDRDBNAM    string
	SQLDSCHEMAM   string
	SQLDSCHEMAS   string
}

type SQLDAGRP struct {
	SQLPRECISION uint16
	SQLSCALE     uint16
	SQLLENGTH    uint64
	SQLTYPE      uint16
	SQLCCSID     uint16
	SQLDOPTGRP   *SQLDOPTGRP
}

type SQLDOPTGRP struct {
	FLAG         byte
	SQLUNNAMED   uint16
	SQLNAMEM     string
	SQLNAMES     string
	SQLLABELM    string
	SQLLABELS    string
	SQLCOMMENTSM string
	SQLCOMMENTSS string
	SQLUDTGRP    *SQLUDTGRP
}

type SQLUDTGRP struct {
	FLAG          byte
	SQLUDTXTYPE   int16
	SQLUDTRDB     string
	SQLUDTSCHEMAM string
	SQLUDTSCHEMAS string
	SQLUDTNAMEM   string
	SQLUDTNAMES   string
	SQLDXGRP      *SQLDXGRP
}

type SQLDXGRP struct {
	FLAG           byte
	SQLXKEYMEM     int16
	SQLXUPDATEABLE int16
	SQLXGENERATED  int16
	SQLXPARMMODE   int16
	SQLXRDBNAM     string
	SQLXCORNAMEM   string
	SQLXCORNAMES   string
	SQLXBASENAMEM  string
	SQLXBASENAMES  string
	SQLXSCHEMAM    string
	SQLXSCHEMAS    string
	SQLXNAMEM      string
	SQLXNAMES      string
}

func (drda *DRDA) ReadSQLDARD() (*SQLDARD, error) {
	if drda.DDM.CodePoint != CP_SQLDARD {
		return nil, errors.New("mismatch code point")
	}

	data := drda.GetParameter(CP_DATA)
	if data == nil || len(data.Payload) == 0 {
		return nil, errors.New("missing parameter data")
	}
	index := 0
	var o = &SQLDARD{
		DDM: drda.DDM,
	}
	var err error
	if data.Payload[index] != 0xFF { // SQLCAGRP FLAG
		if len(data.Payload) < index+14 {
			return nil, errors.New("prase SQLCAGRP error")
		}
		o.SQLCAGRP = &SQLCAGRP{
			FLAG: data.Payload[index],
		}
		o.SQLCAGRP.SQLSTATE, err = strconv.ParseInt(
			string(data.Payload[index+1:index+6]), 10, 64)
		if err != nil {
			return nil, err
		}
		o.SQLCAGRP.SQLERRPROC = string(data.Payload[index+6 : index+14])
		index += 14
		if data.Payload[index] != 0xFF { // SQLCAXGRP FLAG
			if len(data.Payload) < index+36+6 {
				return nil, errors.New("prase SQLCAXGRP error")
			}
			// TODO: INT64?
			o.SQLCAGRP.SQLCAXGRP = &SQLCAXGRP{
				FLAG:        data.Payload[index],
				ROWSFETCHED: binary.BigEndian.Uint64(data.Payload[index+1 : index+9]),
				ROWSUPDATED: binary.BigEndian.Uint32(data.Payload[index+9 : index+13]),
				SQLERRD:     data.Payload[index+13 : index+25],
				SQLWARN:     data.Payload[index+25 : index+36],
			}
			index += 36
			len1 := binary.BigEndian.Uint16(data.Payload[index : index+2])
			if len(data.Payload) < index+2+int(len1) {
				return nil, errors.New("prase SQLRDBNAME error")
			}
			o.SQLCAGRP.SQLCAXGRP.SQLRDBNAME = string(data.Payload[index+2 : index+2+int(len1)])
			index += int(len1) + 2
			len2 := binary.BigEndian.Uint16(data.Payload[index : index+2])
			if len(data.Payload) < index+2+int(len2) {
				return nil, errors.New("prase SQLERRMSGM error")
			}
			o.SQLCAGRP.SQLCAXGRP.SQLERRMSGM = string(data.Payload[index+2 : index+2+int(len2)])
			index += int(len2) + 2
			len3 := binary.BigEndian.Uint16(data.Payload[index : index+2])
			if len(data.Payload) < index+2+int(len3) {
				return nil, errors.New("prase SQLERRMSGS error")
			}
			o.SQLCAGRP.SQLCAXGRP.SQLERRMSGS = string(data.Payload[index+2 : index+2+int(len3)])
			index += 2 + int(len3)
		}
	}
	if data.Payload[index] != 0xFF { // SQLDHGRP FLAG
		if len(data.Payload) < index+13 {
			return nil, errors.New("prase SQLDHGRP error")
		}
		o.SQLDHGRP = &SQLDHGRP{
			FLAG:          data.Payload[index],
			SQLDHOLD:      binary.BigEndian.Uint16(data.Payload[index+1 : index+3]),
			SQLDRETURN:    binary.BigEndian.Uint16(data.Payload[index+3 : index+5]),
			SQLDSCROLL:    binary.BigEndian.Uint16(data.Payload[index+5 : index+7]),
			SQLDSENSITIVE: binary.BigEndian.Uint16(data.Payload[index+7 : index+9]),
			SQLDFCODE:     binary.BigEndian.Uint16(data.Payload[index+9 : index+11]),
			SQLDKEYTYPE:   binary.BigEndian.Uint16(data.Payload[index+11 : index+13]),
		}
		index += 13
		len1 := binary.BigEndian.Uint16(data.Payload[index : index+2])
		if len(data.Payload) < index+2+int(len1) {
			return nil, errors.New("prase SQLDRDBNAM error")
		}
		o.SQLDHGRP.SQLDRDBNAM = string(data.Payload[index+2 : index+2+int(len1)])
		index += int(len1) + 2
		len2 := binary.BigEndian.Uint16(data.Payload[index : index+2])
		if len(data.Payload) < index+2+int(len2) {
			return nil, errors.New("prase SQLDSCHEMAM error")
		}
		o.SQLDHGRP.SQLDSCHEMAM = string(data.Payload[index+2 : index+2+int(len2)])
		index += int(len2) + 2
		len3 := binary.BigEndian.Uint16(data.Payload[index : index+2])
		if len(data.Payload) < index+2+int(len3) {
			return nil, errors.New("prase SQLDSCHEMAS error")
		}
		o.SQLDHGRP.SQLDSCHEMAS = string(data.Payload[index+2 : index+2+int(len3)])
		index += 2 + int(len3)
	}
	o.SQLNUMBRP = binary.BigEndian.Uint16(data.Payload[index+11 : index+13])

	return o, nil
}
