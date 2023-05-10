package drda

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
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
	for _, para := range drda.Parameters {
		para.Length = int32(len(para.Payload) + 4)
		drda.DDM.Length += para.Length
	}
	drda.DDM.Length2 = drda.DDM.Length - 6

	var buf = bytes.NewBuffer(make([]byte, 0))
	// DDM
	buf.Write(Int32ToBytes(drda.DDM.Length))    // Length
	buf.WriteByte(drda.DDM.Magic)               // Magic
	buf.WriteByte(drda.DDM.Format)              // Format
	buf.Write(Int32ToBytes(drda.DDM.CorrelId))  // CorrelId
	buf.Write(Int32ToBytes(drda.DDM.Length2))   // Length2
	buf.Write(Int32ToBytes(drda.DDM.CodePoint)) // codePoint

	// Parameters
	for _, para := range drda.Parameters {
		buf.Write(Int32ToBytes(para.Length))    // Length
		buf.Write(Int32ToBytes(para.CodePoint)) // CodePoint
		buf.Write(para.Payload)
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

type SQLCARD struct {
	DDM      *DDM
	State    int64
	ErrProc  string
	RDBName  string
	MessageM string
	MessageS string
}

func (drda *DRDA) ReadSQLCARD() (*SQLCARD, error) {
	if drda.DDM.CodePoint != CP_SQLCARD {
		return nil, errors.New("mismatch code point")
	}
	data := drda.GetParameter(CP_DATA)
	if data == nil || len(data.Payload) <= 54 {
		return nil, errors.New("missing parameter data")
	}
	if data.Payload[0] != 0x00 { // SQLCAGRP FLAG
		return nil, errors.New("unsupport sqlcagrp flag")
	}
	var sqlcard = &SQLCARD{
		DDM: drda.DDM,
	}
	var err error
	sqlcard.State, err = strconv.ParseInt(
		string(data.Payload[1:6]), 10, 64)
	if err != nil {
		return nil, err
	}
	sqlcard.ErrProc = string(data.Payload[6:18])
	if data.Payload[18] != 0x00 { // SQLCAXGRP FLAG
		return nil, errors.New("uunsupport sqlcaxgrp flag")
	}
	index := 50
	len1 := binary.BigEndian.Uint16(data.Payload[index : index+2])
	sqlcard.RDBName = string(data.Payload[index+2 : index+2+int(len1)])
	index += int(len1) + 2
	len2 := binary.BigEndian.Uint16(data.Payload[index : index+2])
	sqlcard.MessageM = string(data.Payload[index+2 : index+2+int(len2)])
	index += int(len2) + 2
	len3 := binary.BigEndian.Uint16(data.Payload[index : index+2])
	sqlcard.MessageS = string(data.Payload[index+2 : index+2+int(len3)])
	index += int(len3) + 2
	return sqlcard, nil
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

func (excsat *EXCSAT) WriteEXCSAT() (*DRDA, error) {
	if excsat.DDM.CodePoint != CP_EXCSAT {
		return nil, errors.New("mismatch code point")
	}
	return &DRDA{
		DDM: excsat.DDM,
		Parameters: []*Parameter{
			{CodePoint: CP_EXTNAM, Payload: ToEBCDIC([]byte(excsat.EXTNAM))},
			{CodePoint: CP_SRVNAM, Payload: ToEBCDIC([]byte(excsat.SRVNAM))},
			{CodePoint: CP_SRVCLSNM, Payload: ToEBCDIC([]byte(excsat.SRVCLSNM))},
			{CodePoint: CP_SRVRLSLV, Payload: ToEBCDIC([]byte(excsat.SRVRLSLV))},
			{CodePoint: CP_MGRLVLLS, Payload: []byte{
				0x14, 0x03, byte((excsat.AGENT & 0xff00) >> 8), byte(excsat.AGENT & 0x00ff), // AGENT
				0x24, 0x07, byte((excsat.SQLAM & 0xff00) >> 8), byte(excsat.SQLAM & 0x00ff), // SQLAM
				0x24, 0x0f, byte((excsat.RDB & 0xff00) >> 8), byte(excsat.RDB & 0x00ff), // RDB
				0x14, 0x40, byte((excsat.SECMGR & 0xff00) >> 8), byte(excsat.SECMGR & 0x00ff), // SECMGR
				0x14, 0x74, byte((excsat.CMNTCPIP & 0xff00) >> 8), byte(excsat.CMNTCPIP & 0x00ff), // CMNTCPIP
				0x1c, 0x08, byte((excsat.UNICODEMGR & 0xff00) >> 8), byte(excsat.UNICODEMGR & 0x00ff), // UNICODEMGR CCSID_1208 UTF-8
			}},
		},
	}, nil
}
