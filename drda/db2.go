package drda

import (
	"os"
	"strings"
)

var (
	SRVNAM, _ = os.Hostname()
	SRVRLSLV  = "SQL11055"
	EXTNAM    = "GOLANG KANRI DRDA"
	SRVCLSNM  = "DRDA/GOLANG"
)

func (conn *Conn) Login() error {
	var EXCSAT = &DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x41, CorrelId: 1, CodePoint: CP_EXCSAT},
		Parameters: []*Parameter{
			{CodePoint: CP_EXTNAM, Payload: ToEBCDIC([]byte(EXTNAM))},
			{CodePoint: CP_SRVNAM, Payload: ToEBCDIC([]byte(SRVNAM))},
			{CodePoint: CP_SRVCLSNM, Payload: ToEBCDIC([]byte(SRVCLSNM))},
			{CodePoint: CP_SRVRLSLV, Payload: ToEBCDIC([]byte(SRVRLSLV))},
			{CodePoint: CP_MGRLVLLS, Payload: []byte{
				0x14, 0x03, 0x00, 0x07, // AGENT
				0x24, 0x07, 0x00, 0x0a, // SQLAM
				0x24, 0x0f, 0x00, 0x08, // RDB
				0x14, 0x40, 0x00, 0x09, // SECMGR AES
				0x14, 0x74, 0x00, 0x08, // CMNTCPIP
				0x1c, 0x08, 0x04, 0xb8, // UNICODEMGR CCSID_1208 UTF-8
			}},
		},
	}
	var ACCSEC = &DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x01, CorrelId: 2, CodePoint: CP_ACCSEC},
		Parameters: []*Parameter{
			{CodePoint: CP_SECMEC, Payload: []byte{
				0x00, 0x03, // USER_PASSWORD
			}},
			{CodePoint: CP_RDBNAM, Payload: ToEBCDIC([]byte(
				conn.dbname + strings.Repeat(" ", 18-len(conn.dbname)),
			))},
		},
	}
	var SECCHK = &DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x41, CorrelId: 1, CodePoint: CP_SECCHK},
		Parameters: []*Parameter{
			{CodePoint: CP_SECMEC, Payload: []byte{
				0x00, 0x03, // USER_PASSWORD
			}},
			{CodePoint: CP_RDBNAM, Payload: ToEBCDIC([]byte(
				conn.dbname + strings.Repeat(" ", 18-len(conn.dbname)),
			))},
			{CodePoint: CP_USRID, Payload: ToEBCDIC([]byte(conn.userid))},
			{CodePoint: CP_PASSWORD, Payload: ToEBCDIC([]byte(conn.passwd))},
		},
	}
	var ACCRDB = &DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x01, CorrelId: 2, CodePoint: CP_ACCRDB},
		Parameters: []*Parameter{
			{CodePoint: CP_RDBNAM, Payload: ToEBCDIC([]byte(
				conn.dbname + strings.Repeat(" ", 18-len(conn.dbname)),
			))},
			{CodePoint: CP_RDBACCCL, Payload: []byte{0x24, 0x07}},
			{CodePoint: CP_PRDID, Payload: ToEBCDIC([]byte(SRVRLSLV))},
			{CodePoint: CP_PRDDTA, Payload: ToEBCDIC([]byte(EXTNAM))},
			{CodePoint: CP_TYPDEFNAM, Payload: ToEBCDIC([]byte("QTDSQLASC"))},
			{CodePoint: CP_TYPDEFOVR, Payload: []byte{
				0x00, 0x06, 0x11, 0x9c,
				0x04, 0xb8, 0x00, 0x06,
				0x11, 0x9d, 0x04, 0xb0,
				0x00, 0x06, 0x11, 0x9e,
				0x04, 0xb8, 0x00, 0x06,
				0x19, 0x13, 0x04, 0xb8,
			}},
		},
	}
	conn.Write(EXCSAT, ACCSEC)
	conn.Read()
	conn.Read()
	conn.Write(SECCHK, ACCRDB)
	conn.Read()
	conn.Read()
	conn.Read()
	return nil
}
