package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

func main() {
	conn, err := NewConnect("127.0.0.1:50000", "xxx", "xxx", "xxxxxx")
	if err != nil {
		panic(err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	conn.Write(&DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x41, CorrelId: 1, CodePoint: EXCSAT},
		Parameters: []*Parameter{
			{CodePoint: EXTNAM, Payload: ToEBCDIC([]byte("DRDA"))},
			{CodePoint: MGRLVLLS, Payload: []byte{
				0x14, 0x03, 0x00, 0x0a, // AGENT
				0x24, 0x07, 0x00, 0x0b, // SQLAM
				0x14, 0x74, 0x00, 0x05, // CMNTCPIP
				0x24, 0x0f, 0x00, 0x0c, // RDB
				0x14, 0x40, 0x00, 0x0a, // SECMGR AES
				0x1c, 0x08, 0x04, 0xb8, // UNICODEMGR CCSID_1208 UTF-8
			}},
			{CodePoint: SRVCLSNM, Payload: ToEBCDIC([]byte("DRDA(GOLANG)/" + strings.ToUpper(runtime.GOOS)))},
			{CodePoint: SRVNAM, Payload: ToEBCDIC([]byte(hostname))},
			{CodePoint: SRVRLSLV, Payload: ToEBCDIC([]byte("SQL11055"))},
		},
	})
	conn.Write(&DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x01, CorrelId: 2, CodePoint: ACCSEC},
		Parameters: []*Parameter{
			{CodePoint: SECMEC, Payload: []byte{
				0x00, 0x03, // USER_PASSWORD
				// 0x00, 0x04, // USER_ONLY
				// 0x00, 0x05, // CHANGE_PASSWORD
				// 0x00, 0x06, // USER_PASS_SUBST
				// 0x00, 0x07, // USER_ENC_PASS
				// 0x00, 0x09, // ENC_USER_ENC_PASS
				// 0x00, 0x0a, // ENC_CHANGE_PASS
				// 0x00, 0x0b, // KERBEROS
				// 0x00, 0x0c, // ENC_USER_DATA
				// 0x00, 0x0d, // ENC_USER_ENC_PASS_ENC_DATA
				// 0x00, 0x0e, // ENC_USER_ENC_PASS_ENC_NEWPASS_ENC_DATA
			}},
			{CodePoint: RDBNAM, Payload: []byte(conn.dbname + strings.Repeat(" ", 18-len(conn.dbname)))},
		},
	})

	conn.Write(&DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x01, CorrelId: 2, CodePoint: SECCHK},
		Parameters: []*Parameter{
			{CodePoint: SECMEC, Payload: []byte{
				0x00, 0x03, // USER_PASSWORD
				// 0x00, 0x04, // USER_ONLY
				// 0x00, 0x05, // CHANGE_PASSWORD
				// 0x00, 0x06, // USER_PASS_SUBST
				// 0x00, 0x07, // USER_ENC_PASS
				// 0x00, 0x09, // ENC_USER_ENC_PASS
				// 0x00, 0x0a, // ENC_CHANGE_PASS
				// 0x00, 0x0b, // KERBEROS
				// 0x00, 0x0c, // ENC_USER_DATA
				// 0x00, 0x0d, // ENC_USER_ENC_PASS_ENC_DATA
				// 0x00, 0x0e, // ENC_USER_ENC_PASS_ENC_NEWPASS_ENC_DATA
			}},
			{CodePoint: RDBNAM, Payload: []byte(conn.dbname + strings.Repeat(" ", 18-len(conn.dbname)))},
			{CodePoint: USRID, Payload: []byte(conn.userid)},
			{CodePoint: PASSWORD, Payload: []byte(conn.passwd)},
		},
	})

	conn.Write(&DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x01, CorrelId: 2, CodePoint: ACCRDB},
		Parameters: []*Parameter{
			{CodePoint: SECMEC, Payload: []byte{
				0x00, 0x03, // USER_PASSWORD
				// 0x00, 0x04, // USER_ONLY
				// 0x00, 0x05, // CHANGE_PASSWORD
				// 0x00, 0x06, // USER_PASS_SUBST
				// 0x00, 0x07, // USER_ENC_PASS
				// 0x00, 0x09, // ENC_USER_ENC_PASS
				// 0x00, 0x0a, // ENC_CHANGE_PASS
				// 0x00, 0x0b, // KERBEROS
				// 0x00, 0x0c, // ENC_USER_DATA
				// 0x00, 0x0d, // ENC_USER_ENC_PASS_ENC_DATA
				// 0x00, 0x0e, // ENC_USER_ENC_PASS_ENC_NEWPASS_ENC_DATA
			}},
			{CodePoint: RDBNAM, Payload: []byte(conn.dbname + strings.Repeat(" ", 18-len(conn.dbname)))},
			{CodePoint: USRID, Payload: []byte(conn.userid)},
			{CodePoint: PASSWORD, Payload: []byte(conn.passwd)},
		},
	})

	drda, _ := conn.Read()
	fmt.Printf("%x\n", drda.Parameters[0].Payload)
	drda, _ = conn.Read()
	fmt.Printf("%x\n", drda.DDM.CodePoint)
	conn.Close()
}
