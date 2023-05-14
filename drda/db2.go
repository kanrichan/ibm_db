package drda

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	EXTNAM   = "GOLANG DRDA"
	SRVCLSNM = "DRDA/GOLANG"
	SRVRLSLV = "SQL11055"
)

func (conn *Conn) Login() error {
	conn.m.Lock()
	defer conn.m.Unlock()
	var srvnam, err = os.Hostname()
	if err != nil {
		return err
	}
	var rdbnam = conn.dbname + strings.Repeat(" ", 18-len(conn.dbname))
	var excsat = &DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x41, CorrelId: 1, CodePoint: CP_EXCSAT},
		Parameters: []*Parameter{
			{CodePoint: CP_EXTNAM, Payload: ToEBCDIC([]byte(EXTNAM))},
			{CodePoint: CP_SRVNAM, Payload: ToEBCDIC([]byte(srvnam))},
			{CodePoint: CP_SRVCLSNM, Payload: ToEBCDIC([]byte(SRVCLSNM))},
			{CodePoint: CP_SRVRLSLV, Payload: ToEBCDIC([]byte(SRVRLSLV))},
			{CodePoint: CP_MGRLVLLS, Payload: []byte{
				0x14, 0x03, 0x00, 0x0a, // AGENT
				0x24, 0x07, 0x00, 0x0b, // SQLAM
				0x24, 0x0f, 0x00, 0x0c, // RDB
				0x14, 0x40, 0x00, 0x09, // SECMGR AES
				0x14, 0x74, 0x00, 0x08, // CMNTCPIP
				0x1c, 0x08, 0x04, 0xb8, // UNICODEMGR CCSID_1208 UTF-8
			}},
		},
	}
	var accsec = &DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x01, CorrelId: 2, CodePoint: CP_ACCSEC},
		Parameters: []*Parameter{
			{CodePoint: CP_SECMEC, Payload: []byte{
				// 0x00 0x03 USRIDPWD Neither user ID nor password is encrypted
				// 0x00 0x09 EUSRIDPWD Both user ID and password are encrypted
				// 0x00 0x0D EUSRPWDDTA The user ID, Password, and Data are encrypted
				0x00, 0x03,
			}},
			{CodePoint: CP_RDBNAM, Payload: ToEBCDIC([]byte(rdbnam))},
		},
	}
	err = conn.Write(excsat, accsec)
	if err != nil {
		return err
	}
	for i := 0; i < 2; i++ {
		drda, err := conn.Read()
		if err != nil {
			return err
		}
		switch drda.DDM.CodePoint {
		case CP_EXCSATRD:
			// TODO
		case CP_ACCSECRD:
			secmec := drda.GetParameter(CP_SECMEC)
			if secmec == nil {
				return errors.New("unknown error")
			}
			if len(secmec.Payload) != 2 ||
				secmec.Payload[0] != 0x00 || secmec.Payload[1] != 0x03 {
				return errors.New("unknown error")
			}
		case CP_RDBNFNRM:
			return errors.New("database not found")
		default:
			return errors.New("unknown error")
		}
	}

	var secchk = &DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x41, CorrelId: 1, CodePoint: CP_SECCHK},
		Parameters: []*Parameter{
			{CodePoint: CP_SECMEC, Payload: []byte{
				0x00, 0x03, // USER_PASSWORD
			}},
			{CodePoint: CP_RDBNAM, Payload: ToEBCDIC([]byte(rdbnam))},
			{CodePoint: CP_USRID, Payload: ToEBCDIC([]byte(conn.userid))},
			{CodePoint: CP_PASSWORD, Payload: ToEBCDIC([]byte(conn.passwd))},
		},
	}
	var accrdb = &DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x01, CorrelId: 2, CodePoint: CP_ACCRDB},
		Parameters: []*Parameter{
			{CodePoint: CP_RDBNAM, Payload: ToEBCDIC([]byte(rdbnam))},
			{CodePoint: CP_RDBACCCL, Payload: []byte{0x24, 0x07}}, // SQLAM
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
	err = conn.Write(secchk, accrdb)
	if err != nil {
		return err
	}

	for i := 0; i < 3; i++ {
		drda, err := conn.Read()
		if err != nil {
			return err
		}
		switch drda.DDM.CodePoint {
		// case CP_SQLERRRM:
		// 	srvdgn := drda.GetParameter(CP_SRVDGN)
		// 	if srvdgn == nil {
		// 		return errors.New("unknown error")
		// 	}
		// 	return errors.New(string(ToASCII(srvdgn.Payload)))
		case CP_SQLCARD:
			sqlcard, err := drda.ReadSQLCARD()
			switch {
			case err != nil:
				return err
			case sqlcard.SqlState < 0:
				return fmt.Errorf("%5d %s %s%s", sqlcard.SqlState,
					sqlcard.SqlErrProc, sqlcard.SqlMessageM, sqlcard.SqlMessageS)
			}
		default:
			// return errors.New("unknown error")
		}
	}
	return nil
}

func (conn *Conn) Select() error {
	var PRPSQLSTT = &DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x51, CorrelId: 1, CodePoint: CP_PRPSQLSTT},
		Parameters: []*Parameter{
			{CodePoint: CP_PKGNAMCSN, Payload: append(ToEBCDIC([]byte(
				conn.dbname+strings.Repeat(" ", 18-len(conn.dbname))+
					"NULLID"+strings.Repeat(" ", 12)+
					"SYSSH200"+strings.Repeat(" ", 10),
			)), []byte{0x53, 0x59, 0x53, 0x4c, 0x56, 0x4c, 0x30, 0x31, 0x00, 0x04}...)},
			{CodePoint: CP_RTNSQLDA, Payload: []byte{0xf1}},
			{CodePoint: CP_TYPSQLDA, Payload: []byte{0x04}},
		},
	}
	var SQLATTR = &DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x53, CorrelId: 1, CodePoint: CP_SQLATTR},
		Parameters: []*Parameter{
			{CodePoint: CP_DATA, Payload: []byte("\016FOR READ ONLY ")},
		},
	}
	var SQLSTT = &DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x43, CorrelId: 1, CodePoint: CP_SQLSTT},
		Parameters: []*Parameter{
			{CodePoint: CP_DATA, Payload: []byte(`"SELECT * FROM SAMPLE FOR READ ONLY`)},
		},
	}
	var OPNQRY = &DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x01, CorrelId: 2, CodePoint: CP_OPNQRY},
		Parameters: []*Parameter{
			{CodePoint: CP_PKGNAMCSN, Payload: append(ToEBCDIC([]byte(
				conn.dbname+strings.Repeat(" ", 18-len(conn.dbname))+
					"NULLID"+strings.Repeat(" ", 12)+
					"SYSSH200"+strings.Repeat(" ", 10),
			)), []byte{0x53, 0x59, 0x53, 0x4c, 0x56, 0x4c, 0x30, 0x31, 0x00, 0x04}...)},
			{CodePoint: CP_QRYBLKSZ, Payload: []byte{0x00, 0x00, 0x7f, 0xff}},
			{CodePoint: CP_QRYCLSIMP, Payload: []byte{0x01}},
			{CodePoint: CP_OUTOVROPT, Payload: []byte{0x03}},
			{CodePoint: 0x214b, Payload: []byte{0xf1}},
			{CodePoint: 0x2137, Payload: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00}},
			{CodePoint: 0x2136, Payload: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00}},
			{CodePoint: 0x2134, Payload: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00}},
		},
	}
	var RDBCMM = &DRDA{
		DDM: &DDM{Magic: 0xd0, Format: 0x01, CorrelId: 1, CodePoint: CP_RDBCMM},
	}
	conn.Write(PRPSQLSTT, SQLATTR, SQLSTT, OPNQRY)
	fmt.Println("0")
	conn.Read()
	fmt.Println("1")
	conn.Read()
	fmt.Println("2")
	conn.Read()
	fmt.Println("3")
	conn.Read()
	conn.Read()
	conn.Read()
	conn.Write(RDBCMM)
	conn.Read()
	conn.Read()
	return nil
}
