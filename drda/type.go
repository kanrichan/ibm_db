package drda

import "errors"

const (
	DRDA_TP_Nullable   byte = 0x01
	DRDA_TP_CHAR       byte = 0x30
	DRDA_TP_NCHAR      byte = 0x31
	DRDA_TP_VARCHAR    byte = 0x32
	DRDA_TP_NVARCHAR   byte = 0x33
	DRDA_TP_VARMIX     byte = 0x3E
	DRDA_TP_NVARMIX    byte = 0x3F
	DRDA_TP_LONG       byte = 0x34
	DRDA_TP_NLONG      byte = 0x35
	DRDA_TP_LONGMIX    byte = 0x40
	DRDA_TP_NLONGMIX   byte = 0x41
	DRDA_TP_INTEGER    byte = 0x02
	DRDA_TP_NINTEGER   byte = 0x03
	DRDA_TP_BOOLEAN    byte = 0xBE
	DRDA_TP_NBOOLEAN   byte = 0xBF
	DRDA_TP_SMALL      byte = 0x04
	DRDA_TP_NSMALL     byte = 0x05
	DRDA_TP_DATE       byte = 0x20
	DRDA_TP_NDATE      byte = 0x21
	DRDA_TP_INTEGER8   byte = 0x16
	DRDA_TP_NINTEGER8  byte = 0x17
	DRDA_TP_FLOAT8     byte = 0x0A
	DRDA_TP_NFLOAT8    byte = 0x0B
	DRDA_TP_FLOAT4     byte = 0x0C
	DRDA_TP_NFLOAT4    byte = 0x0D
	DRDA_TP_TIME       byte = 0x22
	DRDA_TP_NTIME      byte = 0x23
	DRDA_TP_TIMESTAMP  byte = 0x24
	DRDA_TP_NTIMESTAMP byte = 0x25
	DRDA_TP_DECIMAL    byte = 0x0E
	DRDA_TP_NDECIMAL   byte = 0x0F
	DRDA_TP_LOBBYTES   byte = 0xC8
	DRDA_TP_NLOBBYTES  byte = 0xC9
	DRDA_TP_LOBCMIXED  byte = 0xCE
	DRDA_TP_NLOBCMIXED byte = 0xCF
)

const (
	DB2_TYPE_DATE       int16 = 0x180
	DB2_TYPE_NDATE      int16 = 0x181
	DB2_TYPE_TIME       int16 = 0x184
	DB2_TYPE_NTIME      int16 = 0x185
	DB2_TYPE_TIMESTAMP  int16 = 0x188
	DB2_TYPE_NTIMESTAMP int16 = 0x189
	DB2_TYPE_BLOB       int16 = 0x194
	DB2_TYPE_NBLOB      int16 = 0x195
	DB2_TYPE_CLOB       int16 = 0x198
	DB2_TYPE_NCLOB      int16 = 0x199
	DB2_TYPE_VARCHAR    int16 = 0x1C0
	DB2_TYPE_NVARCHAR   int16 = 0x1C1
	DB2_TYPE_CHAR       int16 = 0x1C4
	DB2_TYPE_NCHAR      int16 = 0x1C5
	DB2_TYPE_LONG       int16 = 0x1C8
	DB2_TYPE_NLONG      int16 = 0x1C9
	DB2_TYPE_FLOAT      int16 = 0x1E0
	DB2_TYPE_NFLOAT     int16 = 0x1E1
	DB2_TYPE_DECIMAL    int16 = 0x1E4
	DB2_TYPE_NDECIMAL   int16 = 0x1E5
	DB2_TYPE_BIGINT     int16 = 0x1EC
	DB2_TYPE_NBIGINT    int16 = 0x1ED
	DB2_TYPE_INTEGER    int16 = 0x1F0
	DB2_TYPE_NINTEGER   int16 = 0x1F1
	DB2_TYPE_SMALL      int16 = 0x1F4
	DB2_TYPE_NSMALL     int16 = 0x1F5
	DB2_TYPE_NUMERIC    int16 = 0x1F8
	DB2_TYPE_NNUMERIC   int16 = 0x1F9
	DB2_TYPE_BOOLEAN    int16 = 0x984
	DB2_TYPE_NBOOLEAN   int16 = 0x985
)

type DRDAType struct {
	Type byte
	Len  uint16
}

type DB2Type struct {
	Type int16
	Len  uint16
}

func (t DB2Type) ToDRDAType() (o DRDAType, err error) {
	o.Len = t.Len
	switch t.Type {
	case DB2_TYPE_DATE:
		o.Type = DRDA_TP_DATE
		return
	case DB2_TYPE_TIME:
		o.Type = DRDA_TP_TIME
	case DB2_TYPE_LONG:
		o.Type = DRDA_TP_LONG
	case DB2_TYPE_NLONG:
		o.Type = DRDA_TP_NLONG
	case DB2_TYPE_NTIME:
		o.Type = DRDA_TP_NTIME
	case DB2_TYPE_NDATE:
		o.Type = DRDA_TP_NDATE
	case DB2_TYPE_SMALL:
		o.Type = DRDA_TP_SMALL
	case DB2_TYPE_CHAR:
		o.Type = DRDA_TP_VARMIX
	case DB2_TYPE_NCHAR:
		o.Type = DRDA_TP_NVARMIX
	case DB2_TYPE_NSMALL:
		o.Type = DRDA_TP_NSMALL
	case DB2_TYPE_DECIMAL:
		o.Type = DRDA_TP_DECIMAL
	case DB2_TYPE_NUMERIC:
		o.Type = DRDA_TP_DECIMAL
	case DB2_TYPE_INTEGER:
		o.Type = DRDA_TP_INTEGER
	case DB2_TYPE_BIGINT:
		o.Type = DRDA_TP_INTEGER8
	case DB2_TYPE_VARCHAR:
		o.Type = DRDA_TP_VARCHAR
	case DB2_TYPE_BOOLEAN:
		o.Type = DRDA_TP_BOOLEAN
	case DB2_TYPE_NDECIMAL:
		o.Type = DRDA_TP_NDECIMAL
	case DB2_TYPE_NNUMERIC:
		o.Type = DRDA_TP_NDECIMAL
	case DB2_TYPE_NINTEGER:
		o.Type = DRDA_TP_NINTEGER
	case DB2_TYPE_NBIGINT:
		o.Type = DRDA_TP_NINTEGER8
	case DB2_TYPE_NVARCHAR:
		o.Type = DRDA_TP_NVARCHAR
	case DB2_TYPE_NBOOLEAN:
		o.Type = DRDA_TP_NBOOLEAN
	case DB2_TYPE_TIMESTAMP:
		o.Type = DRDA_TP_TIMESTAMP
	case DB2_TYPE_NTIMESTAMP:
		o.Type = DRDA_TP_NTIMESTAMP
	case DB2_TYPE_BLOB:
		o.Type = DRDA_TP_LOBBYTES
		o.Len = 0x8004
	case DB2_TYPE_NBLOB:
		o.Type = DRDA_TP_NLOBBYTES
		o.Len = 0x8004
	case DB2_TYPE_CLOB:
		o.Type = DRDA_TP_LOBCMIXED
		o.Len = 0x8004
	case DB2_TYPE_NCLOB:
		o.Type = DRDA_TP_NLOBCMIXED
		o.Len = 0x8004
	case DB2_TYPE_FLOAT:
		if t.Len == 4 {
			o.Type = DRDA_TP_FLOAT4
		}
		o.Type = DRDA_TP_FLOAT8
	case DB2_TYPE_NFLOAT:
		if t.Len == 4 {
			o.Type = DRDA_TP_NFLOAT4
		}
		o.Type = DRDA_TP_NFLOAT8
	default:
		return o, errors.New("Unknown DB2 SQL type 0x{db2Type:X}")
	}
	return
}
