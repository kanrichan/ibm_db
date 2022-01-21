package main

const (
	// DRDA (Exchange Server Attributes)
	EXCSAT   = 0x1041 // DDM (EXCSAT)
	EXTNAM   = 0x115e // Parameter (External Name)
	MGRLVLLS = 0x1404 // Parameter (Manager-Level List)
	SRVCLSNM = 0x1147 // Parameter (Server Class Name)
	SRVNAM   = 0x116d // Parameter (Server Name)
	SRVRLSLV = 0x115a // Parameter (Server Product Release Level)

	// DRDA (Access Security)
	ACCSEC = 0x106d // DDM (ACCSEC)
	SECMEC = 0x11a2 // Parameter (Security Mechanism)
	RDBNAM = 0x2110 // Parameter (Relational Database Name)
	SECTKN = 0x11dc // Parameter (Security Token)

	// DRDA (Security Check)
	SECCHK   = 0x106e // DDM (SECCHK)
	USRID    = 0x11a0 // Parameter (User ID at the Target System)
	PASSWORD = 0x11a1 // Parameter (Password)

	// DRDA (Access RDB)
	ACCRDB = 0x2001 // DDM (ACCRDB)
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
