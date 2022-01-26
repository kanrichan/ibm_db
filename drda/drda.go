package drda

const (
	// DRDA (Exchange Server Attributes)
	CP_EXCSAT   = 0x1041 // DDM (EXCSAT)
	CP_EXTNAM   = 0x115e // Parameter (External Name)
	CP_MGRLVLLS = 0x1404 // Parameter (Manager-Level List)
	CP_SRVCLSNM = 0x1147 // Parameter (Server Class Name)
	CP_SRVNAM   = 0x116d // Parameter (Server Name)
	CP_SRVRLSLV = 0x115a // Parameter (Server Product Release Level)

	// DRDA (Access Security)
	CP_ACCSEC = 0x106d // DDM (ACCSEC)
	CP_SECMEC = 0x11a2 // Parameter (Security Mechanism)
	CP_RDBNAM = 0x2110 // Parameter (Relational Database Name)
	CP_SECTKN = 0x11dc // Parameter (Security Token)

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
