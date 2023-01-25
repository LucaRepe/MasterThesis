## Differences between Angr and IDA

0x411032
instr ['JMP 0X4127D0']
edges ['0x4127d0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414ec3
instr ['JMP DWORD PTR [0X41B030]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x413820
instr ['PUSH EBP', 'MOV EBP, ESP', 'POP EBP', 'RET ']
edges []
edge_attr []
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x414e5d
instr ['JMP DWORD PTR [0X41B004]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x411740
instr ['PUSH EBP', 'MOV EBP, ESP', 'POP EBP', 'RET ']
edges []
edge_attr []
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x411302
instr ['JMP 0X414ED5']
edges ['0x414ed5']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x41498b
instr ['SUB DWORD PTR [EBX + 0X41A2C0], ESP', 'MOV DWORD PTR [0X41A2BC], ECX', 'MOV DWORD PTR [0X41A2B8], EDX', 'MOV DWORD PTR [0X41A2B4], EBX', 'MOV DWORD PTR [0X41A2B0], ESI', 'MOV DWORD PTR [0X41A2AC], EDI', 'MOV WORD PTR [0X41A2D8], SS', 'MOV WORD PTR [0X41A2CC], CS', 'MOV WORD PTR [0X41A2A8], DS', 'MOV WORD PTR [0X41A2A4], ES', 'MOV WORD PTR [0X41A2A0], FS', 'MOV WORD PTR [0X41A29C], GS', 'PUSHFD ', 'POP DWORD PTR [0X41A2D0]', 'MOV EAX, DWORD PTR [EBP]', 'MOV DWORD PTR [0X41A2C4], EAX', 'MOV EAX, DWORD PTR [EBP + 4]', 'MOV DWORD PTR [0X41A2C8], EAX', 'LEA EAX, [EBP + 8]', 'MOV DWORD PTR [0X41A2D4], EAX', 'MOV EAX, DWORD PTR [EBP - 0X324]', 'MOV DWORD PTR [0X41A210], 0X10001', 'MOV EAX, DWORD PTR [0X41A2C8]', 'MOV DWORD PTR [0X41A1CC], EAX', 'MOV DWORD PTR [0X41A1C0], 0XC0000409', 'MOV DWORD PTR [0X41A1C4], 1', 'MOV DWORD PTR [0X41A1D0], 1', 'MOV ECX, 4', 'IMUL EDX, ECX, 0', 'MOV DWORD PTR [EDX + 0X41A1D4], 2', 'MOV EAX, 4', 'IMUL ECX, EAX, 0', 'MOV EDX, DWORD PTR [0X41A020]', 'MOV DWORD PTR [EBP + ECX - 8], EDX', 'MOV EAX, 4', 'SHL EAX, 0', 'MOV ECX, DWORD PTR [0X41A024]', 'MOV DWORD PTR [EBP + EAX - 8], ECX', 'PUSH 0X4184EC', 'CALL 0X411398']
edges ['0x411398', '0x414a70']
edge_attr ['Call', 'Fallthrough']
func_beg True
dir_call True
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x413970
instr ['PUSH EBP', 'MOV EBP, ESP', 'POP EBP', 'RET ']
edges []
edge_attr []
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x41110e
instr ['JMP 0X414EA5']
edges ['0x414ea5']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x411050
instr ['JMP 0X413A20']
edges ['0x413a20']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x4112f3
instr ['JMP 0X414F10']
edges ['0x414f10']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x411334
instr ['JMP 0X414D7F']
edges ['0x414d7f']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414e57
instr ['JMP DWORD PTR [0X41B03C]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x4110dc
instr ['JMP 0X414E7B']
edges ['0x414e7b']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x411767
instr ['MOV ECX, 0X41C008', 'CALL 0X411307']
edges ['0x411307', '0x411771']
edge_attr ['Call', 'Fallthrough']
func_beg False
dir_call True
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x4111b8
instr ['JMP 0X414E9F']
edges ['0x414e9f']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414ea5
instr ['JMP DWORD PTR [0X41B044]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x411249
instr ['JMP 0X4131E0']
edges ['0x4131e0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x411320
instr ['JMP 0X414E99']
edges ['0x414e99']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x4110c3
instr ['JMP 0X414EBD']
edges ['0x414ebd']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x411190
instr ['JMP 0X414ECF']
edges ['0x414ecf']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x4112e9
instr ['JMP 0X412630']
edges ['0x412630']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x4110a0
instr ['JMP 0X414F20']
edges ['0x414f20']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414ae9
instr ['SUB DWORD PTR [EBX + 0X41A2C0], ESP', 'MOV DWORD PTR [0X41A2BC], ECX', 'MOV DWORD PTR [0X41A2B8], EDX', 'MOV DWORD PTR [0X41A2B4], EBX', 'MOV DWORD PTR [0X41A2B0], ESI', 'MOV DWORD PTR [0X41A2AC], EDI', 'MOV WORD PTR [0X41A2D8], SS', 'MOV WORD PTR [0X41A2CC], CS', 'MOV WORD PTR [0X41A2A8], DS', 'MOV WORD PTR [0X41A2A4], ES', 'MOV WORD PTR [0X41A2A0], FS', 'MOV WORD PTR [0X41A29C], GS', 'PUSHFD ', 'POP DWORD PTR [0X41A2D0]', 'MOV EAX, DWORD PTR [EBP]', 'MOV DWORD PTR [0X41A2C4], EAX', 'MOV EAX, DWORD PTR [EBP + 4]', 'MOV DWORD PTR [0X41A2C8], EAX', 'LEA EAX, [EBP + 8]', 'MOV DWORD PTR [0X41A2D4], EAX', 'MOV EAX, DWORD PTR [EBP - 0X31C]', 'MOV EAX, DWORD PTR [0X41A2C8]', 'MOV DWORD PTR [0X41A1CC], EAX', 'MOV DWORD PTR [0X41A1C0], 0XC0000409', 'MOV DWORD PTR [0X41A1C4], 1', 'MOV DWORD PTR [0X41A1D0], 1', 'MOV ECX, 4', 'IMUL EDX, ECX, 0', 'MOV EAX, DWORD PTR [EBP + 8]', 'MOV DWORD PTR [EDX + 0X41A1D4], EAX', 'PUSH 0X4184EC', 'CALL 0X411398']
edges ['0x411398', '0x414b9f']
edge_attr ['Call', 'Fallthrough']
func_beg True
dir_call True
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x411208
instr ['JMP 0X412FA0']
edges ['0x412fa0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x41120d
instr ['JMP 0X4135E0']
edges ['0x4135e0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x41117c
instr ['JMP 0X414E69']
edges ['0x414e69']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x411221
instr ['JMP 0X414E6F']
edges ['0x414e6f']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414e93
instr ['JMP DWORD PTR [0X41B050]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x4127e0
instr ['PUSH EBP', 'MOV EBP, ESP', 'MOV EAX, DWORD PTR [0X41A14C]', 'MOV ECX, DWORD PTR [EBP + 8]', 'MOV DWORD PTR [0X41A14C], ECX', 'MOV DWORD PTR [0X41A150], 0', 'POP EBP', 'RET ']
edges []
edge_attr []
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x412ad0
instr ['PUSH EBP', 'MOV EBP, ESP', 'CALL 0X411181']
edges ['0x411181', '0x412ad8']
edge_attr ['Call', 'Fallthrough']
func_beg True
dir_call True
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x4111d1
instr ['JMP 0X411960']
edges ['0x411960']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x4110af
instr ['JMP 0X412A60']
edges ['0x412a60']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x4131e0
instr ['PUSH EBP', 'MOV EBP, ESP', 'PUSH 0X41A188', 'CALL 0X4112CB']
edges ['0x4112cb', '0x4131ed']
edge_attr ['Call', 'Fallthrough']
func_beg True
dir_call True
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x41121c
instr ['JMP 0X412A90']
edges ['0x412a90']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x41129e
instr ['JMP 0X413830']
edges ['0x413830']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414ecf
instr ['JMP DWORD PTR [0X41B028]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x4139b4
instr ['ADD ESP, 4', 'POP EBP', 'RET ']
edges []
edge_attr []
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x4111e5
instr ['JMP 0X414EDB']
edges ['0x414edb']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414e9f
instr ['JMP DWORD PTR [0X41B048]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x41384c
instr ['ADD ESP, 4', 'POP EBP', 'RET ']
edges []
edge_attr []
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x4139ab
instr ['MOV ECX, DWORD PTR [EBP + 8]', 'PUSH ECX', 'CALL 0X413860']
edges ['0x413860', '0x4139b4']
edge_attr ['Call', 'Fallthrough']
func_beg False
dir_call True
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x414ebd
instr ['JMP DWORD PTR [0X41B034]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x4112a8
instr ['JMP 0X413920']
edges ['0x413920']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414e8d
instr ['JMP DWORD PTR [0X41B054]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x411014
instr ['JMP 0X414EB1']
edges ['0x414eb1']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x411271
instr ['JMP 0X413970']
edges ['0x413970']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414ec9
instr ['JMP DWORD PTR [0X41B02C]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x411069
instr ['JMP 0X414F40']
edges ['0x414f40']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414e81
instr ['JMP DWORD PTR [0X41B01C]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x414e7b
instr ['JMP DWORD PTR [0X41B018]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x414e6f
instr ['JMP DWORD PTR [0X41B010]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x411276
instr ['JMP 0X411810']
edges ['0x411810']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414eb1
instr ['JMP DWORD PTR [0X41B000]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x4111ea
instr ['JMP 0X4137F0']
edges ['0x4137f0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x413329
instr ['SUB DWORD PTR [EDX + 3], EBP', 'CALL 0X41128A']
edges ['0x41128a', '0x413331']
edge_attr ['Call', 'Fallthrough']
func_beg True
dir_call True
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x4112e4
instr ['JMP 0X414E63']
edges ['0x414e63']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x413994
instr ['ADD ESP, 0XC', 'TEST EAX, EAX', 'JE 0X4139B7']
edges ['0x4139b7', '0x41399b']
edge_attr ['Jump', 'Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump True
dir_jump True
indir_jump False
has_return False


0x411244
instr ['JMP 0X414EF0']
edges ['0x414ef0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x411041
instr ['JMP 0X414E81']
edges ['0x414e81']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x41384f
instr ['POP EBP', 'RET ']
edges []
edge_attr []
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x414e99
instr ['JMP DWORD PTR [0X41B04C]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x411831
instr ['MOV EAX, DWORD PTR [EDX]', 'MOV DWORD PTR [ESI + 4], EAX', 'MOV DWORD PTR [ESI + 0XC], EBX', 'MOV DWORD PTR [EDX], ESI', 'POP EDI', 'POP ESI', 'POP EBX', 'POP EBP', 'RET 4']
edges []
edge_attr []
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x4110b4
instr ['JMP 0X4134A0']
edges ['0x4134a0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x412ebf
instr ['XCHG DWORD PTR [EDX], ECX', 'POP EBP', 'RET ']
edges []
edge_attr []
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x411131
instr ['JMP 0X412A20']
edges ['0x412a20']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414d7f
instr ['JMP DWORD PTR [0X41B170]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x411154
instr ['JMP 0X411A00']
edges ['0x411a00']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x41131b
instr ['JMP 0X411850']
edges ['0x411850']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x413843
instr ['MOV ECX, DWORD PTR [EBP + 8]', 'PUSH ECX', 'CALL 0X413860']
edges ['0x413860', '0x41384c']
edge_attr ['Call', 'Fallthrough']
func_beg False
dir_call True
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x4110c8
instr ['JMP 0X414E57']
edges ['0x414e57']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x4110eb
instr ['JMP 0X412AF0']
edges ['0x412af0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414eb7
instr ['JMP DWORD PTR [0X41B038]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x41105f
instr ['JMP 0X412B90']
edges ['0x412b90']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x4139a4
instr ['ADD ESP, 4', 'TEST EAX, EAX', 'JE 0X4139B7']
edges ['0x4139b7', '0x4139ab']
edge_attr ['Jump', 'Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump True
dir_jump True
indir_jump False
has_return False


0x41124e
instr ['JMP 0X412AD0']
edges ['0x412ad0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x411028
instr ['JMP 0X414E93']
edges ['0x414e93']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414e69
instr ['JMP DWORD PTR [0X41B00C]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x414e63
instr ['JMP DWORD PTR [0X41B008]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x41106e
instr ['JMP 0X413820']
edges ['0x413820']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414edb
instr ['JMP DWORD PTR [0X41B020]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x4110e1
instr ['JMP 0X414EC9']
edges ['0x414ec9']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x4110fa
instr ['JMP 0X412B50']
edges ['0x412b50']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x412add
instr ['MOV AL, 1', 'POP EBP', 'RET ']
edges []
edge_attr []
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x411280
instr ['JMP 0X4137D0']
edges ['0x4137d0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x411765
instr ['REP STOSD DWORD PTR ES:[EDI], EAX']
edges ['0x411767']
edge_attr ['Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x411226
instr ['JMP 0X414F50']
edges ['0x414f50']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x411370
instr ['JMP 0X411740']
edges ['0x411740']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x411046
instr ['JMP 0X414AC0']
edges ['0x414ac0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x4112b2
instr ['JMP 0X414F00']
edges ['0x414f00']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x4111a4
instr ['JMP 0X414BE0']
edges ['0x414be0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x413980
instr ['PUSH EBP', 'MOV EBP, ESP', 'MOV EAX, DWORD PTR [EBP + 0X10]', 'PUSH EAX', 'MOV ECX, DWORD PTR [EBP + 0XC]', 'PUSH ECX', 'MOV EDX, DWORD PTR [EBP + 8]', 'PUSH EDX', 'CALL 0X4139D0']
edges ['0x4139d0', '0x413994']
edge_attr ['Call', 'Fallthrough']
func_beg True
dir_call True
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x414e75
instr ['JMP DWORD PTR [0X41B014]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x4111cc
instr ['JMP 0X414E8D']
edges ['0x414e8d']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x413951
instr ['SUB DWORD PTR [EBP - 0X3D], EBX', 'INT3 ']
edges ['0x413970']
edge_attr ['Fallthrough']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x41137a
instr ['JMP 0X414E87']
edges ['0x414e87']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x411a00
instr ['MOV EAX, 0X41132F', 'RET ']
edges []
edge_attr []
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x414bf9
instr ['SUB DWORD PTR [EBX + 0X41A2C0], ESP', 'MOV DWORD PTR [0X41A2BC], ECX', 'MOV DWORD PTR [0X41A2B8], EDX', 'MOV DWORD PTR [0X41A2B4], EBX', 'MOV DWORD PTR [0X41A2B0], ESI', 'MOV DWORD PTR [0X41A2AC], EDI', 'MOV WORD PTR [0X41A2D8], SS', 'MOV WORD PTR [0X41A2CC], CS', 'MOV WORD PTR [0X41A2A8], DS', 'MOV WORD PTR [0X41A2A4], ES', 'MOV WORD PTR [0X41A2A0], FS', 'MOV WORD PTR [0X41A29C], GS', 'PUSHFD ', 'POP DWORD PTR [0X41A2D0]', 'MOV EAX, DWORD PTR [EBP]', 'MOV DWORD PTR [0X41A2C4], EAX', 'MOV EAX, DWORD PTR [EBP + 4]', 'MOV DWORD PTR [0X41A2C8], EAX', 'LEA EAX, [EBP + 8]', 'MOV DWORD PTR [0X41A2D4], EAX', 'MOV EAX, DWORD PTR [EBP - 0X320]', 'MOV EAX, DWORD PTR [0X41A2C8]', 'MOV DWORD PTR [0X41A1CC], EAX', 'MOV DWORD PTR [0X41A1C0], 0XC0000409', 'MOV DWORD PTR [0X41A1C4], 1', 'CMP DWORD PTR [EBP + 0XC], 0', 'JBE 0X414C9D']
edges ['0x414c9d', '0x414c90']
edge_attr ['Jump', 'Fallthrough']
func_beg True
dir_call False
indir_call False
cond_jump True
dir_jump True
indir_jump False
has_return False


0x411299
instr ['JMP 0X4138E0']
edges ['0x4138e0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x41139d
instr ['JMP 0X414EB7']
edges ['0x414eb7']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x4131ed
instr ['ADD ESP, 4', 'POP EBP', 'RET ']
edges []
edge_attr []
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x41114a
instr ['JMP 0X412840']
edges ['0x412840']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414ed5
instr ['JMP DWORD PTR [0X41B024]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x414e87
instr ['JMP DWORD PTR [0X41B058]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x413809
instr ['SUB DWORD PTR [EBP - 0X3D], EBX', 'INT3 ']
edges ['0x413820']
edge_attr ['Fallthrough']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x413830
instr ['PUSH EBP', 'MOV EBP, ESP', 'MOV EAX, DWORD PTR [EBP + 8]', 'PUSH EAX', 'CALL 0X413890']
edges ['0x413890', '0x41383c']
edge_attr ['Call', 'Fallthrough']
func_beg True
dir_call True
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x4111a9
instr ['JMP 0X414EC3']
edges ['0x414ec3']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x411168
instr ['JMP 0X414E5D']
edges ['0x414e5d']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x41119f
instr ['JMP 0X414F30']
edges ['0x414f30']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x41182f
instr ['REP STOSB BYTE PTR ES:[EDI], AL']
edges ['0x411831']
edge_attr ['Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x411145
instr ['JMP 0X4127B0']
edges ['0x4127b0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x414eab
instr ['JMP DWORD PTR [0X41B040]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x412ad8
instr ['CALL 0X411104']
edges ['0x411104', '0x412add']
edge_attr ['Call', 'Fallthrough']
func_beg False
dir_call True
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x41116d
instr ['JMP 0X414E75']
edges ['0x414e75']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x411339
instr ['JMP 0X413980']
edges ['0x413980']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x4139b7
instr ['POP EBP', 'RET ']
edges []
edge_attr []
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x411186
instr ['JMP 0X4127E0']
edges ['0x4127e0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x41399b
instr ['MOV EAX, DWORD PTR [EBP + 8]', 'PUSH EAX', 'CALL 0X413890']
edges ['0x413890', '0x4139a4']
edge_attr ['Call', 'Fallthrough']
func_beg False
dir_call True
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x41383c
instr ['ADD ESP, 4', 'TEST EAX, EAX', 'JE 0X41384F']
edges ['0x41384f', '0x413843']
edge_attr ['Jump', 'Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump True
dir_jump True
indir_jump False
has_return False


0x4112a3
instr ['JMP 0X414EAB']
edges ['0x414eab']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False

## Differences between IDA and Ghidra/Radare

0x411d94
instr ['CALL    J__C_EXIT']
edges ['UnresolvableCallTarget', '0x411d99']
edge_attr ['Call', 'Fallthrough']
func_beg False
dir_call False
indir_call True
cond_jump False
dir_jump False
indir_jump False
has_return False


0x41370e
instr ['CALL    EDI']
edges ['UnresolvableCallTarget', '0x413710']
edge_attr ['Call', 'Fallthrough']
func_beg False
dir_call False
indir_call True
cond_jump False
dir_jump False
indir_jump False
has_return False


0x411d6a
instr ['ADD     ESP, 8', 'RETN']
edges []
edge_attr []
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x411d7c
instr ['MOVZX   EDX, AL', 'TEST    EDX, EDX', 'JNZ     SHORT LOC_411D8C']
edges ['0x411d8c', '0x411d83']
edge_attr ['Jump', 'Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump True
dir_jump True
indir_jump False
has_return False


0x411a6f
instr ['ADD     ESP, 14H', 'RETN']
edges []
edge_attr []
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x412df6
instr ['MOV     EDX, [EBP+MS_EXC.EXC_PTR]', 'MOV     EAX, [EDX]', 'MOV     ECX, [EAX]', 'MOV     [EBP+VAR_38], ECX', 'CMP     [EBP+VAR_38], 0C0000005H', 'JNZ     SHORT LOC_412E12']
edges ['0x412e12', '0x412e09']
edge_attr ['Jump', 'Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump True
dir_jump True
indir_jump False
has_return False


0x411d6e
instr ['MOV     ESP, [EBP+MS_EXC.OLD_ESP]', 'MOV     ECX, [EBP+EXCEPTIONNUM]', 'MOV     [EBP+VAR_34], ECX', 'CALL    J____SCRT_IS_MANAGED_APP']
edges ['UnresolvableCallTarget', '0x411d7c']
edge_attr ['Call', 'Fallthrough']
func_beg False
dir_call False
indir_call True
cond_jump False
dir_jump False
indir_jump False
has_return False


0x412f58
instr ['JMP     SHORT LOC_412F81']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x411a60
instr ['PUSH    1', 'PUSH    1', 'PUSH    0', 'PUSH    0', 'PUSH    0', 'CALL    SUB_4110BE']
edges ['0x4110be', '0x411a6f']
edge_attr ['Call', 'Fallthrough']
func_beg True
dir_call True
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x411d4a
instr ['MOV     [EBP+MS_EXC.REGISTRATION.TRYLEVEL], 0FFFFFFFEH', 'JMP     SHORT LOC_411DB2']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x411d8c
instr ['MOVZX   ECX, [EBP+VAR_19]', 'TEST    ECX, ECX', 'JNZ     SHORT LOC_411D99']
edges ['0x411d99', '0x411d94']
edge_attr ['Jump', 'Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump True
dir_jump True
indir_jump False
has_return False


0x412e12
instr ['MOV     [EBP+VAR_2C], 0']
edges ['0x412e19']
edge_attr ['Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x41371b
instr ['POP     EDI']
edges ['0x41371c']
edge_attr ['Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x4110d2
instr ['JMP     _CRTDBGREPORTW']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x41371c
instr ['POP     ESI', 'RETN']
edges []
edge_attr []
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x411d99
instr ['MOV     EDX, [EBP+VAR_34]', 'MOV     [EBP+VAR_44], EDX', 'MOV     [EBP+MS_EXC.REGISTRATION.TRYLEVEL], 0FFFFFFFEH', 'MOV     EAX, [EBP+VAR_44]', 'JMP     SHORT LOC_411DB2']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x412e09
instr ['MOV     [EBP+VAR_2C], 1', 'JMP     SHORT LOC_412E19']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x4112f8
instr ['JMP     ___SCRT_UNHANDLED_EXCEPTION_FILTER@4; __SCRT_UNHANDLED_EXCEPTION_FILTER(X)']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x4125f1
instr ['MOV     ESP, [EBP+MS_EXC.OLD_ESP]']
edges ['0x4125f4']
edge_attr ['Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x4127d0
instr ['MOV     EAX, 5', 'RETN']
edges []
edge_attr []
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x413710
instr ['ADD     ESI, 4', 'CMP     ESI, OFFSET UNK_4190F4', 'JB      SHORT LOC_413700']
edges ['0x413700', '0x41371b']
edge_attr ['Jump', 'Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump True
dir_jump True
indir_jump False
has_return False


0x4112d5
instr ['JMP     __RTC_SHUTDOWN']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x4136f0
instr ['PUSH    ESI', 'MOV     ESI, OFFSET UNK_418EF0', 'MOV     EAX, ESI', 'CMP     EAX, OFFSET UNK_4190F4', 'JNB     SHORT LOC_41371C']
edges ['0x41371c', '0x4136ff']
edge_attr ['Jump', 'Fallthrough']
func_beg True
dir_call False
indir_call False
cond_jump True
dir_jump True
indir_jump False
has_return False


0x413706
instr ['MOV     ECX, EDI; THIS', 'CALL    DS:___GUARD_CHECK_ICALL_FPTR; STD::SHARED_MUTEX::~SHARED_MUTEX(VOID)']
edges ['UnresolvableCallTarget', '0x41370e']
edge_attr ['Call', 'Fallthrough']
func_beg False
dir_call False
indir_call True
cond_jump False
dir_jump False
indir_jump False
has_return False


0x411a29
instr ['PUSH    0', 'PUSH    1', 'PUSH    0', 'PUSH    0', 'PUSH    0', 'MOV     BYTE_41A138, 1', 'CALL    SUB_4110BE']
edges ['0x4110be', '0x411a3f']
edge_attr ['Call', 'Fallthrough']
func_beg False
dir_call True
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x414d8b
instr ['JMP     DS:__IMP__CRTDBGREPORTW']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x412e19
instr ['MOV     EAX, [EBP+VAR_2C]', 'RETN']
edges []
edge_attr []
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x412e1d
instr ['MOV     ESP, [EBP+MS_EXC.OLD_ESP]', 'MOV     [EBP+VAR_1D], 0', 'MOV     [EBP+MS_EXC.REGISTRATION.TRYLEVEL], 0FFFFFFFEH', 'MOV     AL, [EBP+VAR_1D]', 'JMP     SHORT LOC_412E37']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x411a45
instr ['ADD     ESP, 18H']
edges ['0x411a48']
edge_attr ['Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x4125de
instr ['MOV     EAX, [EBP+MS_EXC.EXC_PTR]', 'MOV     EAX, [EAX]', 'XOR     ECX, ECX', 'CMP     DWORD PTR [EAX], 406D1388H', 'SETZ    CL', 'MOV     EAX, ECX', 'RETN']
edges []
edge_attr []
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x411316
instr ['JMP     SUB_412810']
edges ['0x412810']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x413700
instr ['MOV     EDI, [ESI]', 'TEST    EDI, EDI', 'JZ      SHORT LOC_413710']
edges ['0x413710', '0x413706']
edge_attr ['Jump', 'Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump True
dir_jump True
indir_jump False
has_return False


0x411dab
instr ['MOV     [EBP+MS_EXC.REGISTRATION.TRYLEVEL], 0FFFFFFFEH']
edges ['0x411db2']
edge_attr ['Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x41118b
instr ['JMP     SUB_4136F0']
edges ['0x4136f0']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x412fc2
instr ['JMP     SHORT LOC_412FDB']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x41122b
instr ['JMP     __RTC_INITBASE']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x4110f0
instr ['JMP     ___SCRT_STUB_FOR_INITIALIZE_MTA']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x411a20
instr ['CMP     BYTE_41A138, 0', 'JNZ     SHORT LOCRET_411A48']
edges ['UnresolvableJumpTarget', '0x411a29']
edge_attr ['Jump', 'Fallthrough']
func_beg True
dir_call False
indir_call False
cond_jump True
dir_jump False
indir_jump True
has_return False


0x4136ff
instr ['PUSH    EDI']
edges ['0x413700']
edge_attr ['Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x411a48
instr ['RETN']
edges []
edge_attr []
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True


0x411bff
instr ['MOV     [EBP+MS_EXC.REGISTRATION.TRYLEVEL], 0', 'CALL    J____SCRT_ACQUIRE_STARTUP_LOCK']
edges ['UnresolvableCallTarget', '0x411c0b']
edge_attr ['Call', 'Fallthrough']
func_beg False
dir_call False
indir_call True
cond_jump False
dir_jump False
indir_jump False
has_return False


0x411a3f
instr ['PUSH    EAX', 'CALL    SUB_411316']
edges ['0x411316', '0x411a45']
edge_attr ['Call', 'Fallthrough']
func_beg False
dir_call True
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x41132f
instr ['JMP     _CRTDBGREPORT']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x411d83
instr ['MOV     EAX, [EBP+VAR_34]', 'PUSH    EAX; CODE', 'CALL    J__EXIT']
edges ['UnresolvableCallTarget', '0x411d8c']
edge_attr ['Call', 'Fallthrough']
func_beg False
dir_call False
indir_call True
cond_jump False
dir_jump False
indir_jump False
has_return False


0x411d53
instr ['MOV     EDX, [EBP+MS_EXC.EXC_PTR]', 'MOV     EAX, [EDX]', 'MOV     ECX, [EAX]', 'MOV     [EBP+EXCEPTIONNUM], ECX', 'MOV     EDX, [EBP+MS_EXC.EXC_PTR]', 'PUSH    EDX; EXCEPTIONPTR', 'MOV     EAX, [EBP+EXCEPTIONNUM]', 'PUSH    EAX; EXCEPTIONNUM', 'CALL    J__SEH_FILTER_EXE']
edges ['UnresolvableCallTarget', '0x411d6a']
edge_attr ['Call', 'Fallthrough']
func_beg False
dir_call False
indir_call True
cond_jump False
dir_jump False
indir_jump False
has_return False


0x4110be
instr ['JMP     SUB_411A10']
edges ['0x411a10']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump True
indir_jump False
has_return False


0x412d60
instr ['MOV     [EBP+MS_EXC.REGISTRATION.TRYLEVEL], 0', 'MOV     ECX, [EBP+VAR_24]', 'PUSH    ECX; VOID *', 'CALL    ?IS_POTENTIALLY_VALID_IMAGE_BASE@@YA_NQAX@Z; IS_POTENTIALLY_VALID_IMAGE_BASE(VOID * CONST)']
edges ['UnresolvableCallTarget', '0x412d70']
edge_attr ['Call', 'Fallthrough']
func_beg False
dir_call False
indir_call True
cond_jump False
dir_jump False
indir_jump False
has_return False


0x412ded
instr ['MOV     [EBP+MS_EXC.REGISTRATION.TRYLEVEL], 0FFFFFFFEH', 'JMP     SHORT LOC_412E37']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x412e30
instr ['MOV     [EBP+MS_EXC.REGISTRATION.TRYLEVEL], 0FFFFFFFEH']
edges ['0x412e37']
edge_attr ['Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x414d85
instr ['JMP     DS:__IMP__CRTDBGREPORT']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


0x411a10
instr ['MOV     EAX, OFFSET J__CRTDBGREPORTW', 'RETN']
edges []
edge_attr []
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return True
