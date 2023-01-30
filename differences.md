## Differences between Ghidra and Radare

0x109b
instr ['HLT']
edges ['0x109c']
edge_attr ['Fallthrough']
func_beg False
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x1030
instr ['PUSH dword ptr [EBX + 0x4]', 'JMP dword ptr [EBX + 0x8]']
edges ['UnresolvableJumpTarget']
edge_attr ['Jump']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump True
has_return False


## Differences between IDA and Ghidra

0x4014
instr ['EXTRN __CXA_FINALIZE:NEAR ; WEAK']
edges ['0x4018']
edge_attr ['Fallthrough']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x4018
instr ['EXTRN PUTS:NEAR']
edges []
edge_attr []
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x4010
instr ['EXTRN __LIBC_START_MAIN:NEAR']
edges ['0x4014']
edge_attr ['Fallthrough']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


## Differences between angr and IDA

0x10e9
instr ['LEA ESI, [ESI]']
edges ['0x10f0']
edge_attr ['Fallthrough']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x1066
instr ['NOP ']
edges ['0x1070']
edge_attr ['Fallthrough']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x1137
instr ['LEA ESI, [ESI]', 'NOP ']
edges ['0x1140']
edge_attr ['Fallthrough']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x10a4
instr ['NOP ', 'NOP ', 'NOP ', 'NOP ', 'NOP ', 'NOP ']
edges ['0x10b0']
edge_attr ['Fallthrough']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x118b
instr ['LEA ESI, [ESI]', 'NOP ']
edges ['0x1190']
edge_attr ['Fallthrough']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False


0x10e3
instr ['LEA ESI, [ESI]', 'NOP ']
edges ['0x10e8']
edge_attr ['Fallthrough']
func_beg True
dir_call False
indir_call False
cond_jump False
dir_jump False
indir_jump False
has_return False
