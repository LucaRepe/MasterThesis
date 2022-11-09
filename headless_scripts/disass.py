import sys
import idc
import idautils

f = open(idc.ARGV[1], 'w') if len(idc.ARGV) > 1 else sys.stdout
log = f.write

# log current file path
log(idc.get_input_file_path() + '\n')

# wait for auto-analysis to complete
idc.auto_wait()

# count functions
#log( 'count %d\n' % len(list(idautils.Functions())) )

for func in idautils.Functions():
    flags = idc.get_func_attr(func, FUNCATTR_FLAGS)
    if flags & FUNC_LIB or flags & FUNC_THUNK:
        continue
    dism_addr = list(idautils.FuncItems(func))
    for line in dism_addr:
        #log(idc.print_insn_mnem(line) + '\n' )
        disass = idc.generate_disasm_line(line, 0)
        log(disass + '\n' )

# if logging to a file, close it and exit IDA Pro
if f != sys.stdout:
    f.close()
    idc.qexit(0)