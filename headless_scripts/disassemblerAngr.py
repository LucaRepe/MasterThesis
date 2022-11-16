import angr
import sys
import re

def run():
    f = open(sys.argv[2], 'w')
    base_addr = 0x100000
    p = angr.Project(sys.argv[1], auto_load_libs = False, load_options = {'main_opts':{'base_addr': base_addr}})
    cfg = p.analyses.CFGFast()
    cfg.normalize()
    for func_node in cfg.functions.values():
        for block in func_node.blocks:
            c = block.capstone
            for i in c.insns:
                f.write(' '.join(re.findall(r'.{1,2}', i.insn.bytes.hex())).upper() + '\t\t' + i.mnemonic.upper() + " " + i.op_str.upper() + '\n')


if __name__ == '__main__':
    run()