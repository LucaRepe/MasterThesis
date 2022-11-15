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
            #print(re.sub(r'.', '', str(block.disassembly), count = 10))
            #print(block.bytes.hex())
            print(re.sub(r'.', '', str(block.capstone), count = 10) + '\t' + block.bytes.hex())       

if __name__ == '__main__':
    run()