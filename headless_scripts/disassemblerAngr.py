import angr
import sys
import re


from typing import List, Tuple


class BasicBlock:
    start_addr: int
    list_bytes: List[List]
    list_instr: List[str]

    def __repr__(self):
        return f'{self.start_addr} {self.list_bytes} {self.list_instr}'

def run():
    f = open(sys.argv[2], 'w')
    base_addr = 0x100000
    p = angr.Project(sys.argv[1], auto_load_libs = False, load_options = {'main_opts':{'base_addr': base_addr}})
    cfg = p.analyses.CFGFast()
    cfg.normalize()
    fun_to_bb = dict()
    for func_node in cfg.functions.values():
        fun_to_bb[func_node.addr] = list()
        for block in func_node.blocks:
            c = block.capstone
            lbytes = list()
            linstr = list()
            for i in c.insns:
                f.write(' '.join(re.findall(r'.{1,2}', i.insn.bytes.hex())).upper() + '\t\t' + i.mnemonic.upper() + " " + i.op_str.upper() + '\n')
                lbytes.append(i.opcode)
                linstr.append(f'{i.mnemonic} {i.op_str}')
            bb = BasicBlock()

            bb.start_addr = block.addr
            bb.list_bytes = lbytes
            bb.list_instr = linstr
            fun_to_bb[func_node.addr].append(bb)
    print(fun_to_bb)


if __name__ == '__main__':
    run()
