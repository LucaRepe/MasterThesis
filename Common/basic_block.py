from typing import List

class BasicBlock:
    start_addr: int
    list_bytes: List[List]
    list_instr: List[str]
    list_instr_norm: List[str]
    list_addr: List[int]
    list_edges: List[int]
    list_edge_attr: List[str]
    function_beginning: bool
    direct_fun_call: bool
    indirect_fun_call: bool
    conditional_jump: bool
    direct_jump: bool
    indirect_jump: bool
    has_return: bool
    unique_hash_identifier: int

    def __repr__(self):
        return f'{self.start_addr} {self.list_bytes} {self.list_instr} {self.list_addr} {self.list_edges} ' \
                f'{self.list_edge_attr} '