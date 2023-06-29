# Lab15-03

## Anti-disassembly techniques check


Angr
In BBs 0x1515 0x1517 there might be a CJWST technique
In BB 0x148c there might be a CJWCC technique
In BB 0x14c0 there might be a ID technique
In BB 0x1000 there might be a RPA technique


Ghidra
In BB 0x148c there might be a CJWCC technique
In BB 0x1000 there might be a RPA technique


Ida
In BB 0x1000 there might be a RPA technique


Radare
In BBs 0x1515 0x1517 there might be a CJWST technique
In BB 0x148c there might be a CJWCC technique
In BB 0x1000 there might be a RPA technique


## Addresses of the function that contains the RPA technique: 0x1000 -> 0x101E


Angr
nodes_count 3
edges_count 2
func_beg_count 1
dir_call_count 1
indir_call_count 0
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 0

Ghidra
nodes_count 3
edges_count 2
func_beg_count 1
dir_call_count 1
indir_call_count 0
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 0

Ida
nodes_count 3
edges_count 2
func_beg_count 1
dir_call_count 1
indir_call_count 0
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 0

Radare
nodes_count 3
edges_count 2
func_beg_count 1
dir_call_count 1
indir_call_count 0
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 0


## Addresses of the function that contains the CJWCC technique: 0x148C -> 0x14B3

Attributes comparison on function containing the technique


Angr
nodes_count 7
edges_count 5
func_beg_count 2
dir_call_count 1
indir_call_count 0
cond_jump_count 1
dir_jump_count 2
indir_jump_count 0
ret_count 0

Ghidra
nodes_count 4
edges_count 3
func_beg_count 1
dir_call_count 0
indir_call_count 0
cond_jump_count 1
dir_jump_count 2
indir_jump_count 0
ret_count 0

Ida
nodes_count 5
edges_count 3
func_beg_count 2
dir_call_count 1
indir_call_count 0
cond_jump_count 0
dir_jump_count 1
indir_jump_count 0
ret_count 0

Radare
nodes_count 6
edges_count 5
func_beg_count 1
dir_call_count 1
indir_call_count 0
cond_jump_count 1
dir_jump_count 2
indir_jump_count 0
ret_count 0

Jaccard similarity check on nodes


Angr vs Ghidra 0.5
Angr vs Radare 0.8333333333333334
Angr vs Ida 0.2857142857142857


Ghidra vs Radare 0.6
Ghidra vs Angr 0.5
Ghidra vs Ida 0.0


Ida vs Ghidra 0.0
Ida vs Angr 0.2857142857142857
Ida vs Radare 0.3333333333333333


Radare vs Ghidra 0.6
Radare vs Angr 0.8333333333333334
Radare vs Ida 0.3333333333333333


Jaccard similarity check on edges


Angr vs Ghidra 0.5
Angr vs Radare 0.8333333333333334
Angr vs Ida 0.2857142857142857


Ghidra vs Radare 0.6
Ghidra vs Angr 0.5
Ghidra vs Ida 0.0


Ida vs Ghidra 0.0
Ida vs Angr 0.2857142857142857
Ida vs Radare 0.3333333333333333


Radare vs Ghidra 0.6
Radare vs Angr 0.8333333333333334
Radare vs Ida 0.3333333333333333


Graph edit distance check on differences subgraphs


Ghidra vs radare 5.0
Ghidra vs angr 5.0
Ghidra vs ida 2.0


Radare vs ghidra 5.0
Radare vs angr 4.0
Radare vs ida 5.0


Angr vs ghidra 5.0
Angr vs radare 4.0
Angr vs ida 6.0


Ida vs ghidra 2.0
Ida vs radare 5.0
Ida vs angr 6.0
