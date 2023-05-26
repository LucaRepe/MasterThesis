# Lab 15-02

## Anti-disassembly techniques check


Angr
In BBs 0x1263 0x126b there might be a CJWST technique
In BB 0x1154 there might be a CJWCC technique
In BB 0x11d0 there might be a CJWCC technique
In BB 0x12e3 there might be a CJWCC technique
In BB 0x120f there might be a ID technique
In BB 0x12e3 there might be a ID technique


Ghidra
In BB 0x1154 there might be a CJWCC technique


Ida
In BB 0x1154 there might be a CJWCC technique


Radare
In BBs 0x1263 0x126b there might be a CJWST technique
In BB 0x1154 there might be a CJWCC technique
In BB 0x11d0 there might be a CJWCC technique
In BB 0x12e3 there might be a CJWCC technique
In BB 0x120f there might be a ID technique
In BB 0x12e3 there might be a ID technique


## Pin subset check on original addresses


Pin trace addresses: 124
Angr is True - addresses: 393
Ghidra is True - addresses: 292
Ida is True - addresses: 292
Radare is True - addresses: 406


Addresses present on the Pin trace that are missing in Angr: 0
Addresses present on the Pin trace that are missing in Ghidra: 0
Addresses present on the Pin trace that are missing in Ida: 0
Addresses present on the Pin trace that are missing in Radare: 0

## Addresses of the function that contains the first CJWCC technique: 0x113F -> 0x1167


## Attributes comparison on function containing the technique


Angr
nodes_count 9
edges_count 7
func_beg_count 1
dir_call_count 1
indir_call_count 1
cond_jump_count 1
dir_jump_count 2
indir_jump_count 0
ret_count 0

Ghidra
nodes_count 6
edges_count 5
func_beg_count 0
dir_call_count 0
indir_call_count 1
cond_jump_count 1
dir_jump_count 2
indir_jump_count 0
ret_count 0

Ida
nodes_count 6
edges_count 5
func_beg_count 0
dir_call_count 0
indir_call_count 1
cond_jump_count 1
dir_jump_count 2
indir_jump_count 0
ret_count 0

Radare
nodes_count 8
edges_count 7
func_beg_count 0
dir_call_count 1
indir_call_count 1
cond_jump_count 1
dir_jump_count 2
indir_jump_count 0
ret_count 0

## Jaccard similarity check on nodes


Angr vs Ghidra 0.5
Angr vs Radare 0.7142857142857143
Angr vs Ida 0.5


Ghidra vs Radare 0.5
Ghidra vs Angr 0.5
Ghidra vs Ida 1.0


Ida vs Ghidra 1.0
Ida vs Angr 0.5
Ida vs Radare 0.5


Radare vs Ghidra 0.5
Radare vs Angr 0.7142857142857143
Radare vs Ida 0.5


## Jaccard similarity check on edges


Angr vs Ghidra 0.5
Angr vs Radare 0.7142857142857143
Angr vs Ida 0.5


Ghidra vs Radare 0.5
Ghidra vs Angr 0.5
Ghidra vs Ida 1.0


Ida vs Ghidra 1.0
Ida vs Angr 0.5
Ida vs Radare 0.5


Radare vs Ghidra 0.5
Radare vs Angr 0.7142857142857143
Radare vs Ida 0.5


## Graph edit distance check on differences subgraphs


Ghidra vs radare 6.0
Ghidra vs angr 5.0
Ghidra vs ida 0.0


Radare vs ghidra 6.0
Radare vs angr 2.0
Radare vs ida 6.0


Angr vs ghidra 5.0
Angr vs radare 2.0
Angr vs ida 5.0


Ida vs ghidra 0.0
Ida vs radare 6.0
Ida vs angr 5.0


## Addresses of the function that contains the first CJWCC technique: 0x120F -> 0x1229

Angr
nodes_count 5
edges_count 3
func_beg_count 1
dir_call_count 0
indir_call_count 1
cond_jump_count 0
dir_jump_count 1
indir_jump_count 0
ret_count 0

Ghidra
nodes_count 0
edges_count 0
func_beg_count 0
dir_call_count 0
indir_call_count 0
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 0

Ida
nodes_count 0
edges_count 0
func_beg_count 0
dir_call_count 0
indir_call_count 0
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 0

Radare
nodes_count 6
edges_count 5
func_beg_count 0
dir_call_count 1
indir_call_count 1
cond_jump_count 0
dir_jump_count 1
indir_jump_count 0
ret_count 0


## Addresses of the function that contains the CJWST technique: 0x1263 -> 0x126E

Attributes comparison on function containing the technique


Angr
nodes_count 6
edges_count 6
func_beg_count 0
dir_call_count 1
indir_call_count 0
cond_jump_count 2
dir_jump_count 2
indir_jump_count 0
ret_count 0

Ghidra
nodes_count 0
edges_count 0
func_beg_count 0
dir_call_count 0
indir_call_count 0
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 0

Ida
nodes_count 0
edges_count 0
func_beg_count 0
dir_call_count 0
indir_call_count 0
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 0

Radare
nodes_count 7
edges_count 8
func_beg_count 0
dir_call_count 1
indir_call_count 1
cond_jump_count 2
dir_jump_count 2
indir_jump_count 0
ret_count 0


## Addresses of the function that contains the CJWCC + ID technique: 0x12E3 -> 0x12F1

Angr
nodes_count 5
edges_count 4
func_beg_count 0
dir_call_count 1
indir_call_count 0
cond_jump_count 1
dir_jump_count 1
indir_jump_count 0
ret_count 0

Ghidra
nodes_count 0
edges_count 0
func_beg_count 0
dir_call_count 0
indir_call_count 0
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 0

Ida
nodes_count 0
edges_count 0
func_beg_count 0
dir_call_count 0
indir_call_count 0
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 0

Radare
nodes_count 6
edges_count 6
func_beg_count 0
dir_call_count 1
indir_call_count 0
cond_jump_count 1
dir_jump_count 2
indir_jump_count 0
ret_count 0