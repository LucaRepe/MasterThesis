# Lab 15-01


## Anti-disassembly techniques check


Angr
In BB 0x100c there might be a CJWCC technique
In BB 0x105e there might be a CJWCC technique
In BB 0x101f there might be a CJWCC technique
In BB 0x1047 there might be a CJWCC technique


Ghidra
In BB 0x100c there might be a CJWCC technique
In BB 0x101f there might be a CJWCC technique
In BB 0x1047 there might be a CJWCC technique
In BB 0x105e there might be a CJWCC technique


Ida
In BB 0x100c there might be a CJWCC technique
In BB 0x101f there might be a CJWCC technique
In BB 0x1047 there might be a CJWCC technique
In BB 0x105e there might be a CJWCC technique


Radare
In BB 0x100c there might be a CJWCC technique
In BB 0x101f there might be a CJWCC technique
In BB 0x1033 there might be a CJWCC technique
In BB 0x1047 there might be a CJWCC technique
In BB 0x105e there might be a CJWCC technique


## Pin subset check on original addresses


Pin trace addresses: 88
Angr is False - addresses: 139
Ghidra is False - addresses: 138
Ida is False - addresses: 139
Radare is True - addresses: 155


Addresses present on the Pin trace that are missing in Angr: 2
{'0x1068', '0x1063'}
Addresses present on the Pin trace that are missing in Ghidra: 2
{'0x1068', '0x1063'}
Addresses present on the Pin trace that are missing in Ida: 2
{'0x1068', '0x1063'}
Addresses present on the Pin trace that are missing in Radare: 0


## Addresses of the function that contains the right technique: 0x1000 -> 0x101D


## Attributes comparison on function containing the technique


Angr
nodes_count 8
edges_count 8
func_beg_count 1
dir_call_count 1
indir_call_count 0
cond_jump_count 3
dir_jump_count 3
indir_jump_count 0
ret_count 0

Ghidra
nodes_count 8
edges_count 8
func_beg_count 1
dir_call_count 1
indir_call_count 0
cond_jump_count 3
dir_jump_count 3
indir_jump_count 0
ret_count 0

Ida
nodes_count 8
edges_count 8
func_beg_count 1
dir_call_count 1
indir_call_count 0
cond_jump_count 3
dir_jump_count 3
indir_jump_count 0
ret_count 0

Radare
nodes_count 9
edges_count 10
func_beg_count 1
dir_call_count 1
indir_call_count 0
cond_jump_count 3
dir_jump_count 3
indir_jump_count 0
ret_count 0


## Jaccard similarity check on nodes


Angr vs Ghidra 1.0
Angr vs Radare 0.6666666666666666
Angr vs Ida 1.0


Ghidra vs Radare 0.6666666666666666
Ghidra vs Angr 1.0
Ghidra vs Ida 1.0


Ida vs Ghidra 1.0
Ida vs Angr 1.0
Ida vs Radare 0.6666666666666666


Radare vs Ghidra 0.6666666666666666
Radare vs Angr 0.6666666666666666
Radare vs Ida 0.6666666666666666


## Jaccard similarity check on edges


Angr vs Ghidra 1.0
Angr vs Radare 0.6666666666666666
Angr vs Ida 1.0


Ghidra vs Radare 0.6666666666666666
Ghidra vs Angr 1.0
Ghidra vs Ida 1.0


Ida vs Ghidra 1.0
Ida vs Angr 1.0
Ida vs Radare 0.6666666666666666


Radare vs Ghidra 0.6666666666666666
Radare vs Angr 0.6666666666666666
Radare vs Ida 0.6666666666666666


## Graph edit distance check on differences subgraphs


Ghidra vs radare 6.0
Ghidra vs angr 0.0
Ghidra vs ida 0.0


Radare vs ghidra 6.0
Radare vs angr 6.0
Radare vs ida 6.0


Angr vs ghidra 0.0
Angr vs radare 6.0
Angr vs ida 0.0


Ida vs ghidra 0.0
Ida vs radare 6.0
Ida vs angr 0.0


## Addresses of the function that contains the wrong technique: 0x1030 -> 0x1044


## Attributes comparison on function containing the technique


Angr
nodes_count 3
edges_count 2
func_beg_count 0
dir_call_count 0
indir_call_count 0
cond_jump_count 1
dir_jump_count 1
indir_jump_count 0
ret_count 0

Ghidra
nodes_count 3
edges_count 2
func_beg_count 0
dir_call_count 0
indir_call_count 0
cond_jump_count 1
dir_jump_count 1
indir_jump_count 0
ret_count 0

Ida
nodes_count 3
edges_count 2
func_beg_count 0
dir_call_count 0
indir_call_count 0
cond_jump_count 1
dir_jump_count 1
indir_jump_count 0
ret_count 0

Radare
nodes_count 8
edges_count 9
func_beg_count 0
dir_call_count 1
indir_call_count 0
cond_jump_count 3
dir_jump_count 3
indir_jump_count 0
ret_count 0

## Jaccard similarity check on nodes


Angr vs Ghidra 1.0
Angr vs Radare 0.375
Angr vs Ida 1.0


Ghidra vs Radare 0.375
Ghidra vs Angr 1.0
Ghidra vs Ida 1.0


Ida vs Ghidra 1.0
Ida vs Angr 1.0
Ida vs Radare 0.375


Radare vs Ghidra 0.375
Radare vs Angr 0.375
Radare vs Ida 0.375


## Jaccard similarity check on edges


Angr vs Ghidra 1.0
Angr vs Radare 0.375
Angr vs Ida 1.0


Ghidra vs Radare 0.375
Ghidra vs Angr 1.0
Ghidra vs Ida 1.0


Ida vs Ghidra 1.0
Ida vs Angr 1.0
Ida vs Radare 0.375


Radare vs Ghidra 0.375
Radare vs Angr 0.375
Radare vs Ida 0.375


## Graph edit distance check on differences subgraphs


Ghidra vs radare 13.0
Ghidra vs angr 1.0
Ghidra vs ida 1.0


Radare vs ghidra 13.0
Radare vs angr 13.0
Radare vs ida 13.0


Angr vs ghidra 1.0
Angr vs radare 13.0
Angr vs ida 0.0


Ida vs ghidra 1.0
Ida vs radare 13.0
Ida vs angr 0.0