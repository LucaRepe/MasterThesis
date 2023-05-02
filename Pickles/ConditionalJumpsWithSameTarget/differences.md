# Conditional jumps with same target


Range of addresses regarding the technique: 0x1015 -> 0x1069


## Pin subset check on original addresses


Pin trace addresses: 546
Angr is False - addresses: 1126
Ghidra is False - addresses: 1120
Ida is False - addresses: 1130
Radare is False - addresses: 1018


Addresses present on the Pin trace that are missing in Angr: 2
{'0x1052', '0x1055'}
Addresses present on the Pin trace that are missing in Ghidra: 12
{'0x1260', '0x1255', '0x1055', '0x1250', '0x19dc', '0x19e7', '0x1261', '0x19e1', '0x1d72', '0x125a', '0x1052', '0x125b'}
Addresses present on the Pin trace that are missing in Ida: 2
{'0x1052', '0x1055'}
Addresses present on the Pin trace that are missing in Radare: 65
{'0x123f', '0x11cf', '0x11c8', '0x1222', '0x1212', '0x11b0', '0x11e9', '0x11f9', '0x11cb', '0x1261', '0x125a', '0x1236', '0x11be', '0x122c', '0x1217', '0x123b', '0x1231', '0x11d9', '0x1a74', '0x11c9', '0x11c0', '0x11aa', '0x121c', '0x122a', '0x11b5', '0x11d4', '0x1a7e', '0x11de', '0x11a0', '0x11eb', '0x1a9d', '0x1a9c', '0x123d', '0x121d', '0x119d', '0x11f4', '0x1260', '0x11a5', '0x1a9b', '0x1a72', '0x1250', '0x124d', '0x1a73', '0x1a79', '0x1a80', '0x11ab', '0x125b', '0x11c5', '0x11b7', '0x11e4', '0x120d', '0x1208', '0x1255', '0x1248', '0x11bc', '0x124f', '0x11ef', '0x1223', '0x1228', '0x119e', '0x11e3', '0x11fb', '0x11cd', '0x11ed', '0x11ea'}


## Attributes comparison on function containing the technique


Angr
nodes_count 8
edges_count 8
func_beg_count 1
dir_call_count 3
indir_call_count 1
cond_jump_count 2
dir_jump_count 2
indir_jump_count 0
ret_count 1

Ghidra
nodes_count 8
edges_count 8
func_beg_count 1
dir_call_count 3
indir_call_count 1
cond_jump_count 2
dir_jump_count 2
indir_jump_count 0
ret_count 1

Ida
nodes_count 8
edges_count 8
func_beg_count 2
dir_call_count 3
indir_call_count 1
cond_jump_count 2
dir_jump_count 2
indir_jump_count 0
ret_count 1

Radare
nodes_count 8
edges_count 9
func_beg_count 1
dir_call_count 3
indir_call_count 1
cond_jump_count 2
dir_jump_count 2
indir_jump_count 0
ret_count 1

## Jaccard similarity check on nodes


Angr vs Ghidra 1.0
Angr vs Radare 0.4
Angr vs Ida 1.0


Ghidra vs Radare 0.4
Ghidra vs Angr 1.0
Ghidra vs Ida 1.0


Ida vs Ghidra 1.0
Ida vs Angr 1.0
Ida vs Radare 0.4


Radare vs Ghidra 0.4
Radare vs Angr 0.4
Radare vs Ida 0.4


## Jaccard similarity check on edges


Angr vs Ghidra 1.0
Angr vs Radare 0.4
Angr vs Ida 1.0


Ghidra vs Radare 0.4
Ghidra vs Angr 1.0
Ghidra vs Ida 1.0


Ida vs Ghidra 1.0
Ida vs Angr 1.0
Ida vs Radare 0.4


Radare vs Ghidra 0.4
Radare vs Angr 0.4
Radare vs Ida 0.4


## Graph edit distance check on differences subgraphs


Ghidra vs radare 4.0
Ghidra vs angr 0.0
Ghidra vs ida 0.0


Radare vs ghidra 4.0
Radare vs angr 4.0
Radare vs ida 4.0


Angr vs ghidra 0.0
Angr vs radare 4.0
Angr vs ida 0.0


Ida vs ghidra 0.0
Ida vs radare 4.0
Ida vs angr 0.0
