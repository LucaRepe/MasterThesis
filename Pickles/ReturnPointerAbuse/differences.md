# Return pointer abuse


Addresses of the function that contains the technique: 0x108E -> 0x10BF


## Pin subset check on original addresses


Pin trace addresses: 554
Angr is True - addresses: 1132
Ghidra is False - addresses: 1075
Ida is True - addresses: 1136
Radare is False - addresses: 973


Addresses present on the Pin trace that are missing in Angr: 0
Addresses present on the Pin trace that are missing in Ghidra: 61
{'0x118a', '0x10fb', '0x10f8', '0x110b', '0x10e2', '0x125e', '0x10d3', '0x118d', '0x1269', '0x110e', '0x1192', '0x19ea', '0x112d', '0x111c', '0x10bc', '0x10fe', '0x10ce', '0x10dc', '0x1106', '0x1193', '0x10c1', '0x1113', '0x10de', '0x1121', '0x19ef', '0x1188', '0x10f0', '0x10ef', '0x1182', '0x1124', '0x19f5', '0x10c9', '0x1263', '0x10ed', '0x112a', '0x126f', '0x10e0', '0x1191', '0x119c', '0x10e8', '0x10b9', '0x10eb', '0x126e', '0x1268', '0x1119', '0x10d9', '0x10c7', '0x10f5', '0x10bf', '0x10fd', '0x1185', '0x119b', '0x118f', '0x1194', '0x1104', '0x1110', '0x1199', '0x1d82', '0x10fa', '0x1111', '0x1101'}
Addresses present on the Pin trace that are missing in Ida: 0
Addresses present on the Pin trace that are missing in Radare: 120
{'0x118a', '0x1244', '0x1a80', '0x11f2', '0x112d', '0x111c', '0x11c5', '0x121b', '0x11fd', '0x10dc', '0x125b', '0x1121', '0x11d6', '0x1124', '0x1a81', '0x1a87', '0x10c9', '0x11fb', '0x11c3', '0x119c', '0x123f', '0x11f1', '0x1268', '0x122b', '0x10fd', '0x11ec', '0x1104', '0x1a8e', '0x1110', '0x1199', '0x11cc', '0x11ca', '0x11b3', '0x123a', '0x11ac', '0x125e', '0x10d3', '0x11f7', '0x10bc', '0x1193', '0x10c1', '0x1188', '0x1aa9', '0x1182', '0x11b8', '0x112a', '0x11d3', '0x126f', '0x1225', '0x11d9', '0x1231', '0x1238', '0x1119', '0x10c7', '0x10f5', '0x11b9', '0x119b', '0x1256', '0x1194', '0x124d', '0x1a8c', '0x1111', '0x1249', '0x1005', '0x10fb', '0x10f8', '0x1aaa', '0x11ae', '0x10e2', '0x118d', '0x124b', '0x11ab', '0x10ce', '0x1106', '0x125d', '0x10f0', '0x1a82', '0x1216', '0x122a', '0x10ed', '0x10e0', '0x1220', '0x10e8', '0x10eb', '0x100b', '0x10d9', '0x11f9', '0x10bf', '0x11e2', '0x118f', '0x11be', '0x110b', '0x1236', '0x1269', '0x110e', '0x1192', '0x11db', '0x10fe', '0x100c', '0x1113', '0x10de', '0x1202', '0x10ef', '0x11ce', '0x11e7', '0x1263', '0x1207', '0x1191', '0x10b9', '0x126e', '0x1aab', '0x11f8', '0x1000', '0x1185', '0x1209', '0x11d7', '0x10fa', '0x1230', '0x11dd', '0x1101'}


## Attributes comparison on function containing the technique


Angr
nodes_count 7
edges_count 7
func_beg_count 2
dir_call_count 1
indir_call_count 3
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 1

Ghidra
nodes_count 4
edges_count 4
func_beg_count 0
dir_call_count 0
indir_call_count 2
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 1

Ida
nodes_count 7
edges_count 6
func_beg_count 0
dir_call_count 1
indir_call_count 2
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 1

Radare
nodes_count 4
edges_count 3
func_beg_count 0
dir_call_count 1
indir_call_count 1
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 1


## Jaccard similarity check on nodes


Angr vs Ghidra 0.5
Angr vs Radare 0.5
Angr vs Ida 1.0


Ghidra vs Radare 1.0
Ghidra vs Angr 0.5
Ghidra vs Ida 0.5


Ida vs Ghidra 0.5
Ida vs Angr 1.0
Ida vs Radare 0.5


Radare vs Ghidra 1.0
Radare vs Angr 0.5
Radare vs Ida 0.5


## Jaccard similarity check on edges


Angr vs Ghidra 0.5
Angr vs Radare 0.5
Angr vs Ida 1.0


Ghidra vs Radare 1.0
Ghidra vs Angr 0.5
Ghidra vs Ida 0.5


Ida vs Ghidra 0.5
Ida vs Angr 1.0
Ida vs Radare 0.5


Radare vs Ghidra 1.0
Radare vs Angr 0.5
Radare vs Ida 0.5


## Graph edit distance check on differences subgraphs


Ghidra vs radare 1.0
Ghidra vs angr 7.0
Ghidra vs ida 8.0


Radare vs ghidra 1.0
Radare vs angr 8.0
Radare vs ida 7.0


Angr vs ghidra 7.0
Angr vs radare 8.0
Angr vs ida 2.0


Ida vs ghidra 8.0
Ida vs radare 7.0
Ida vs angr 2.0
