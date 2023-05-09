# Disassembly desynchronization

Addresses of the function that contains the technique: 0x1000 -> 0x102F

## Pin subset check on original addresses


Pin trace addresses: 536
Angr is True - addresses: 1115
Ghidra is False - addresses: 1109
Ida is True - addresses: 1119
Radare is False - addresses: 1007


Addresses present on the Pin trace that are missing in Angr: 0
Addresses present on the Pin trace that are missing in Ghidra: 10
{'0x121c', '0x19b3', '0x1227', '0x19a8', '0x1d42', '0x122c', '0x1226', '0x122d', '0x1221', '0x19ad'}
Addresses present on the Pin trace that are missing in Ida: 0
Addresses present on the Pin trace that are missing in Radare: 65
{'0x11d9', '0x1a40', '0x11a0', '0x11de', '0x1199', '0x11d4', '0x1169', '0x1227', '0x1202', '0x11f4', '0x11f6', '0x11fd', '0x1176', '0x1a4a', '0x11e3', '0x11c7', '0x120b', '0x118c', '0x1195', '0x1a3f', '0x1194', '0x1a4c', '0x117c', '0x11ee', '0x1a3e', '0x122c', '0x1a69', '0x11a5', '0x1177', '0x121c', '0x1183', '0x11b5', '0x11b9', '0x1214', '0x1191', '0x1188', '0x11e9', '0x118a', '0x11b7', '0x1197', '0x1226', '0x11aa', '0x1a45', '0x1a67', '0x11e8', '0x1171', '0x1219', '0x11ef', '0x1207', '0x11bb', '0x11b0', '0x121b', '0x11b6', '0x11f8', '0x11c0', '0x1181', '0x1209', '0x119b', '0x122d', '0x11af', '0x1a68', '0x116c', '0x1221', '0x11c5', '0x116a'}


## Attributes comparison on function containing the technique


Angr
nodes_count 3
edges_count 2
func_beg_count 1
dir_call_count 0
indir_call_count 1
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 1

Ghidra
nodes_count 3
edges_count 2
func_beg_count 1
dir_call_count 0
indir_call_count 1
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 1

Ida
nodes_count 3
edges_count 2
func_beg_count 1
dir_call_count 0
indir_call_count 1
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 1

Radare
nodes_count 3
edges_count 2
func_beg_count 1
dir_call_count 0
indir_call_count 1
cond_jump_count 0
dir_jump_count 0
indir_jump_count 0
ret_count 1
