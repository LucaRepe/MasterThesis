# Impossible disassembly


Addresses of the function that contains the technique: 0x105b -> 0x109b


## Pin subset check on original addresses


Pin trace addresses: 531
Angr is False - addresses: 1107
Ghidra is False - addresses: 1056
Ida is False - addresses: 1018
Radare is False - addresses: 1002


Addresses present on the Pin trace that are missing in Angr: 6
{'0x113f', '0x113d', '0x1083', '0x1084', '0x1081', '0x1140'}
Addresses present on the Pin trace that are missing in Ghidra: 58
{'0x1d32', '0x10f8', '0x19a1', '0x10ec', '0x10d4', '0x10d1', '0x120a', '0x1087', '0x10cd', '0x108a', '0x10e3', '0x10a1', '0x10a6', '0x108c', '0x1214', '0x113f', '0x1147', '0x113d', '0x10d6', '0x1083', '0x10a8', '0x1145', '0x1140', '0x10ca', '0x10e0', '0x10b0', '0x1096', '0x1148', '0x199b', '0x10db', '0x10e6', '0x10b9', '0x1091', '0x1215', '0x10de', '0x121a', '0x10f5', '0x10bb', '0x1081', '0x10c5', '0x1142', '0x1144', '0x120f', '0x10e1', '0x10bd', '0x10b6', '0x1084', '0x1143', '0x109b', '0x10c8', '0x10a4', '0x10cb', '0x121b', '0x10c0', '0x10ce', '0x1996', '0x10f2', '0x10aa'}
Addresses present on the Pin trace that are missing in Ida: 87
{'0x1025', '0x10f8', '0x1137', '0x10ec', '0x1042', '0x10a1', '0x100f', '0x1103', '0x113d', '0x1044', '0x1096', '0x10db', '0x10e6', '0x10de', '0x1081', '0x1132', '0x1054', '0x1001', '0x10e1', '0x107b', '0x10bd', '0x10fe', '0x10aa', '0x100d', '0x10d4', '0x10d1', '0x10a6', '0x108c', '0x1076', '0x1083', '0x112f', '0x107d', '0x103b', '0x101b', '0x1140', '0x1016', '0x113c', '0x103d', '0x10c5', '0x10f5', '0x1106', '0x1128', '0x100c', '0x104b', '0x112d', '0x10b6', '0x10c8', '0x1014', '0x10f2', '0x1087', '0x108a', '0x1003', '0x1059', '0x104d', '0x1052', '0x10d6', '0x10b0', '0x10e0', '0x105b', '0x1064', '0x10b9', '0x1091', '0x10bb', '0x1080', '0x1070', '0x1084', '0x109b', '0x10cb', '0x10c0', '0x102f', '0x1061', '0x10cd', '0x10e3', '0x1000', '0x106d', '0x113f', '0x1049', '0x1005', '0x106a', '0x10a8', '0x10ca', '0x1004', '0x1139', '0x10a4', '0x1039', '0x10ce', '0x1006'}
Addresses present on the Pin trace that are missing in Radare: 65
{'0x119d', '0x1a33', '0x1193', '0x115f', '0x11b3', '0x1a56', '0x1a38', '0x116f', '0x1209', '0x11a7', '0x1158', '0x11e4', '0x1183', '0x11c7', '0x1a57', '0x117f', '0x11c2', '0x1198', '0x117a', '0x11d7', '0x1214', '0x1176', '0x1157', '0x119e', '0x1171', '0x1202', '0x1189', '0x11ae', '0x11dc', '0x11a5', '0x1a55', '0x11e6', '0x11cc', '0x1a2d', '0x1a2e', '0x116a', '0x11eb', '0x11f9', '0x1215', '0x1165', '0x1164', '0x121a', '0x11f0', '0x1182', '0x1207', '0x120f', '0x1185', '0x1187', '0x11f5', '0x1a2c', '0x11e2', '0x11a4', '0x11dd', '0x118e', '0x11a9', '0x11d1', '0x1a3a', '0x11a3', '0x115a', '0x121b', '0x11d6', '0x120a', '0x1178', '0x11f7', '0x11b5'}


## Attributes comparison on function containing the technique


Angr
nodes_count 8
edges_count 7
func_beg_count 1
dir_call_count 0
indir_call_count 2
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
edges_count 7
func_beg_count 0
dir_call_count 0
indir_call_count 2
cond_jump_count 1
dir_jump_count 2
indir_jump_count 0
ret_count 0


## Jaccard similarity check on nodes


Angr vs Ghidra 0.75
Angr vs Radare 0.875
Angr vs Ida 0.0


Ghidra vs Radare 0.8571428571428571
Ghidra vs Angr 0.75
Ghidra vs Ida 0.0


Ida vs Ghidra 0.0
Ida vs Angr 0.0
Ida vs Radare 0.0


Radare vs Ghidra 0.8571428571428571
Radare vs Angr 0.875
Radare vs Ida 0.0


## Jaccard similarity check on edges


Angr vs Ghidra 0.75
Angr vs Radare 0.875
Angr vs Ida 0.0


Ghidra vs Radare 0.8571428571428571
Ghidra vs Angr 0.75
Ghidra vs Ida 0.0


Ida vs Ghidra 0.0
Ida vs Angr 0.0
Ida vs Radare 0.0


Radare vs Ghidra 0.8571428571428571
Radare vs Angr 0.875
Radare vs Ida 0.0


## Graph edit distance check on differences subgraphs


Ghidra vs radare 4.0
Ghidra vs angr 4.0
Ghidra vs ida 11.0


Radare vs ghidra 4.0
Radare vs angr 4.0
Radare vs ida 14.0


Angr vs ghidra 4.0
Angr vs radare 4.0
Angr vs ida 15.0


Ida vs ghidra 11.0
Ida vs radare 14.0
Ida vs angr 15.0
