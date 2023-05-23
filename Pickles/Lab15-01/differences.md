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
In BB 0x1032 there might be a ID technique


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