#!/bin/bash
./Tools/ghidra_10.2.3_PUBLIC/support/analyzeHeadless /root/MasterThesis ANewProject -import /root/MasterThesis/mainTechVS.exe -scriptPath /root/MasterThesis -postScript disassemblerGhidra.py /root/MasterThesis/Pickles/analysisGhidra.txt /root/MasterThesis/Pickles/ghidra.p -deleteProject
