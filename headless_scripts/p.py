import r2pipe
import sys

R2 = r2pipe.open(sys.argv[0]) # Open r2 with file
R2.cmd('aaa')              # Analyze file
R2.cmd('pdf @@f > out.txt')     # Write disassembly for each function to out file
R2.quit()                   # Quit r2