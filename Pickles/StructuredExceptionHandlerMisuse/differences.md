# Structured exception handler misuse

IDA recognizes a BB at 0x11e09 that isn't a BB.
Radare misses two BBs.
Angr finds one additional direct call at '0x11e09' that doesn't exist and counts two function beginning at '0x11e09' and '0x11e03'
