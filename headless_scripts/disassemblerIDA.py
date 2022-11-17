import sys
import idc
import idautils


def unoverflow(x):
    return (abs(x) ^ 0xff) + 1


def to_hex(integer):
    return '{:02x}'.format(integer)


def run():
    # file for output
    f = open(idc.ARGV[1], 'w') if len(idc.ARGV) > 1 else sys.stdout
    log = f.write

    # wait for auto-analysis to complete
    idc.auto_wait()

    cur_addr = 0
    for func in idautils.Functions():
        start = idc.get_func_attr(func, idc.FUNCATTR_START)
        end = idc.get_func_attr(func, idc.FUNCATTR_END)
        cur_addr = start
        while cur_addr <= end:
            log(' '.join([to_hex(b) if b >= 0 else to_hex(unoverflow(b)) for b in idc.get_bytes(cur_addr, idc.get_item_size(cur_addr))]).upper() + '\t\t')
            log(idc.GetDisasm(cur_addr).upper() + '\n')
            cur_addr = idc.next_head(cur_addr, end)

    # if logging to a file, close it and exit IDA Pro
    if f != sys.stdout:
        f.close()
        idc.qexit(0)


if __name__ == '__main__':
    run()
