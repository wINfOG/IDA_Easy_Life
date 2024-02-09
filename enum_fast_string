#origin: https://github.com/mandiant/flare-emu/blob/c6983cdc67e63c11b22c0e45ce1d0c0e1ec480e0/tests/flare_emu_test.py
import flare_emu
import idc
import idaapi
import ida_bytes
import idautils
import ida_ua
import ida_funcs
import ida_segment

from unicorn import UC_MEM_READ, UC_MEM_WRITE

eh = flare_emu.EmuHelper()
func_start_addr = 0


addr_check_start = 0
addr_check_end = 0

# 补丁信息，只支持1byte，地址+数据
final_patch_one_byte: [(int, int)] = []
final_patch_many_bytes: [(int, bytes)] = []

def mem_check_hook(uc, access, address, size, value, userData):
    """
    目标是找出地址写，用于模拟的解密字符串
    """
    global addr_check_start
    global addr_check_end
    if access not in [UC_MEM_WRITE]:
        return
    if address > addr_check_end or address < addr_check_start:
        return

    real_value: int = value & ((2 ** (size * 8)) - 1)
    eh = userData["EmuHelper"]
    pc = eh.getRegVal("pc")

    # fixme 当前只考虑了 size：1 2 4 8 的情况；对于更长的，考虑到字节需要补充只打印修改命令，不直接patch
    if size == 1:
        check_charactor = chr(real_value)
        print(f"[OK] pc={hex(pc)} {hex(address)} :{hex(size)} -> {hex(real_value)} -> {real_value.to_bytes(size, 'little')}", )
        final_patch_one_byte.append((address, ord(check_charactor)))

    elif size == 2 or size == 4 or size == 8:
        print(f"[OK] pc={hex(pc)} {hex(address)} :{hex(size)} -> {hex(real_value)} -> {real_value.to_bytes(size, 'little')}", )
        final_patch_many_bytes.append((address, real_value.to_bytes(size, 'little')))

    else:
        print(f"[DEBUG] too long!! {hex(address)} :{hex(size)} -> {hex(real_value)} -> {real_value.to_bytes(size, 'little')}", )


def go():
    global func_start_addr
    end_address = 0
    if func_start_addr == 0:
        do_func = idaapi.get_screen_ea()
        end_address = do_func
        do_func = idaapi.get_func(do_func)
        print(f"target function={hex(do_func.start_ea)}")
        func_start_addr = do_func.start_ea

    print(f"enum range: {hex(func_start_addr)} -> {hex(end_address)}")


    # 获得目标data段的地址范围,用于记录
    global addr_check_start
    global addr_check_end
    data_segment = ida_segment.get_segm_by_name("__data")
    addr_check_start = data_segment.start_ea
    addr_check_end = data_segment.end_ea
    assert addr_check_end != 0
    assert addr_check_start != 0
    head_env = eh.emulateRange(func_start_addr, endAddr=end_address , skipCalls=True, memAccessHook=mem_check_hook)

    for one in final_patch_one_byte:
        ida_bytes.patch_byte(one[0], one[1])

    for one in final_patch_many_bytes:
        ida_bytes.patch_bytes(one[0], one[1])

if __name__ == '__main__':
    go()
