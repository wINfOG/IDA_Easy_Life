import idc
import idaapi
import ida_bytes
import idautils
import ida_ua
import ida_funcs
import ida_segment

from unicorn import UC_MEM_READ, UC_MEM_WRITE
from unicorn import *
from unicorn.arm64_const import *

func_start_addr = 0
addr_check_start = 0
addr_check_end = 0

# 补丁信息
final_patch_one_byte: [(int, int)] = []
final_patch_many_bytes: [(int, bytes)] = []


def mmap_segments(emu, seg_name):
    data_segment = ida_segment.get_segm_by_name(seg_name)
    data_segment_start = data_segment.start_ea
    data_segment_end = data_segment.end_ea
    emu.mem_map(data_segment_start // 0x1000 * 0x1000, ((data_segment_end - data_segment_start) // 0x1000 + 2) * 0x1000)

    data = ida_bytes.get_bytes(data_segment_start, data_segment_end - data_segment_start)
    emu.mem_write(data_segment_start, data)
    return emu

def init_unicorn_from_function(func_start: int, func_end: int):
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM + UC_MODE_LITTLE_ENDIAN)
    address = 0
    print("func_start=", hex(func_start))
    print("func_end=", hex(func_end))
    print("func_mmap=", hex(func_start // 0x1000 * 0x1000))
    print("func_mmap=", hex(((func_end - func_start) // 0x1000 + 1) * 0x1000))
    mu.mem_map(
        func_start // 0x1000 * 0x1000, ((func_end - func_start) // 0x1000 + 2) * 0x1000
    )

    data_segment = ida_segment.get_segm_by_name("__data")
    data_segment_start = data_segment.start_ea
    data_segment_end = data_segment.end_ea
    mu.mem_map(data_segment_start// 0x1000 * 0x1000, ((data_segment_end - data_segment_start) // 0x1000 + 2) * 0x1000)

    const_segment = ida_segment.get_segm_by_name("__const")
    const_segment_start = const_segment.start_ea
    const_segment_end = const_segment.end_ea
    mu.mem_map(const_segment_start// 0x1000 * 0x1000, ((const_segment_end - const_segment_start) // 0x1000 + 2) * 0x1000)

    bss_segment = ida_segment.get_segm_by_name("__bss")
    bss_segment_start = bss_segment.start_ea
    bss_segment_end = bss_segment.end_ea
    mu.mem_map(bss_segment_start // 0x1000 * 0x1000,
               ((bss_segment_end - bss_segment_start) // 0x1000 + 2) * 0x1000)

    got_segment = ida_segment.get_segm_by_name("__got")
    got_segment_start = got_segment.start_ea
    got_segment_end = got_segment.end_ea
    mu.mem_map(got_segment_start // 0x1000 * 0x1000,
               ((got_segment_end - got_segment_start) // 0x1000 + 2) * 0x1000)


    undef_segment = ida_segment.get_segm_by_name("UNDEF")
    undef_segment_start = undef_segment.start_ea
    undef_segment_end = undef_segment.end_ea
    mu.mem_map(undef_segment_start // 0x1000 * 0x1000,
               ((undef_segment_end - undef_segment_start) // 0x1000 + 2) * 0x1000)



    stack = 0x1000
    mu.mem_map(stack, 0x4000)

    data = ida_bytes.get_bytes(func_start, func_end - func_start)
    print(hex(func_start))
    print(len(data))
    mu.mem_write(func_start, data)

    data = ida_bytes.get_bytes(data_segment_start, data_segment_end - data_segment_start)
    mu.mem_write(data_segment_start, data)

    data = ida_bytes.get_bytes(const_segment_start, const_segment_end - const_segment_start)
    mu.mem_write(const_segment_start, data)

    data = ida_bytes.get_bytes(bss_segment_start, bss_segment_end - bss_segment_start)
    mu.mem_write(bss_segment_start, b'\x00' * len(data))

    data = ida_bytes.get_bytes(got_segment_start, got_segment_end - got_segment_start)
    mu.mem_write(got_segment_start, data)


    data = ida_bytes.get_bytes(undef_segment_start, undef_segment_end - undef_segment_start)
    mu.mem_write(undef_segment_start, data)

    mu = mmap_segments(mu, "__objc_selrefs")

    mu.reg_write(UC_ARM64_REG_SP, stack + 0x500)
    return mu

def hook_mem(uc: unicorn.Uc, access, address, size, value, user_data):
    global mu
    print(f"hook_mem pc={hex(emu.reg_read(UC_ARM64_REG_PC))}")
    print(
        "! <M>  Missing memory at 0x%x, data size = %u, data value = 0x%x"
        % (address, size, value)
    )
    mu.mem_map(address // 0x1000 * 0x1000, 0x1000)
    print(f"mem_map {hex(address // 0x1000 * 0x1000)}")
    print("mem_map")
    data = ida_bytes.get_bytes(address // 0x1000 * 0x1000, 0x1000)
    mu.mem_write(address // 0x1000 * 0x1000, data)
    print("mem_write")
    return True

def read_hook(emu, access, address, size, value, user_data):

    print(f"hook pc={hex(emu.reg_read(UC_ARM64_REG_PC))}")
    if access == UC_MEM_READ:
        print(f"read:{address} {size} {value}")
    else:
        # print(f"write:{hex(address)} {mu.mem_read(address,size)}")
        real_value: int = value & ((2 ** (size * 8)) - 1)
        print(f"{access} write:{hex(address)} {size} {hex(value)}")
        if size <=8:
            print(f"hint = {real_value.to_bytes(size, 'little')}")
            if size == 1:
                final_patch_one_byte.append((address, ord(chr(real_value))))
            else:
                final_patch_many_bytes.append((address, real_value.to_bytes(size, 'little')))
        else:
            print(f"hint = too long..")
        # ida_bytes.patch_bytes(address,value)

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


    unicorn_emu = init_unicorn_from_function(func_start_addr, do_func.end_ea)

    unicorn_emu.hook_add(
        UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
        hook_mem,
    )
    unicorn_emu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, read_hook)
    unicorn_emu.emu_start(func_start_addr, end_address)


    for one in final_patch_one_byte:
        print(f"ida_bytes.patch_byte({hex(one[0])}, {one[1]})")

    for one in final_patch_many_bytes:
        print(f"ida_bytes.patch_bytes({hex(one[0])}, {one[1]})")

if __name__ == '__main__':
    go()
