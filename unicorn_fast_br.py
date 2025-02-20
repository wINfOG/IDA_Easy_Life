import idc
import idaapi
import ida_bytes
import idautils
import ida_ua
import ida_funcs
import ida_segment
import keypatch

from unicorn import UC_MEM_READ, UC_MEM_WRITE
from unicorn import *
from unicorn.arm64_const import *

func_start_addr = 0

reg_names = {
    "X0": unicorn.arm64_const.UC_ARM64_REG_X0,
    "X1": unicorn.arm64_const.UC_ARM64_REG_X1,
    "X2": unicorn.arm64_const.UC_ARM64_REG_X2,
    "X3": unicorn.arm64_const.UC_ARM64_REG_X3,
    "X4": unicorn.arm64_const.UC_ARM64_REG_X4,
    "X5": unicorn.arm64_const.UC_ARM64_REG_X5,
    "X6": unicorn.arm64_const.UC_ARM64_REG_X6,
    "X7": unicorn.arm64_const.UC_ARM64_REG_X7,
    "X8": unicorn.arm64_const.UC_ARM64_REG_X8,
    "X9": unicorn.arm64_const.UC_ARM64_REG_X9,
    "X10": unicorn.arm64_const.UC_ARM64_REG_X10,
    "X11": unicorn.arm64_const.UC_ARM64_REG_X11,
    "X12": unicorn.arm64_const.UC_ARM64_REG_X12,
    "X13": unicorn.arm64_const.UC_ARM64_REG_X13,
    "X14": unicorn.arm64_const.UC_ARM64_REG_X14,
    "X15": unicorn.arm64_const.UC_ARM64_REG_X15,
    "X16": unicorn.arm64_const.UC_ARM64_REG_X16,
    "X17": unicorn.arm64_const.UC_ARM64_REG_X17,
    "X18": unicorn.arm64_const.UC_ARM64_REG_X18,
    "X19": unicorn.arm64_const.UC_ARM64_REG_X19,
    "X20": unicorn.arm64_const.UC_ARM64_REG_X20,
    "X21": unicorn.arm64_const.UC_ARM64_REG_X21,
    "X22": unicorn.arm64_const.UC_ARM64_REG_X22,
    "X23": unicorn.arm64_const.UC_ARM64_REG_X23,
    "X24": unicorn.arm64_const.UC_ARM64_REG_X24,
    "X25": unicorn.arm64_const.UC_ARM64_REG_X25,
    "X26": unicorn.arm64_const.UC_ARM64_REG_X26,
    "X27": unicorn.arm64_const.UC_ARM64_REG_X27,
    "X28": unicorn.arm64_const.UC_ARM64_REG_X28,
    "W0": unicorn.arm64_const.UC_ARM64_REG_W0,
    "W1": unicorn.arm64_const.UC_ARM64_REG_W1,
    "W2": unicorn.arm64_const.UC_ARM64_REG_W2,
    "W3": unicorn.arm64_const.UC_ARM64_REG_W3,
    "W4": unicorn.arm64_const.UC_ARM64_REG_W4,
    "W5": unicorn.arm64_const.UC_ARM64_REG_W5,
    "W6": unicorn.arm64_const.UC_ARM64_REG_W6,
    "W7": unicorn.arm64_const.UC_ARM64_REG_W7,
    "W8": unicorn.arm64_const.UC_ARM64_REG_W8,
    "W9": unicorn.arm64_const.UC_ARM64_REG_W9,
    "W10": unicorn.arm64_const.UC_ARM64_REG_W10,
    "W11": unicorn.arm64_const.UC_ARM64_REG_W11,
    "W12": unicorn.arm64_const.UC_ARM64_REG_W12,
    "W13": unicorn.arm64_const.UC_ARM64_REG_W13,
    "W14": unicorn.arm64_const.UC_ARM64_REG_W14,
    "W15": unicorn.arm64_const.UC_ARM64_REG_W15,
    "W16": unicorn.arm64_const.UC_ARM64_REG_W16,
    "W17": unicorn.arm64_const.UC_ARM64_REG_W17,
    "W18": unicorn.arm64_const.UC_ARM64_REG_W18,
    "W19": unicorn.arm64_const.UC_ARM64_REG_W19,
    "W20": unicorn.arm64_const.UC_ARM64_REG_W20,
    "W21": unicorn.arm64_const.UC_ARM64_REG_W21,
    "W22": unicorn.arm64_const.UC_ARM64_REG_W22,
    "W23": unicorn.arm64_const.UC_ARM64_REG_W23,
    "W24": unicorn.arm64_const.UC_ARM64_REG_W24,
    "W25": unicorn.arm64_const.UC_ARM64_REG_W25,
    "W26": unicorn.arm64_const.UC_ARM64_REG_W26,
    "W27": unicorn.arm64_const.UC_ARM64_REG_W27,
    "W28": unicorn.arm64_const.UC_ARM64_REG_W28,
    "SP": unicorn.arm64_const.UC_ARM64_REG_SP,
}

def patch_one(address: int, new_instruction: str):
    kp_asm = keypatch.Keypatch_Asm()
    if kp_asm.arch is None:
        print("ERROR: Keypatch cannot handle this architecture")
        return False

    assembly = kp_asm.ida_resolve(new_instruction, address)
    (encoding, count) = kp_asm.assemble(assembly, address)

    if encoding is None:
        print("Keypatch: no need to patch, ")
        return False

    # 这里没有处理指令的长度问题，只在arm下能用
    patch_data = ''.join(chr(c) for c in encoding)
    patch_len = len(patch_data)
    kp_asm.patch(address, patch_data, patch_len)

    print(f"patch !! {assembly}")


def mmap_segments(emu, seg_name):
    data_segment = ida_segment.get_segm_by_name(seg_name)
    data_segment_start = data_segment.start_ea
    data_segment_end = data_segment.end_ea
    emu.mem_map(data_segment_start // 0x1000 * 0x1000, ((data_segment_end - data_segment_start) // 0x1000 + 2) * 0x1000)

    data = ida_bytes.get_bytes(data_segment_start, data_segment_end - data_segment_start)
    emu.mem_write(data_segment_start, data)
    return emu

def init_unicorn_from_function(func_start: int, func_end: int):
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    address = 0
    print("func_start=", hex(func_start))
    print("func_end=", hex(func_end))
    print("func_mmap=", hex(func_start // 0x1000 * 0x1000))
    print("func_mmap=", hex(((func_end - func_start) // 0x1000 + 1) * 0x1000))
    mu.mem_map(
        func_start // 0x1000 * 0x1000, ((func_end - func_start) // 0x1000 + 2) * 0x1000
    )

    stack = 0x1000
    mu.mem_map(stack, 0x4000)
    # 花指令可能需要向后取数据，因此多mmap一些
    data = ida_bytes.get_bytes(func_start, func_end - func_start + 0x100)
    print(hex(func_start))
    print(len(data))
    mu.mem_write(func_start, data)

    mu.reg_write(UC_ARM64_REG_SP, stack + 0x500)
    return mu

"""
花指令修复-2
"""
br_addr = None

def hook_mem_invalid(uc, access, address, size, value, user_data):
    print(f"hook_mem pc={hex(uc.reg_read(UC_ARM64_REG_PC))}")

    print(
        "! <M>  Missing memory at 0x%x, data size = %u, data value = 0x%x"
        % (address, size, value)
    )
    uc.mem_map(address // 0x1000 * 0x1000, 0x1000)
    print(f"mem_map {hex(address // 0x1000 * 0x1000)}")
    data = ida_bytes.get_bytes(address // 0x1000 * 0x1000, 0x1000)
    if data:
        uc.mem_write(address // 0x1000 * 0x1000, data)
    return True

def go():

    global br_addr
    if not br_addr:
        # Get the current screen EA
        br_addr = idaapi.get_screen_ea()
    check_br: str = idc.GetDisasm(br_addr)
    if "BR      " not in check_br:
        print(f"not a br_address at {hex(br_addr)}={check_br}")
        return 0
    register_name = check_br.split(" ")[-1]
    print(f"reg = {register_name}")

    global func_start_addr
    end_address = 0
    if func_start_addr == 0:
        do_func = idaapi.get_screen_ea()
        end_address = do_func
        do_func = idaapi.get_func(do_func)
        print(f"target function={hex(do_func.start_ea)}")
        func_start_addr = do_func.start_ea

    print(f"enum range: {hex(func_start_addr)} -> {hex(end_address)}")


    unicorn_emu = init_unicorn_from_function(func_start_addr, do_func.end_ea)
    
    #
    unicorn_emu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)

    unicorn_emu.emu_start(func_start_addr, end_address)
    ret = unicorn_emu.reg_read(reg_names[register_name])

    if ret > 0x1000:
        print(f"final = {hex(ret)}")
        patch_one(br_addr, f"b {hex(ret)}")
    else:
        print(f"[error] final = {hex(ret)}")

if __name__ == '__main__':
    go()
