import flare_emu
import idc
import idaapi
import keypatch

"""
用于花指令修复的快速脚本
注意：
- 只对arm64进行过测试
- 无法适用于修改LR返回值的场景
"""
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


"""
花指令修复-1
"""
br_addr = None
start_addr = None


def cat_cat0() -> int:
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
    func_start_addr = start_addr
    if not func_start_addr:
        func_start_addr = idaapi.get_func(br_addr).start_ea

    # 执行模拟
    eh = flare_emu.EmuHelper()
    # 传入待选参数 endAddr，和第一个参数共同标识一段地址区间
    eh.emulateRange(func_start_addr, endAddr=br_addr, skipCalls=True)
    ret = eh.getRegVal(register_name)
    # 提取字符串

    if ret > 0x1000:
        print(f"final = {hex(ret)}")
        patch_one(br_addr, f"b {hex(ret)}")
    else:
        print(f"[error] final = {hex(ret)}")

    return func_start_addr


if __name__ == "__main__":
    address = cat_cat0()
