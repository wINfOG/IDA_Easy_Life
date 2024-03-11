import idc
import idaapi
import idautils
import ida_allins
import ida_ua
import ida_idp
import ida_idaapi

"""
尝试修复ios中不完整函数，当前模板
只实现了没啥用的_objc_release
todo：适配更多的函数
todo：尝试解决多个返回值的问题
todo：尝试解决部分参数通过栈传递的问题
"""

def fix_objc_release(function_ea: int):
    func = idaapi.get_func(function_ea)
    if not func:
        print(f"[Error] Address:{hex(function_ea)} not a valid function")
        return

    instruction_count = 0
    func_inst: [ida_ua.insn_t] = []
    for item_ea in idautils.FuncItems(func.start_ea):
        instruction_count += 1
        func_inst.append(idautils.DecodeInstruction(item_ea))
        if instruction_count > 2:
            return

    # 严格校验
    if instruction_count != 2:
        return
    # https://raw.githubusercontent.com/AdamTaguirov/IDA-practical-cheatsheet/main/IDA_Python_supported_instructions.txt
    if func_inst[1].itype != ida_allins.ARM_b or func_inst[0].itype != ida_allins.ARM_mov:
        return
    reg_left = func_inst[0].Op1.reg
    reg_right = func_inst[0].Op2.reg
    if reg_right == 0 or reg_left != ida_idp.str2reg("X0"):
        return

    reg_right_name = ida_idp.get_reg_name(reg_right, 8)
    # 组装最后需要的内容
    new_func_set_name: str = f"objc_release_{reg_right_name}"
    new_func_set_type: str = f"void __usercall {new_func_set_name}(id {reg_right_name}@<{reg_right_name}>)"
    print(f"[Info] objc_release fix address={hex(func.start_ea)} new_func={new_func_set_type}")

    idaapi.set_name(func.start_ea, new_func_set_name, idaapi.SN_FORCE)
    idc.SetType(func.start_ea, new_func_set_type)



def go():
    # 只支持arm64
    file_type = idaapi.get_file_type_name()
    if "ARM64" not in str(file_type):
        print(f"[Error] ARM64 only !!! not {file_type}")
        return

    objc_release_ea: int = idc.get_name_ea_simple("_objc_release")
    if ida_idaapi.BADADDR == objc_release_ea:
        return

    print(f"[Info] objc_release address: {hex(objc_release_ea)}")
    for i in idautils.CodeRefsTo(objc_release_ea, 0):
        if idautils.DecodeInstruction(i).itype != ida_allins.ARM_b:
            continue
        fix_objc_release(i)

if __name__ == '__main__':
    go()
