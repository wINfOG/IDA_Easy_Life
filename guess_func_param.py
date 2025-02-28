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

def guess_call_state_by_unicorn(call_address):
    # 模拟前5条指令能够应对大部分情况
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    start_address = call_address - 0x24
    mu.mem_map(call_address // 0x1000 * 0x1000, 0x2000)
    data = ida_bytes.get_bytes(start_address, 0x24)
    mu.mem_write(start_address, data)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
    mu.emu_start(start_address, call_address)
    return mu
