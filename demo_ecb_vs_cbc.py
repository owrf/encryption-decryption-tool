"""演示 ECB 模式为什么会泄漏信息，而 CBC 模式不会。

运行方式：
    python demo_ecb_vs_cbc.py

这个脚本不涉及界面，也不做 base64 编码，直接把原始字节按 16 字节一块打印
成十六进制，好用眼睛直接看出规律。
"""

import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

BLOCK = 16


def show_blocks(label, data):
    """把 data 按 16 字节一块打印成十六进制，并标出重复的块。"""
    print(f"  {label}")
    blocks = [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]
    for index, block in enumerate(blocks):
        hexed = block.hex()
        # 如果这个块的内容之前出现过，就标记出来
        is_first_occurrence = blocks.index(block) == index
        mark = "" if is_first_occurrence else "   <-- 和前面的块完全相同"
        print(f"    第 {index} 块: {hexed}{mark}")
    print()


# "AAAA...AAAA" 是 4 个完全相同的 16 字节块（每块 16 个字母 A）
plaintext = ("A" * 64).encode("utf-8")
key = b"0123456789abcdef"          # 正好 16 字节，AES 可以直接接受

print()
print("=" * 70)
print("明文是 64 个相同的字节：'A' * 64")
print("=" * 70)
print()
print("  明文")
for i in range(4):
    print(f"    第 {i} 块: {('A' * 16).encode().hex()}")
print()

padded = pad(plaintext, BLOCK)

print("=" * 70)
print("ECB 模式")
print("=" * 70)
ecb_cipher = AES.new(key, AES.MODE_ECB)
ecb_out = ecb_cipher.encrypt(padded)
show_blocks("密文:", ecb_out)

print("=" * 70)
print("CBC 模式（随机 IV）")
print("=" * 70)
iv = os.urandom(BLOCK)
cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
cbc_out = cbc_cipher.encrypt(padded)
print(f"  IV      : {iv.hex()}")
print()
show_blocks("密文:", cbc_out)

print("=" * 70)
print("结论")
print("=" * 70)
print("""
  ECB 模式下，4 个相同的明文块产生了 4 个完全相同的密文块。攻击者只看密文
  就能判断出"明文里有重复内容"——他既不需要密钥，也没有解密任何东西。

  CBC 模式下，每一块在加密前都先和前一块的密文做了异或，所以 4 个相同的
  明文块产生了 4 个不同的密文块，重复的规律完全看不出来。

  这就是 crypto_core.py 使用 MODE_CBC 而不是 MODE_ECB 的原因。
""")
