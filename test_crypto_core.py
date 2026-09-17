"""crypto_core.py 的测试。

运行方式：
    python test_crypto_core.py

这个文件没有用 pytest 框架，而是自己实现了一个极简的测试计数器。目的是
让你能看清楚"测试"到底是什么：就是拿一个断言去检查程序的行为对不对。
"""

import base64 as b64
import sys

from crypto_core import (
    BLOCK_SIZE,
    IV_SIZE,
    SALT_SIZE,
    decrypt,
    derive_key,
    encrypt,
)

PASSWORD = "correct horse battery staple"

# 全局计数器，最后汇总
passed = 0
failed = 0


def check(name, condition, detail=""):
    """检查 condition 是否为真，并记录结果。"""
    global passed, failed
    if condition:
        passed += 1
        print(f"  通过  {name}")
    else:
        failed += 1
        print(f"  失败  {name}   {detail}")


def expect_error(name, fn, needle):
    """断言 fn() 会抛出 ValueError，并且错误信息里包含 needle。

    这个函数检查的是"程序该报错的时候有没有报错"。很多 bug 不是崩溃，
    而是该拦截的时候放过去了。
    """
    global passed, failed
    try:
        fn()
    except ValueError as exc:
        if needle.lower() in str(exc).lower():
            passed += 1
            print(f"  通过  {name}")
        else:
            failed += 1
            print(f"  失败  {name}   错误信息是：{exc}")
    except Exception as exc:
        failed += 1
        print(f"  失败  {name}   抛出了错误的异常类型：{type(exc).__name__}: {exc}")
    else:
        failed += 1
        print(f"  失败  {name}   没有抛出任何异常")


print()
print("1. 基础往返：加密再解密应该拿回原文")
msg = "hello world"
blob = encrypt(msg, PASSWORD)
check("decrypt(encrypt(m)) == m", decrypt(blob, PASSWORD) == msg)

print()
print("2. 中文、标点、换行、超长文本都能原样往返")
for sample in ["中文测试", "emoji 🔐 也可以", "line1\nline2\ttabbed", "a" * 5000, "  spaces  "]:
    blob = encrypt(sample, PASSWORD)
    check(f"往返：{sample[:20]!r}", decrypt(blob, PASSWORD) == sample)

print()
print("3. CBC 的核心特性：相同输入每次加密结果都不同")
blobs = {encrypt(msg, PASSWORD) for _ in range(5)}
check("连续加密 5 次得到 5 个不同结果", len(blobs) == 5, f"实际得到 {len(blobs)} 个不同结果")
check("它们全都能正确解密", all(decrypt(b, PASSWORD) == msg for b in blobs))

print()
print("4. 密码错误必须被明确拒绝，不能静默解出乱码")
expect_error("密码错误时抛出 ValueError", lambda: decrypt(blob, "wrong password"), "密码错误")

print()
print("5. 密文被篡改必须能被发现")
good = encrypt(msg, PASSWORD)
raw = bytearray(b64.b64decode(good))
raw[SALT_SIZE + IV_SIZE + 2] ^= 0x01          # 翻转密文里的一个二进制位
tampered = b64.b64encode(bytes(raw)).decode("ascii")
expect_error("翻转一个二进制位后被拒绝", lambda: decrypt(tampered, PASSWORD), "修改")

print()
print("6. 各种非法输入都要给出清晰的错误提示")
expect_error("空输入", lambda: decrypt("", PASSWORD), "空")
expect_error("不是 base64", lambda: decrypt("!!!not base64!!!", PASSWORD), "base64")
expect_error("长度不足", lambda: decrypt(b64.b64encode(b"x" * 20).decode(), PASSWORD), "太短")
expect_error("明文为空", lambda: encrypt("", PASSWORD), "明文")
expect_error("密码为空", lambda: encrypt(msg, ""), "密码")

print()
print("7. 密钥派生：确定性 + 依赖盐")
salt_a = b"A" * SALT_SIZE
salt_b = b"B" * SALT_SIZE
check("相同密码 + 相同盐 → 相同密钥", derive_key(PASSWORD, salt_a) == derive_key(PASSWORD, salt_a))
check("相同密码 + 不同盐 → 不同密钥", derive_key(PASSWORD, salt_a) != derive_key(PASSWORD, salt_b))
check("密钥正好 32 字节（AES-256）", len(derive_key(PASSWORD, salt_a)) == 32)

print()
print("8. 密文布局确实是 salt + IV + 密文")
raw = b64.b64decode(encrypt("x" * BLOCK_SIZE, PASSWORD))
check("去掉 salt 和 IV 后，剩余长度是块大小的整数倍",
      (len(raw) - SALT_SIZE - IV_SIZE) % BLOCK_SIZE == 0,
      f"实际总长 {len(raw)} 字节")

print()
print("-" * 50)
print(f"通过：{passed}   失败：{failed}")
print("-" * 50)
sys.exit(1 if failed else 0)
