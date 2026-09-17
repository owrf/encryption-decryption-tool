"""AES 加解密核心逻辑。

这个模块里故意不包含任何界面代码。把加密逻辑和图形界面分开，是为了让逻辑
能被导入、被复用、被自动化测试。aes_tool.py 只是一个薄薄的外壳。

本文件定义的函数：
    derive_key(password, salt)      把任意长度的密码拉伸成 32 字节 AES 密钥
    encrypt(plaintext, password)    加密，返回 base64 文本
    decrypt(blob_b64, password)     解密，返回原文

设计说明
--------
为什么不用 ECB 模式？
    ECB 把数据切成 16 字节一块，每块独立加密。所以相同的明文块永远产生相同的
    密文块，这会泄漏明文的结构。本模块使用 CBC 模式：每一块在加密前先和前一块
    的密文做异或运算，因此相同的明文块会产生不同的密文块。

为什么要用 PBKDF2？
    AES 只接受 16、24 或 32 字节的密钥，而用户密码长度是任意的。PBKDF2 把密码
    "拉伸"成合法长度的密钥，同时它的高迭代次数让暴力破解密码变得非常昂贵。

为什么要把 salt 和 IV 存进密文？
    解密时这两个值都需要，而它们本身都不是秘密。每次加密都会重新随机生成，
    然后拼在密文前面，这样解密方就能取回来。拼接格式：

        [ 16 字节 salt ][ 16 字节 IV ][ 密文 ... ]

    整体再经过 base64 编码，方便当作文本传输。

安全限制
--------
CBC 加上 PKCS#7 填充提供的是机密性，但不提供完整性：能够修改密文的攻击者可能
被填充校验挡住，但无法从根本上阻止篡改。生产环境应该使用 AEAD 模式（例如
AES-GCM），它能同时验证密文有没有被改动。

本模块是教学实现，不要直接用于生产环境。
"""

import base64
import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# 参数。注意：修改 ITERATIONS 只影响以后新加密的数据。迭代次数并没有被存进
# 密文里，所以加密方和解密方必须使用同一个值，否则解不开。
SALT_SIZE = 16         # 盐的长度（字节）
IV_SIZE = 16           # 初始化向量的长度，必须等于 AES 块大小
KEY_SIZE = 32          # 32 字节 = AES-256
ITERATIONS = 600_000   # OWASP 对 PBKDF2-HMAC-SHA256 建议的迭代量级
BLOCK_SIZE = AES.block_size    # AES 的块大小，固定是 16

# 密文最短长度：至少要有 salt + IV + 一个完整的密文块
MIN_BLOB_SIZE = SALT_SIZE + IV_SIZE + BLOCK_SIZE


def derive_key(password: str, salt: bytes) -> bytes:
    """把任意长度的密码拉伸成 32 字节的 AES 密钥。

    参数：
        password (str)  : 用户输入的密码，长度不限
        salt     (bytes): 16 字节的随机盐。加了它以后，相同密码在不同次加密中
                          会得到不同密钥，防止攻击者预先算好一张对照表

    返回：
        bytes，正好 32 字节的密钥

    怎么实现的：
        调用 PBKDF2，把"密码 + 盐"反复做 60 万次 SHA-256 哈希。60 万次是为了
        让计算变慢——合法用户只算一次感觉不到（约 0.25 秒），但攻击者要猜测
        几亿个密码就会变得极其昂贵。

    关键性质：
        确定性。同样的密码 + 同样的盐，永远得到同样的密钥。正是这一点让解密方
        能重新算出同一个密钥。
    """
    return PBKDF2(
        password,
        salt,
        dkLen=KEY_SIZE,
        count=ITERATIONS,
        hmac_hash_module=SHA256,
    )


def encrypt(plaintext: str, password: str) -> str:
    """加密一段文本。

    参数：
        plaintext (str): 要加密的内容
        password  (str): 用户设置的密码

    返回：
        str，base64 编码后的结果，里面包含 salt、IV 和密文三部分

    抛出：
        ValueError：明文或密码为空时

    怎么实现的：
        1. 生成 16 字节随机 salt 和 16 字节随机 IV
        2. 用 derive_key 把密码 + salt 变成 32 字节密钥
        3. 创建 AES 对象，指定 CBC 模式，并把 IV 传进去
        4. 给明文填充，让长度变成 16 的整数倍（AES 只能处理整块）
        5. 执行加密，得到密文字节
        6. 把 salt + IV + 密文拼成一串，再 base64 编码成文本返回

    为什么要拼 salt 和 IV：
        解密时必须知道这次用的是哪个 salt 和哪个 IV，否则算不出正确的密钥、
        也解不开第一个块。它们不保密，但必须传给解密方。
    """
    if not plaintext:
        raise ValueError("明文不能为空")
    if not password:
        raise ValueError("密码不能为空")

    # 每次加密都重新生成随机的盐和 IV，这是"相同明文产生不同密文"的关键
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)

    key = derive_key(password, salt)

    # 创建 AES 对象：指定 CBC 模式，并把 IV 传进去
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # 明文必须先填充到块大小的整数倍，CBC 才能处理
    padded = pad(plaintext.encode("utf-8"), BLOCK_SIZE)

    # 执行加密
    ciphertext = cipher.encrypt(padded)

    # 把三部分拼起来再 base64 编码
    return base64.b64encode(salt + iv + ciphertext).decode("ascii")


def decrypt(blob_b64: str, password: str) -> str:
    """解密一段文本，是 encrypt 的逆操作。

    参数：
        blob_b64 (str): encrypt 返回的那段 base64 文本
        password (str): 加密时用的同一个密码

    返回：
        str，原来的明文

    抛出：
        ValueError：输入为空、不是合法 base64、长度不足，或者密码错误 /
                    密文被修改过

    怎么实现的：
        1. 检查输入非空
        2. base64 解码，变回字节。validate=True 表示严格校验格式
        3. 检查长度够不够（至少要有 salt + IV + 一个块）
        4. 用切片把三部分切开：
               salt       = blob[:16]      前 16 字节
               iv         = blob[16:32]    接下来 16 字节
               ciphertext = blob[32:]      剩下的
        5. 用同一个 salt 算出和加密时一样的密钥
        6. 用同一个 IV 创建 AES 对象
        7. 解密
        8. 去掉填充（unpad）
        9. 把字节解码成 UTF-8 文本返回

    为什么"密码错误"能检测出来：
        密码错 → 密钥错 → 解出来是一堆随机字节 → 它们的末尾几乎不可能构成合法
        的填充格式 → unpad 失败 → 我们捕获它并报错。

        注意：CBC 模式下"密码错误"和"密文被改"产生的结果完全一样，程序无法
        区分，所以错误信息写成"密码错误，或者密文已被修改"。
    """
    if not blob_b64:
        raise ValueError("输入不能为空")
    if not password:
        raise ValueError("密码不能为空")

    # validate=True 要求严格合法的 base64，拒绝夹杂其他字符的输入
    try:
        blob = base64.b64decode(blob_b64, validate=True)
    except Exception as exc:
        raise ValueError("输入不是合法的 base64 内容") from exc

    # 长度不够的话，后面切 salt/IV 就会出错，所以先挡掉
    if len(blob) < MIN_BLOB_SIZE:
        raise ValueError(
            f"密文太短：只有 {len(blob)} 字节，至少需要 {MIN_BLOB_SIZE} 字节"
        )

    # 按约定的格式把三部分切回来
    salt = blob[:SALT_SIZE]                              # 开头 16 字节是盐
    iv = blob[SALT_SIZE:SALT_SIZE + IV_SIZE]             # 接着 16 字节是 IV
    ciphertext = blob[SALT_SIZE + IV_SIZE:]              # 剩下的是密文

    # 用同一个盐，就能算出和加密时完全一样的密钥
    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    try:
        unpadded = unpad(decrypted, BLOCK_SIZE)
    except ValueError as exc:
        raise ValueError("密码错误，或者密文已被修改") from exc

    try:
        return unpadded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("解密后的字节不是合法的 UTF-8 文本") from exc


# 下面这段只在直接运行本文件时执行（python crypto_core.py）。
# 被 aes_tool.py 导入时不执行，否则每次启动界面都会往控制台打印自检信息。
if __name__ == "__main__":
    message = "这是一段测试文本 / hello world"
    secret = "my password"

    encrypted = encrypt(message, secret)
    print("密文  :", encrypted)
    print("长度  :", len(encrypted), "个字符")

    recovered = decrypt(encrypted, secret)
    print("解密后:", recovered)
    print("往返  :", "成功" if recovered == message else "失败")
