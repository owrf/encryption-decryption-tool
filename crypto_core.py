"""AES 加解密核心逻辑（纯逻辑，不含界面）。

函数：
    derive_key(password, salt)      把任意长度密码拉伸成 32 字节 AES 密钥
    encrypt(plaintext, password)    加密，返回 base64 文本
    decrypt(blob_b64, password)     解密，返回原文

设计要点：
    - 用 CBC 而不是 ECB：ECB 下相同明文块会产生相同密文块，泄漏明文结构
    - 用 PBKDF2 派生密钥：AES 只接受 16/24/32 字节密钥，用户密码长度任意
    - 每次加密随机生成 salt 和 IV，随密文一起保存
    - 密文格式：base64(salt[16] + iv[16] + ciphertext)

已知限制：
    CBC 只保证机密性，不保证完整性。密码错误和密文被篡改无法区分，
    所以报错信息是"密码错误，或者密文已被修改"。生产环境应改用 AES-GCM。
"""

import base64
import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

SALT_SIZE = 16         # 盐长度
IV_SIZE = 16           # 初始化向量长度，必须等于 AES 块大小
KEY_SIZE = 32          # 32 字节 = AES-256
ITERATIONS = 600_000   # PBKDF2 迭代次数。注意它不存进密文，
                       # 改动后旧密文就解不开了
BLOCK_SIZE = AES.block_size    # 固定 16

# 密文最短长度 = salt + IV + 一个完整密文块
MIN_BLOB_SIZE = SALT_SIZE + IV_SIZE + BLOCK_SIZE


def derive_key(password: str, salt: bytes) -> bytes:
    """把任意长度的密码拉伸成 32 字节 AES 密钥。

    PBKDF2 反复做 60 万次 SHA-256 哈希。这个数字大是为了让暴力破解昂贵：
    合法用户只算一次（约 0.25 秒）感觉不到，攻击者要猜几亿次就不可行。

    确定性：相同密码 + 相同盐 → 相同密钥。解密方靠这一点重新算出密钥。
    """
    return PBKDF2(
        password,
        salt,
        dkLen=KEY_SIZE,
        count=ITERATIONS,
        hmac_hash_module=SHA256,
    )


def encrypt(plaintext: str, password: str) -> str:
    """加密，返回 base64 密文（内含 salt、IV 和密文）。

    抛出 ValueError：明文或密码为空。
    """
    if not plaintext:
        raise ValueError("明文不能为空")
    if not password:
        raise ValueError("密码不能为空")

    # 每次加密都重新随机生成，这是"相同明文产生不同密文"的关键
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # 明文必须先填充到块大小整数倍，AES 才能处理
    padded = pad(plaintext.encode("utf-8"), BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded)

    # 把 salt 和 IV 存在密文前面，否则解密方算不出密钥、也解不开第一块
    return base64.b64encode(salt + iv + ciphertext).decode("ascii")


def decrypt(blob_b64: str, password: str) -> str:
    """解密 encrypt 的返回值。

    抛出 ValueError：输入为空、不是合法 base64、长度不足，
    或者密码错误 / 密文被修改。
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

    if len(blob) < MIN_BLOB_SIZE:
        raise ValueError(
            f"密文太短：只有 {len(blob)} 字节，至少需要 {MIN_BLOB_SIZE} 字节"
        )

    # 按约定切开三部分
    salt = blob[:SALT_SIZE]
    iv = blob[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = blob[SALT_SIZE + IV_SIZE:]

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    try:
        unpadded = unpad(decrypted, BLOCK_SIZE)
    except ValueError as exc:
        # 密码错时解出来是随机字节，末尾几乎不可能构成合法填充，
        # 所以"密码错误"这个结论是从填充校验失败反推出来的
        raise ValueError("密码错误，或者密文已被修改") from exc

    try:
        return unpadded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("解密后的字节不是合法的 UTF-8 文本") from exc


# 只在直接运行本文件时执行自检。被 aes_tool.py 导入时不执行。
if __name__ == "__main__":
    message = "这是一段测试文本 / hello world"
    secret = "my password"

    encrypted = encrypt(message, secret)
    print("密文  :", encrypted)
    print("长度  :", len(encrypted), "个字符")

    recovered = decrypt(encrypted, secret)
    print("解密后:", recovered)
    print("往返  :", "成功" if recovered == message else "失败")
