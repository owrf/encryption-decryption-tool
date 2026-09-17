# Encryption & Decryption Tool (加解密工具)

一个使用 Tkinter 构建的 Python 图形界面加解密工具。

通过加密逻辑与界面分离来组织代码，加密部分有完整的自动化测试。

## 文件结构

```
├── crypto_core.py          加密核心逻辑（纯逻辑，不含界面）
├── aes_tool.py             AES 图形界面（调用 crypto_core）
├── base64_tool.py          Base64 图形界面
├── test_crypto_core.py     crypto_core 的测试（19 项）
├── demo_ecb_vs_cbc.py      演示 ECB 与 CBC 的安全差异
└── requirements.txt        依赖清单
```

`crypto_core.py` 不依赖任何界面代码，因此可以被单独导入、复用和测试。界面层
只负责取数据、调函数、显示结果。

## 环境依赖

需要 Python 3.10 或更高版本。安装依赖：

```bash
pip install -r requirements.txt
```

## 使用方法

```bash
python aes_tool.py
```

输入要加密的文本和密码，点「加密」得到 base64 密文。把密文粘回输入框、用同一个
密码点「解密」，就能还原原文。

### 在代码中直接调用

```python
from crypto_core import encrypt, decrypt

cipher = encrypt("要加密的内容", "密码")
print(cipher)                        # 一段 base64 密文
print(decrypt(cipher, "密码"))        # 要加密的内容
```

## 加密设计

| 项目 | 选择 | 原因 |
|---|---|---|
| 加密算法 | AES-256 | 业界标准对称加密算法 |
| 工作模式 | **CBC** | ECB 会让相同的明文块产生相同的密文块，泄漏明文结构 |
| 密钥派生 | **PBKDF2-HMAC-SHA256**，600,000 轮 | AES 只接受 16/24/32 字节密钥，PBKDF2 把任意长度密码拉伸成密钥；高迭代次数让暴力破解变得昂贵 |
| 随机盐 | 每次加密生成 16 字节 | 相同密码产生不同密钥，防止预计算攻击 |
| 初始化向量 | 每次加密生成 16 字节随机值 | 保证相同明文每次加密结果不同 |

密文格式为 base64 编码的 `salt (16 字节) + IV (16 字节) + 密文`。盐和 IV 都不是
秘密，但解密时必须知道它们，因此随密文一起保存。

### 为什么不用 ECB

运行 `python demo_ecb_vs_cbc.py` 可以直接看到差异：ECB 模式下 4 个相同的明文块会
产生 4 个完全相同的密文块，攻击者仅凭密文就能判断明文存在重复；CBC 模式下则完全
看不出规律。

## 运行测试

```bash
python test_crypto_core.py
```

19 项测试覆盖往返正确性、中文与 emoji、相同明文产生不同密文、错误密码拒绝、
密文篡改检测、非法输入处理、密钥派生的确定性。

## 已知限制

- **CBC 不提供完整性保护。** 错误密码和密文被篡改会产生相同的报错，程序无法区分。
  生产环境应使用 AEAD 模式（如 AES-GCM），它能验证密文是否被改动。
- **界面读取输入时使用了 `strip()`**，会去掉内容首尾的空格和换行。如果需要加密
  首尾带空格的内容，应改用 `text_input.get("1.0", "end-1c")`。
- 本项目是教学实现，请勿直接用于保护真实敏感数据。
