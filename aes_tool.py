"""AES 加解密工具 —— 图形界面。

加密逻辑都在 crypto_core.py，这里只负责取数据、显示结果。

函数：
    do_encrypt()    加密按钮的处理函数
    do_decrypt()    解密按钮的处理函数
"""

from tkinter import *
from crypto_core import encrypt, decrypt


def do_encrypt():
    """读取输入框内容，加密后显示到结果框。

    函数名带 do_ 前缀是为了不和导入的 crypto_core.encrypt 重名。
    同名的话后者会覆盖前者，这种 bug 不报错，只是行为不对。
    """
    # Text 控件读出来的内容末尾永远带一个换行，所以 strip() 掉
    plain_text = text_input.get("1.0", END).strip()
    password = key_input.get()

    # 不捕获异常的话，出错会让窗口报错甚至卡死
    try:
        result_text = encrypt(plain_text, password)
    except ValueError as e:
        result_text = f"错误：{e}"          # 预料到的错误（输入为空等）
    except Exception as e:
        result_text = f"未知错误：{e}"       # 兜底，防止意外崩溃

    result.delete("1.0", END)
    result.insert(END, result_text)


def do_decrypt():
    """读取输入框内容，解密后显示到结果框。

    结构和 do_encrypt 对称，只是错误提示改成"解密失败"，
    因为解密失败的原因通常是密码错误，和加密失败的情况不同。
    """
    cipher_text = text_input.get("1.0", END).strip()
    password = key_input.get()

    try:
        result_text = decrypt(cipher_text, password)
    except ValueError as e:
        result_text = f"解密失败：{e}"
    except Exception as e:
        result_text = f"未知错误：{e}"

    result.delete("1.0", END)
    result.insert(END, result_text)


# 以下是界面搭建代码，程序启动时从上往下依次执行

window = Tk()
window.title("AES 密钥加密解密工具")

Label(window, text="请输入文本:").pack()
text_input = Text(window, height=5, width=50)
text_input.pack()

Label(window, text="请输入密码:").pack()
# show="*" 让密码显示成星号。调试时可临时删掉，看清输入内容
key_input = Entry(window, show="*")
key_input.pack()

# command= 后面写函数名，不要加括号：加括号会立刻执行，而不是等点击
Button(window, text="加密", command=do_encrypt).pack()
Button(window, text="解密", command=do_decrypt).pack()

Label(window, text="结果:").pack()
result = Text(window, height=5, width=50)
result.pack()

# 进入事件循环，等待并响应鼠标键盘操作
window.mainloop()
