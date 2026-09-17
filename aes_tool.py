"""AES 加解密工具 —— 图形界面部分。

所有加密逻辑都在 crypto_core.py 里，这个文件只负责界面和错误提示。把逻辑和
界面分开的好处：逻辑能被自动化测试，界面想换就能换。

本文件定义的函数：
    do_encrypt()    读输入框 → 调用加密 → 把结果显示到结果框
    do_decrypt()    读输入框 → 调用解密 → 把结果显示到结果框

关于 tkinter 的一个重要概念
---------------------------
Text 这类控件不是"一个字符串"，而是"一个对象"，要用方法去操作它：

    text_input.get("1.0", END)     读内容
    result.delete("1.0", END)      清空
    result.insert(END, "abc")      写入

"1.0" 表示"第 1 行第 0 列"，是 tkinter 的坐标写法（行号从 1 开始，列号从 0
开始）。END 是常量，表示末尾。

本文件用到的 tkinter 名称：
    Tk()                   创建窗口
    Label(窗口, text=...)  文字标签
    Text(窗口, ...)        多行文本框
    Entry(窗口, show="*")  单行输入框，show="*" 让输入显示成星号
    Button(窗口, text=..., command=...)   按钮
    .pack()                把控件放进窗口并自动排列
    .title()               设置窗口标题
    .mainloop()            启动窗口，开始响应鼠标键盘操作
"""

from tkinter import *
from crypto_core import encrypt, decrypt


def do_encrypt():
    """加密按钮的处理函数。

    什么时候被调用：
        用户点击"加密"按钮时（创建按钮时写了 command=do_encrypt）。

    参数：
        没有。tkinter 点击按钮时不传任何参数。

    返回：
        没有返回值。它的作用是产生副作用——把结果写进界面。

    怎么实现的：
        1. 从 text_input 控件读出用户输入的明文
        2. 从 key_input 控件读出密码
        3. 调用 crypto_core.encrypt() 加密
        4. 如果出错，把错误信息当作要显示的内容（而不是让程序崩溃）
        5. 清空结果框，写入结果

    为什么要 try / except：
        加密可能因为"输入为空"而失败。如果不捕获，异常会冲出函数，在 tkinter
        里表现为窗口报错甚至卡死。捕获后可以友好地提示用户。

        两个 except 的分工：
            except ValueError  —— 处理我们预料到的错误（输入为空）
            except Exception   —— 兜底，处理任何没预料到的错误
        专业的代码都会写这个兜底，因为你不可能预判所有出错情况。

    为什么函数名是 do_encrypt 而不是 encrypt：
        因为文件顶部从 crypto_core 导入了 encrypt。如果这里再定义同名函数，
        就会把导入的那个覆盖掉，调用时行为就乱了。这种 bug 不报错，只是结果
        不对，非常难查。所以界面层的函数统一加 do_ 前缀。
    """
    # Text 控件读出来的内容末尾永远带一个换行符，所以用 strip() 去掉
    plain_text = text_input.get("1.0", END).strip()
    password = key_input.get()

    try:
        result_text = encrypt(plain_text, password)
    except ValueError as e:
        result_text = f"错误：{e}"
    except Exception as e:
        result_text = f"未知错误：{e}"

    result.delete("1.0", END)
    result.insert(END, result_text)


def do_decrypt():
    """解密按钮的处理函数。

    和 do_encrypt 结构完全一样，只是把 encrypt 换成 decrypt，错误提示改成
    "解密失败"。这种结构叫对称设计，读一个就懂另一个。

    为什么错误提示要分开写：
        加密失败通常是"你没输入内容"；解密失败通常是"密码错了"。用户看到不同
        的提示，才知道该往哪个方向检查。
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


# 下面开始是界面搭建。这部分是"从上往下依次执行"的代码，不在任何函数里。
# 也就是说，程序一启动就会一行一行跑完，然后停在 mainloop() 等待用户操作。

# Tk() 创建主窗口。整个界面必须有一个根窗口，其他控件都放在它里面。
window = Tk()
window.title("AES 密钥加密解密工具")

# Label 是纯文字标签，给用户看提示
Label(window, text="请输入文本:").pack()

# Text 是多行文本框，height 是高度（几行），width 是宽度（几个字符）
text_input = Text(window, height=5, width=50)
text_input.pack()

Label(window, text="请输入密码:").pack()

# Entry 是单行输入框（Text 是多行，Entry 是一行）。
# show="*" 让输入内容显示成星号，防止密码被旁人看到。
# 想临时看清密码内容做调试，可以先把 show="*" 删掉，调完再加回来。
key_input = Entry(window, show="*")
key_input.pack()

# command= 后面写函数名，注意不要加括号。
#     写 do_encrypt   —— 传的是函数本身，点击时才调用       （正确）
#     写 do_encrypt() —— 会立刻执行，再把返回值传给 command（错误）
#
# 这个区别叫"引用"和"调用"。如果写错了，程序一启动就会执行一次加密（那时
# 输入框还是空的，于是立刻报"明文不能为空"），而按钮点了没反应。
Button(window, text="加密", command=do_encrypt).pack()
Button(window, text="解密", command=do_decrypt).pack()

Label(window, text="结果:").pack()
result = Text(window, height=5, width=50)
result.pack()

# mainloop() 进入事件循环：程序停在这里，不断等待并响应鼠标点击、键盘输入等
# 操作。没有它，窗口会一闪而过就关闭。
window.mainloop()
