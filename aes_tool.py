from tkinter import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
 
def encrypt():
    plain_text = text_input.get("1.0", END).strip()
    key = key_input.get()
    
    # 创建AES对象，设定加密模式为ECB
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    # 对明文进行填充
    padded_text = pad(plain_text.encode('utf-8'), AES.block_size)
    # 执行加密操作
    encrypted_text = cipher.encrypt(padded_text)
    # 返回加密后的密文
    encrypted_text = base64.b64encode(encrypted_text).decode('utf-8')
    
    result.delete("1.0", END)
    result.insert(END, encrypted_text)
 
def decrypt():
    encrypted_text = text_input.get("1.0", END).strip()
    key = key_input.get()
    
    # 创建AES对象，设定加密模式为ECB
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    # 解密之前先将密文进行Base64解码
    encrypted_text = base64.b64decode(encrypted_text)
    # 执行解密操作
    decrypted_text = cipher.decrypt(encrypted_text)
    # 对解密后的数据进行去填充
    unpadded_text = unpad(decrypted_text, AES.block_size)
    # 返回解密后的明文
    decrypted_text = unpadded_text.decode('utf-8')
    
    result.delete("1.0", END)
    result.insert(END, decrypted_text)
 
# 创建主窗口
window = Tk()
window.title("密钥加密解密工具")
 
# 创建文本输入框和标签
text_label = Label(window, text="请输入明文/密文:")
text_label.pack()
text_input = Text(window, height=5, width=50)
text_input.pack()
 
# 创建密钥输入框和标签
key_label = Label(window, text="请输入密钥:")
key_label.pack()
key_input = Entry(window)
key_input.pack()
 
# 创建加密和解密按钮
encrypt_button = Button(window, text="加密", command=encrypt)
encrypt_button.pack()
decrypt_button = Button(window, text="解密", command=decrypt)
decrypt_button.pack()
 
# 创建结果显示框
result_label = Label(window, text="结果:")
result_label.pack()
result = Text(window, height=5, width=50)
result.pack()
 
# 运行主循环
window.mainloop()
