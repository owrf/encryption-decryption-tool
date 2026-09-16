import base64
import tkinter as tk
 
def base64_decrypt(encrypted_text):
    try:
        # 将Base64编码的字符串解码为字节串
        byte_string = base64.b64decode(encrypted_text)
        
        # 将字节串解码为字符串
        decrypted_text = byte_string.decode('utf-8')
        
        return decrypted_text
    except Exception as e:
        print("解密发生错误:", e)
 
def base64_encrypt(text):
    try:
        # 将字符串编码为字节串
        byte_string = text.encode('utf-8')
        
        # 使用Base64编码字节串
        encrypted_text = base64.b64encode(byte_string).decode('utf-8')
        
        return encrypted_text
    except Exception as e:
        print("加密发生错误:", e)
 
def decrypt_text():
    encrypted_text = input_text.get()
    decrypted_text = base64_decrypt(encrypted_text)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, decrypted_text)
 
def encrypt_text():
    text = input_text.get()
    encrypted_text = base64_encrypt(text)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, encrypted_text)
 
# 创建主窗口
root = tk.Tk()
root.title("Base64加解密")
root.geometry("400x250")
 
# 创建输入文本框
input_text = tk.Entry(root, width=50)
input_text.pack(pady=10)
 
# 创建解密按钮
decrypt_button = tk.Button(root, text="解密", command=decrypt_text)
decrypt_button.pack()
 
# 创建加密按钮
encrypt_button = tk.Button(root, text="加密", command=encrypt_text)
encrypt_button.pack()
 
# 创建结果文本框
result_text = tk.Text(root, height=6, width=50)
result_text.pack(pady=10)
 
# 运行主循环
root.mainloop()
