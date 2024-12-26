import hashlib
import os

# 安全地处理用户输入
def secure_input(prompt: str) -> str:
    while True:
        user_input = input(prompt)
        if user_input.strip():  # 确保输入不为空
            return user_input
        print("输入不能为空，请重新输入。")

# 安全地处理密码
def hash_password(password: str) -> str:
    # 使用安全的哈希算法（SHA-256）
    salt = os.urandom(16)  # 生成一个随机盐
    password_bytes = password.encode('utf-8')
    salted_password = password_bytes + salt
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password, salt

# 验证密码
def verify_password(stored_hash: str, stored_salt: bytes, input_password: str) -> bool:
    input_hash, _ = hash_password(input_password)
    return input_hash == stored_hash

# 主程序
if __name__ == "__main__":
    # 安全的用户输入
    username = secure_input("请输入用户名: ")
    password = secure_input("请输入密码: ")
    
    # 存储哈希密码
    stored_hash, stored_salt = hash_password(password)
    print(f"已为用户 {username} 安全存储密码哈希。")
    
    # 验证密码
    input_password = secure_input("再次输入密码以验证: ")
    if verify_password(stored_hash, stored_salt, input_password):
        print("密码验证成功！")
    else:
        print("密码验证失败！")
