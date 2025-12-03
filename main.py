import os
import sys
from django.core.management import execute_from_command_line

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    
    # 设置可能影响服务器绑定的环境变量
    os.environ["DJANGO_ALLOWED_HOSTS"] = "*"
    
    try:
        port = '9002'
        host = '0.0.0.0'
        
        # 打印调试信息
        print(f"正在启动Django服务器...")
        print(f"绑定主机: {host}")
        print(f"绑定端口: {port}")
        
        # 方法1：使用host:port格式（最可靠的方式）
        server_address = f"{host}:{port}"
        print(f"使用服务器地址: {server_address}")
        
        # 使用runserver命令，明确指定host和port
        # 这是Django官方推荐的方式，应该绑定到0.0.0.0
        execute_from_command_line(["manage.py", "runserver", server_address])
        
    except Exception as e:
        print(f"启动服务器时出错: {str(e)}")
        
        # 如果上面的方法失败，尝试直接使用manage.py
        print("尝试直接使用manage.py启动...")
        try:
            import subprocess
            subprocess.run(["python", "manage.py", "runserver", f"{host}:{port}"], check=True)
        except Exception as e2:
            print(f"备用方法也失败: {str(e2)}")
            sys.exit(1)