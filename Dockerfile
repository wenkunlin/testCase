# 使用官方 Python 3.10  slim 版本作为基础镜像，体积较小
FROM python:3.10-slim

# 设置工作目录为 /app
WORKDIR /app

# 创建挂载目录
RUN mkdir -p /mnt/src

# 可选：将 apt 源更换为国内镜像（如清华源）以加速系统包安装
# RUN sed -i 's/deb.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list && \
#     sed -i 's/security.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list

# 安装必要的系统依赖（根据你的实际需求调整）
# 例如，一些Python包（如opencv-python, lxml等）可能需要这些系统库
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    pkg-config \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgl1 \
    && rm -rf /var/lib/apt/lists/*

# 将当前目录下的 requirements.txt 文件复制到容器的 /app 目录下
COPY requirements.txt .

    # 升级 pip 并使用官方 PyPI 源安装 Python 依赖
    RUN python -m pip install --upgrade pip && \
        pip install --no-cache-dir -r requirements.txt --use-deprecated=legacy-resolver

# 将当前项目的所有代码复制到工作目录 /app
COPY . .

# 设置环境变量（例如，设置 Python 缓冲，使日志立即输出）
ENV PYTHONUNBUFFERED=1

# 设置容器启动时默认执行的命令
CMD ["sh", "-c", "if [ -d /mnt/src ] && [ \"$(ls -A /mnt/src)\" ]; then cp -r /mnt/src/* /app/ 2>/dev/null || true; fi && /bin/bash"]