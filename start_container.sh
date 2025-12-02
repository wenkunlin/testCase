#!/bin/bash

# 容器启动脚本
# 使用方法: ./start_container.sh [--rebuild]
# 参数说明:
#   --rebuild: 强制重新构建镜像，忽略文件更新时间检查

# 设置DeepSeek API密钥
# 优先从环境变量读取，如果不存在则使用默认值或提示用户
if [ -n "$DEEPSEEK_API_KEY" ]; then
    echo "使用环境变量中的API密钥"
else
    DEEPSEEK_API_KEY="your-actual-key"
fi

# 定义容器名称
CONTAINER_NAME="my-running-app"

# 函数：构建镜像并检查结果
build_image() {
    local tag=$1
    echo "正在构建镜像 $tag..."
    docker build -t "$tag" .
    
    # 检查构建是否成功
    local build_success=$?
    if [ $build_success -ne 0 ]; then
        echo "构建Docker镜像失败，可能是网络问题或其他错误。"
        
        # 检查是否存在之前构建的镜像
        if docker images | grep -q "my-python-app"; then
            echo "发现之前构建的my-python-app镜像，将尝试使用它..."
            return 1  # 构建失败但有备选镜像
        else
            echo "没有找到可用的my-python-app镜像，无法继续。"
            exit 1  # 构建失败且没有备选镜像
        fi
    fi
    return 0  # 构建成功
}

# 处理命令行参数
FORCE_REBUILD=false
if [ "$1" = "--rebuild" ]; then
    FORCE_REBUILD=true
    echo "强制重建模式：将重新构建镜像"
fi

# 停止并删除现有容器（如果存在）
docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm "$CONTAINER_NAME" 2>/dev/null || true

# 镜像标签
IMAGE_TAG="my-python-app:latest"
IMAGE_EXISTS=$(docker images -q "$IMAGE_TAG" 2>/dev/null)

# 检查是否需要强制重建
if [ "$FORCE_REBUILD" = true ]; then
    echo "强制重建模式：重新构建镜像..."
    build_image "$IMAGE_TAG"
elif [ -n "$IMAGE_EXISTS" ]; then
    echo "镜像 $IMAGE_TAG 已存在，检查是否需要更新..."
    
    # 检查是否有最近修改的文件（1天内）
    NEED_UPDATE=false
    
    # 检查Dockerfile是否存在且被修改过
    if [ -f "Dockerfile" ] && [ -n "$(find Dockerfile -mtime -1 2>/dev/null)" ]; then
        echo "检测到Dockerfile有更新"
        NEED_UPDATE=true
    fi
    
    # 检查requirements.txt是否存在且被修改过
    if [ -f "requirements.txt" ] && [ -n "$(find requirements.txt -mtime -1 2>/dev/null)" ]; then
        echo "检测到requirements.txt有更新"
        NEED_UPDATE=true
    fi
    
    # 检查Python文件是否被修改过
    if [ -n "$(find . -name "*.py" -mtime -1 -type f 2>/dev/null | head -1)" ]; then
        NEED_UPDATE=true
        echo "检测到Python文件有更新"
        echo "更新的文件："
        find . -name "*.py" -mtime -1 -type f 2>/dev/null | head -3
    fi
    
    if [ "$NEED_UPDATE" = true ]; then
        echo "检测到文件更新，重新构建镜像..."
        build_image "$IMAGE_TAG"
    else
        echo "镜像无需更新，跳过构建步骤"
    fi
else
    echo "镜像不存在，开始构建镜像..."
    build_image "$IMAGE_TAG"
fi

# 运行容器
echo "正在启动容器..."
# 创建模型缓存目录（macOS友好的路径处理）
MODEL_CACHE_DIR="/Users/lin/Desktop/python/project3_docker/python_test/model_cache"

# 确保目录存在，使用兼容macOS的命令
mkdir -p "$MODEL_CACHE_DIR"

# 修复权限，确保容器可以读写（macOS有时会有权限问题）
chmod -R 755 "$MODEL_CACHE_DIR" 2>/dev/null || true

echo "使用模型缓存目录: $MODEL_CACHE_DIR"

if [ -n "$DEEPSEEK_API_KEY" ]; then
    docker run -it -p 9002:9002 \
      -e DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" \
      -v /Users/lin/Desktop/python/project3_docker/python_test/TestBrain:/mnt/src \
      -v "$MODEL_CACHE_DIR":/root/.cache/torch/sentence_transformers \
      --name my-running-app my-python-app:latest \
      sh -c "if [ -d /mnt/src ] && [ \"$(ls -A /mnt/src)\" ]; then cp -r /mnt/src/* /app/ 2>/dev/null || true; fi && cd /app && python manage.py makemigrations && python manage.py migrate && python manage.py runserver 0.0.0.0:9002"
else
    exit 1
fi