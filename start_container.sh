#!/bin/bash

# 容器启动脚本（跨平台兼容版本，支持权限管理）
# 支持Linux、macOS和Windows（通过WSL）
# 
# 使用方法: ./start_container.sh [--rebuild|--stop|--restart]
# 参数说明:
#   --rebuild: 强制重新构建镜像，忽略文件更新时间检查
#   --stop: 停止正在运行的容器
#   --restart: 重启容器
#
# 环境变量配置（可选，用于跨平台适配）:
#   - DEEPSEEK_API_KEY: DeepSeek API密钥（必需）
#   - MODEL_CACHE_DIR: 模型缓存目录路径（可选，默认：$HOME/.cache/my-app/models）
#   - SOURCE_CODE_PATH: 源代码目录路径（可选，默认：当前目录/TestBrain或当前目录）
#
# 跨平台说明:
#   - Linux/macOS: 直接运行此脚本
#   - Windows: 建议使用WSL（Windows Subsystem for Linux）运行
#
# 权限管理:
#   - 自动检测是否需要sudo权限
#   - 如果普通用户权限不足，会提示使用sudo
#
# 运行模式:
#   - 容器默认在后台运行，Ctrl+C可正常退出脚本
#   - 启动后提供交互选项进入容器终端
#   - 容器日志可通过 docker logs -f my-running-app 查看

# 设置DeepSeek API密钥
# 优先从环境变量读取，如果不存在则使用默认值或提示用户
if [ -n "$DEEPSEEK_API_KEY" ]; then
    echo "使用环境变量中的API密钥"
else
    DEEPSEEK_API_KEY="your-actual-key"
fi

# 定义容器名称
CONTAINER_NAME="my-running-app"

# 检测是否需要sudo权限
DOCKER_CMD="docker"
if ! docker ps >/dev/null 2>&1; then
    echo "检测到当前用户没有Docker权限，尝试使用sudo..."
    if sudo docker ps >/dev/null 2>&1; then
        DOCKER_CMD="sudo docker"
        echo "将使用sudo执行Docker命令"
    else
        echo "错误：无法访问Docker，请检查Docker服务状态和用户权限"
        echo "可能的解决方案："
        echo "1. 将当前用户添加到docker组: sudo usermod -aG docker $USER"
        echo "2. 重新登录或重启系统使权限生效"
        echo "3. 或者使用sudo运行此脚本"
        exit 1
    fi
fi

# 函数：停止容器
stop_container() {
    echo "正在停止容器 $CONTAINER_NAME..."
    
    # 检查容器是否在运行
    if $DOCKER_CMD ps | grep -q "$CONTAINER_NAME"; then
        echo "容器正在运行，正在停止..."
        $DOCKER_CMD stop "$CONTAINER_NAME"
        if [ $? -eq 0 ]; then
            echo "容器停止成功"
        else
            echo "容器停止失败，请检查权限"
            return 1
        fi
    else
        echo "容器 $CONTAINER_NAME 未在运行"
    fi
    
    # 删除容器（如果存在）
    if $DOCKER_CMD ps -a | grep -q "$CONTAINER_NAME"; then
        echo "删除容器 $CONTAINER_NAME..."
        $DOCKER_CMD rm "$CONTAINER_NAME"
        if [ $? -eq 0 ]; then
            echo "容器删除成功"
        else
            echo "容器删除失败，请检查权限"
            return 1
        fi
    else
        echo "容器 $CONTAINER_NAME 不存在"
    fi
    
    return 0
}

# 函数：重启容器
restart_container() {
    echo "正在重启容器 $CONTAINER_NAME..."
    
    # 检查容器是否在运行
    if $DOCKER_CMD ps | grep -q "$CONTAINER_NAME"; then
        echo "容器正在运行，先停止容器..."
        stop_container
        if [ $? -ne 0 ]; then
            echo "停止容器失败，无法重启"
            return 1
        fi
    fi
    
    # 等待一段时间确保容器完全停止
    sleep 2
    
    # 重新启动容器
    echo "重新启动容器..."
    # 这里调用主启动逻辑，但需要跳过权限检测和参数处理
    main_start_container
}

# 函数：构建镜像并检查结果
build_image() {
    local tag=$1
    echo "正在构建镜像 $tag..."
    $DOCKER_CMD build -t "$tag" .
    
    # 检查构建是否成功
    local build_success=$?
    if [ $build_success -ne 0 ]; then
        echo "构建Docker镜像失败，可能是网络问题或其他错误。"
        
        # 检查是否存在之前构建的镜像
        if $DOCKER_CMD images | grep -q "my-python-app"; then
            echo "发现之前构建的my-python-app镜像，将尝试使用它..."
            return 1  # 构建失败但有备选镜像
        else
            echo "没有找到可用的my-python-app镜像，无法继续。"
            exit 1  # 构建失败且没有备选镜像
        fi
    fi
    return 0  # 构建成功
}

# 主启动容器函数
main_start_container() {
    # 运行容器
    echo "正在启动容器..."
    
    # 创建模型缓存目录（跨平台兼容的路径处理）
    MODEL_CACHE_DIR="${MODEL_CACHE_DIR:-$HOME/.cache/my-app/models}"
    mkdir -p "$MODEL_CACHE_DIR"
    chmod -R 755 "$MODEL_CACHE_DIR" 2>/dev/null || true
    echo "使用模型缓存目录: $MODEL_CACHE_DIR"
    
    if [ -n "$DEEPSEEK_API_KEY" ]; then
        # 定义源代码挂载路径
        SOURCE_CODE_PATH="${SOURCE_CODE_PATH:-$(pwd)/TestBrain}"
        if [ ! -d "$SOURCE_CODE_PATH" ]; then
            echo "警告：源代码目录 $SOURCE_CODE_PATH 不存在，使用当前目录作为源代码路径"
            SOURCE_CODE_PATH="$(pwd)"
        fi
        echo "使用源代码目录: $SOURCE_CODE_PATH"
        echo ""
        
        # 先询问用户启动模式
        echo "请选择容器启动模式："
        echo "1. 后台模式 (默认) - 容器在后台运行，需要手动进入容器启动服务"
        echo "2. 交互模式 - 直接进入容器终端，可手动启动服务"
        read -t 10 -p "请输入选择 (1/2，默认1): " start_mode
        echo ""
        
        if [[ "$start_mode" == "2" ]]; then
            # 交互式模式
            echo "正在启动交互式容器..."
            echo "进入容器后，您可以手动执行以下命令启动服务器："
            echo "  python manage.py runserver 0.0.0.0:9002"
            echo ""
            echo "输入 'exit' 退出容器，容器将完全停止"
            echo ""
            
            $DOCKER_CMD run -it --rm -p 9002:9002 \
              -e DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" \
              -v "$SOURCE_CODE_PATH":/app/src \
              -v "$MODEL_CACHE_DIR":/root/.cache/torch/sentence_transformers \
              --name my-running-app my-python-app:latest \
              sh -c "mkdir -p /app/src && if [ -d /app/src ] && [ -n \"$(ls -A /app/src 2>/dev/null)\" ]; then cp -r /app/src/* /app/ 2>/dev/null || true; fi && cd /app && python manage.py makemigrations && python manage.py migrate && echo '数据迁移已完成！' && echo '现在可以手动启动服务器：python manage.py runserver 0.0.0.0:9002' && exec bash"
        else
            # 后台模式
            echo "正在启动后台容器..."
            $DOCKER_CMD run -d -p 9002:9002 \
              -e DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" \
              -v "$SOURCE_CODE_PATH":/app/src \
              -v "$MODEL_CACHE_DIR":/root/.cache/torch/sentence_transformers \
              --name my-running-app my-python-app:latest \
              sh -c "mkdir -p /app/src && if [ -d /app/src ] && [ -n \"$(ls -A /app/src 2>/dev/null)\" ]; then cp -r /app/src/* /app/ 2>/dev/null || true; fi && cd /app && python manage.py makemigrations && python manage.py migrate && tail -f /dev/null"
            
            # 检查容器是否启动成功
            if $DOCKER_CMD ps | grep -q "my-running-app"; then
                echo "容器启动成功！"
                echo "容器ID: $($DOCKER_CMD ps -q --filter name=my-running-app)"
                echo ""
                echo "操作说明："
                echo "1. 查看容器日志: $DOCKER_CMD logs -f my-running-app"
                echo "2. 进入容器交互模式: $DOCKER_CMD exec -it my-running-app bash"
                echo "3. 停止容器: $DOCKER_CMD stop my-running-app"
                echo "4. 重启容器: $DOCKER_CMD restart my-running-app"
                echo "5. 使用此脚本停止: ./start_container.sh --stop"
                echo ""
                echo "容器在后台运行中，数据迁移已完成"
                echo "如需启动服务器，请进入容器执行："
                echo "$DOCKER_CMD exec -it my-running-app bash"
                echo "然后在容器内运行：python manage.py runserver 0.0.0.0:9002"
                echo "注意：使用docker exec进入容器后，exit命令不会停止容器"
            else
                echo "容器启动失败，请检查日志：$DOCKER_CMD logs my-running-app"
                exit 1
            fi
        fi
    else
        exit 1
    fi
}

# 处理命令行参数
case "$1" in
    "--stop")
        stop_container
        exit $?
        ;;
    "--restart")
        restart_container
        exit $?
        ;;
    "--rebuild")
        FORCE_REBUILD=true
        echo "强制重建模式：将重新构建镜像"
        ;;
    "--help" | "-h")
        echo "使用方法: $0 [--rebuild|--stop|--restart|--help]"
        echo "  --rebuild: 强制重新构建镜像"
        echo "  --stop: 停止正在运行的容器"
        echo "  --restart: 重启容器"
        echo "  --help: 显示此帮助信息"
        exit 0
        ;;
    *)
        if [ -n "$1" ]; then
            echo "错误：未知参数 '$1'"
            echo "使用 --help 查看可用参数"
            exit 1
        fi
        ;;
esac

# 停止并删除现有容器（如果存在）
echo "正在清理现有容器..."
$DOCKER_CMD stop "$CONTAINER_NAME" 2>/dev/null || true
sleep 2  # 等待容器完全停止
$DOCKER_CMD rm "$CONTAINER_NAME" 2>/dev/null || true
echo "容器清理完成"

# 镜像标签
IMAGE_TAG="my-python-app:latest"
IMAGE_EXISTS=$($DOCKER_CMD images -q "$IMAGE_TAG" 2>/dev/null)

# 检查是否需要强制重建
if [ "$FORCE_REBUILD" = true ]; then
    echo "强制重建模式：重新构建镜像..."
    build_image "$IMAGE_TAG"
elif [ -n "$IMAGE_EXISTS" ]; then
    echo "镜像 $IMAGE_TAG 已存在，检查是否需要更新..."
    
    # 检查是否有最近修改的文件（1天内）
    NEED_UPDATE=false
    
    if [ -f "Dockerfile" ] && [ -n "$(find Dockerfile -mtime -1 2>/dev/null)" ]; then
        echo "检测到Dockerfile有更新"
        NEED_UPDATE=true
    fi
    
    if [ -f "requirements.txt" ] && [ -n "$(find requirements.txt -mtime -1 2>/dev/null)" ]; then
        echo "检测到requirements.txt有更新"
        NEED_UPDATE=true
    fi
    
    if [ -n "$(find . -name \"*.py\" -mtime -1 -type f 2>/dev/null | head -1)" ]; then
        NEED_UPDATE=true
        echo "检测到Python文件有更新"
        echo "更新的文件："
        find . -name \"*.py\" -mtime -1 -type f 2>/dev/null | head -3
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

# 启动容器
main_start_container