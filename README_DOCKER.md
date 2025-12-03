# Docker容器管理指南

## 概述

本文档详细说明如何使用`start_container.sh`脚本来管理Docker容器，特别是解决权限问题。

## 权限问题解决方案

### 问题描述
当您运行`docker stop my-running-app`时出现"permission denied"错误，这是因为当前用户没有足够的Docker权限。

### 解决方案

#### 方案1：使用脚本的停止功能（推荐）
```bash
# 使用脚本内置的停止功能，会自动处理权限问题
./start_container.sh --stop
```

#### 方案2：永久解决权限问题
```bash
# 将当前用户添加到docker组
sudo usermod -aG docker $USER

# 重新登录或重启系统使权限生效
# 或者执行：newgrp docker
```

#### 方案3：临时使用sudo
```bash
# 使用sudo执行Docker命令
sudo docker stop my-running-app
sudo docker rm my-running-app
```

## 脚本使用方法

### 基本命令

```bash
# 启动容器（默认行为）
./start_container.sh

# 强制重新构建镜像并启动
./start_container.sh --rebuild

# 停止容器（自动处理权限问题）
./start_container.sh --stop

# 重启容器
./start_container.sh --restart

# 显示帮助信息
./start_container.sh --help
```

### 环境变量配置

您可以通过环境变量自定义配置：

```bash
# 设置DeepSeek API密钥（必需）
export DEEPSEEK_API_KEY="your-api-key-here"

# 设置模型缓存目录（可选）
export MODEL_CACHE_DIR="/path/to/your/cache"

# 设置源代码目录（可选）
export SOURCE_CODE_PATH="/path/to/your/source"

# 然后运行脚本
./start_container.sh
```

### 手动Docker命令

如果脚本无法满足需求，您也可以直接使用Docker命令：

```bash
# 查看运行中的容器
docker ps

# 查看所有容器（包括停止的）
docker ps -a

# 查看容器日志
docker logs -f my-running-app

# 进入容器终端
docker exec -it my-running-app bash

# 停止容器（可能需要sudo）
docker stop my-running-app

# 删除容器
docker rm my-running-app

# 查看镜像
docker images

# 删除镜像
docker rmi my-python-app:latest
```

## 故障排除

### 常见问题

1. **权限被拒绝错误**
   - 症状：`docker: permission denied`
   - 解决方案：使用`./start_container.sh --stop`或按照上述权限解决方案处理

2. **端口冲突错误**
   - 症状：`Bind for 0.0.0.0:9002 failed: port is already allocated`
   - 解决方案：停止占用端口的容器或使用不同端口

3. **镜像构建失败**
   - 症状：构建过程中出现网络错误
   - 解决方案：检查网络连接或使用`--rebuild`参数重试

### 日志查看

如果遇到问题，可以查看容器日志：

```bash
# 查看实时日志
docker logs -f my-running-app

# 查看最近100行日志
docker logs --tail 100 my-running-app
```

## 安全建议

1. **API密钥保护**：不要将API密钥硬编码在脚本中，使用环境变量
2. **定期更新**：定期更新Docker镜像以获取安全补丁
3. **网络隔离**：在生产环境中考虑使用Docker网络隔离
4. **资源限制**：为容器设置适当的资源限制

## 技术支持

如果遇到无法解决的问题，请检查：
- Docker服务是否正常运行：`systemctl status docker`
- 用户是否在docker组中：`groups $USER`
- 系统日志：`journalctl -u docker.service`

## 问题修复

已解决MySQL连接错误问题：
- 将数据库从MySQL改为SQLite，避免容器内数据库连接问题
- 移除了不必要的MySQL客户端依赖
- 修改启动脚本自动执行数据库迁移和启动Django服务器

## 使用方法

### 1. 设置API密钥
```bash
# 方法1：设置环境变量
export DEEPSEEK_API_KEY="your-actual-api-key-here"

# 方法2：直接传递环境变量
DEEPSEEK_API_KEY="xxx" ./start_container.sh
```

### 2. 启动容器
```bash
# 常规启动（如果镜像已存在且无需更新）
./start_container.sh

# 强制重建镜像（如果代码有更新）
./start_container.sh --rebuild
```

### 3. 访问应用
容器启动后，Django应用将自动运行在：
- 本地访问：http://localhost:9002
- 容器内访问：http://0.0.0.0:9002

## 容器内操作

容器启动后会自动：
1. 同步本地代码到容器内
2. 执行数据库迁移（python manage.py migrate）
3. 启动Django开发服务器（python manage.py runserver 0.0.0.0:9002）

## 注意事项

- 确保API密钥正确设置，否则容器启动会失败
- 代码修改会自动同步到容器内，无需重新构建镜像
- 数据库使用SQLite，数据文件保存在项目根目录的db.sqlite3文件中