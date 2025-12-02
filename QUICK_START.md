# 快速启动指南

## 问题已修复

✅ **MySQL连接错误已解决**：
- 数据库配置已改为SQLite
- 移除了mysqlclient依赖
- Docker构建问题已修复

## 启动步骤

### 1. 设置API密钥
```bash
# 方法1：设置环境变量
export DEEPSEEK_API_KEY="your-actual-api-key-here"

# 方法2：直接传递环境变量
DEEPSEEK_API_KEY="your-actual-api-key-here" ./start_container.sh
```

### 2. 启动应用（自动重建镜像）
```bash
# 脚本会自动检测requirements.txt更新并重建镜像
./start_container.sh
```

### 3. 或者强制重建镜像
```bash
# 如果遇到构建问题，使用强制重建
./start_container.sh --rebuild
```

## 访问应用

启动成功后，访问：**http://localhost:9002**

## 常见问题

### Q: 仍然遇到构建错误？
A: 使用强制重建模式：`./start_container.sh --rebuild`

### Q: API密钥错误？
A: 确保正确设置了DEEPSEEK_API_KEY环境变量

### Q: 端口被占用？
A: 脚本会自动清理现有容器，如果仍有问题，手动停止：
```bash
docker stop my-running-app
docker rm my-running-app
```

## 验证启动成功

容器启动后应该看到：
- Django数据库迁移完成
- "Starting development server at http://0.0.0.0:9002/"
- 没有MySQL连接错误信息