# Docker容器启动指南

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
DEEPSEEK_API_KEY="your-actual-api-key-here" ./start_container.sh
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