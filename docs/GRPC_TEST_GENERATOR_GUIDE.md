# gRPC接口自动化测试用例生成功能使用指南

## 功能概述

本功能集成在原有的自动化用例生成页面（`/generate/`）中，支持根据gRPC接口定义（proto文件）自动生成测试用例文本和可执行的测试代码。

## 主要特性

1. **自动解析proto文件**：从`example/grpc`目录读取proto文件，提取服务和方法定义
2. **智能生成测试用例**：基于AI大模型生成全面的测试用例，包括：
   - 基本功能测试
   - 参数合法性测试
   - 幂等性测试
   - 并发测试
   - 异常场景测试
3. **生成可执行代码**：参考`example/code`目录下的示例代码风格，生成符合项目规范的测试代码
4. **知识库支持**：结合知识库中的测试用例和`example/grpc`、`example/code`目录内容，生成更准确的测试用例
5. **代码下载**：支持在网页上查看和下载生成的测试代码
6. **自动保存**：生成的代码自动保存到`example/auto`目录

## 使用步骤

### 1. 准备proto文件

将gRPC接口定义文件（.proto）放置在`example/grpc`目录下。

示例：`example/grpc/ntb_config.proto`

### 2. 准备示例代码（可选）

在`example/code`目录下放置参考的测试用例代码：
- `ntb_test_base.py`：基础测试类，封装了gRPC调用的基础方法
- `vrf.py`：测试用例示例，展示测试代码的结构和风格

### 3. 访问生成页面

启动Django服务器后，访问：`http://<服务器IP>:9002/generate/`

### 4. 选择测试类型

在页面上选择"测试类型"为"gRPC接口测试用例"

### 5. 选择gRPC方法

从下拉列表中选择要生成测试用例的gRPC方法，格式为：
```
<proto文件名> - <服务名>.<方法名>
```

例如：`ntb_config.proto - NtbConfigService.CreateVrf`

### 6. 生成测试用例

点击"生成测试用例"按钮，系统将：
1. 解析proto文件
2. 从知识库和示例代码中获取参考信息
3. 调用AI大模型生成测试用例文本
4. 生成基类方法（增删改查接口封装）
5. 生成完整的测试代码

### 7. 查看和下载

生成完成后，页面会显示：
- **测试用例表格**：展示所有生成的测试用例，包括描述、测试步骤、预期结果
- **查看测试代码**：点击按钮在模态框中查看生成的代码
- **下载测试代码**：点击按钮下载代码文件到本地
- **复制代码**：在模态框中点击复制按钮，将代码复制到剪贴板

### 8. 代码保存位置

生成的测试代码会自动保存到：
```
example/auto/test_<方法名>_<时间戳>.py
```

## 生成的代码结构

生成的测试代码包含以下部分：

```python
# -*- coding: utf-8 -*-
'''<方法名> grpc 测试用例'''

from testbase.testcase import debug_run_all
from ntbtest.ntb_test_base import *
from utils.utils import *

class <方法名>Test(NTBTestBase):
    '''测试类'''
    owner = "auto"
    timeout = 30
    priority = NtbTestCase.EnumPriority.High
    status = NtbTestCase.EnumStatus.Design

    def pre_test(self):
        '''测试前准备'''
        super(<方法名>Test, self).pre_test()
    
    def run_test(self):
        '''执行测试'''
        # 测试步骤1
        self.start_step("1.基本功能测试")
        # ... 测试代码 ...
        
        # 测试步骤2
        self.start_step("2.参数合法性测试")
        # ... 测试代码 ...

    def post_test(self):
        '''测试后清理'''
        super(<方法名>Test, self).post_test()

if __name__ == '__main__':
    debug_run_all()
```

## 知识库集成

### 当前支持的知识来源

1. **知识库上传**：通过知识库功能上传的测试用例文档（功能待完善）
2. **example/grpc目录**：proto文件定义
3. **example/code目录**：示例测试代码

### 知识库更新

生成的测试代码会自动保存到`example/auto`目录，并在系统启动时自动加载到知识库中，供后续生成参考。

## 技术架构

### 核心组件

1. **GrpcTestGenerator**（`apps/agents/grpc_test_generator.py`）
   - proto文件解析
   - 测试用例生成
   - 测试代码生成

2. **前端页面**（`templates/generate.html`）
   - 测试类型选择
   - gRPC方法选择
   - 测试用例展示
   - 代码查看和下载

3. **后端视图**（`apps/core/views.py`）
   - 处理生成请求
   - 调用生成器
   - 保存生成的代码

4. **前端脚本**（`static/js/generate.js`）
   - 表单提交处理
   - 测试用例展示
   - 代码下载功能

### 工作流程

```
用户选择gRPC方法
    ↓
解析proto文件
    ↓
获取知识库上下文（知识库 + example/code）
    ↓
AI生成测试用例文本
    ↓
AI生成基类方法
    ↓
AI生成完整测试代码
    ↓
保存到example/auto
    ↓
展示在网页上
    ↓
用户下载代码
```

## 注意事项

1. **proto文件格式**：确保proto文件符合protobuf 3语法规范
2. **示例代码**：`example/code`目录下的示例代码会影响生成的代码风格
3. **AI模型选择**：可以在页面上选择不同的AI模型（DeepSeek、Qwen等）
4. **生成时间**：根据接口复杂度，生成时间可能需要几十秒到几分钟
5. **代码审查**：生成的代码建议人工审查后再使用

## 常见问题

### Q: 为什么没有看到gRPC方法列表？
A: 检查`example/grpc`目录下是否有.proto文件，以及文件格式是否正确。

### Q: 生成的代码在哪里？
A: 代码保存在`example/auto`目录下，文件名格式为`test_<方法名>_<时间戳>.py`。

### Q: 如何自定义生成的代码风格？
A: 修改`example/code`目录下的示例代码，生成器会参考这些代码的风格。

### Q: 知识库功能如何使用？
A: 知识库功能目前会自动加载`example/auto`目录下的代码，未来会支持手动上传测试用例文档。

## 未来规划

1. 支持批量生成多个方法的测试用例
2. 支持自定义测试用例模板
3. 完善知识库上传功能
4. 支持测试用例的版本管理
5. 集成测试执行和结果分析功能
