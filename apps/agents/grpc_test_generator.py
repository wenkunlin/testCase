# -*- coding: utf-8 -*-
"""
gRPC测试用例生成器Agent
用于根据proto文件定义生成gRPC接口测试用例
"""

import os
import re
import json
from typing import List, Dict, Any, Optional
from apps.llm.base import BaseLLMService
from apps.knowledge.service import KnowledgeService
from utils.logger_manager import get_logger

logger = get_logger(__name__)


class GrpcTestGenerator:
    """gRPC测试用例生成器"""
    
    def __init__(self, llm_service: BaseLLMService, knowledge_service: Optional[KnowledgeService] = None):
        """
        初始化gRPC测试用例生成器
        
        Args:
            llm_service: LLM服务实例
            knowledge_service: 知识库服务实例（可选）
        """
        self.llm_service = llm_service
        self.knowledge_service = knowledge_service
        
    def parse_proto_file(self, proto_path: str) -> Dict[str, Any]:
        """
        解析proto文件，提取服务和方法定义
        
        Args:
            proto_path: proto文件路径
            
        Returns:
            包含服务和方法信息的字典
        """
        try:
            with open(proto_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 提取服务定义
            service_pattern = r'service\s+(\w+)\s*\{([^}]+)\}'
            services = []
            
            for service_match in re.finditer(service_pattern, content):
                service_name = service_match.group(1)
                service_body = service_match.group(2)
                
                # 提取RPC方法
                rpc_pattern = r'rpc\s+(\w+)\s*\(([^)]+)\)\s*returns\s*\(([^)]+)\)'
                methods = []
                
                for rpc_match in re.finditer(rpc_pattern, service_body):
                    method_name = rpc_match.group(1)
                    request_type = rpc_match.group(2).strip()
                    response_type = rpc_match.group(3).strip()
                    
                    methods.append({
                        'name': method_name,
                        'request_type': request_type,
                        'response_type': response_type
                    })
                
                services.append({
                    'name': service_name,
                    'methods': methods
                })
            
            # 提取消息定义
            message_pattern = r'message\s+(\w+)\s*\{([^}]+)\}'
            messages = {}
            
            for msg_match in re.finditer(message_pattern, content):
                msg_name = msg_match.group(1)
                msg_body = msg_match.group(2)
                
                # 提取字段
                field_pattern = r'(\w+)\s+(\w+)\s*=\s*\d+;'
                fields = []
                
                for field_match in re.finditer(field_pattern, msg_body):
                    field_type = field_match.group(1)
                    field_name = field_match.group(2)
                    fields.append({
                        'type': field_type,
                        'name': field_name
                    })
                
                messages[msg_name] = fields
            
            return {
                'services': services,
                'messages': messages,
                'raw_content': content
            }
            
        except Exception as e:
            logger.error(f"解析proto文件失败: {str(e)}")
            raise
    
    def get_grpc_methods_from_directory(self, grpc_dir: str) -> List[Dict[str, Any]]:
        """
        从目录中获取所有gRPC方法
        
        Args:
            grpc_dir: gRPC proto文件目录
            
        Returns:
            方法列表
        """
        all_methods = []
        
        try:
            for filename in os.listdir(grpc_dir):
                if filename.endswith('.proto'):
                    proto_path = os.path.join(grpc_dir, filename)
                    proto_info = self.parse_proto_file(proto_path)
                    
                    for service in proto_info['services']:
                        for method in service['methods']:
                            all_methods.append({
                                'file': filename,
                                'service': service['name'],
                                'method': method['name'],
                                'request_type': method['request_type'],
                                'response_type': method['response_type'],
                                'proto_path': proto_path
                            })
            
            return all_methods
            
        except Exception as e:
            logger.error(f"获取gRPC方法失败: {str(e)}")
            raise
    
    def get_knowledge_context(self, method_name: str) -> str:
        """
        从知识库获取相关上下文
        
        Args:
            method_name: 方法名称
            
        Returns:
            知识库上下文
        """
        if not self.knowledge_service:
            return ""
        
        try:
            # 从知识库搜索相关测试用例
            results = self.knowledge_service.search(
                query=f"gRPC {method_name} 测试用例",
                top_k=3
            )
            
            context = "\n\n".join([r['content'] for r in results])
            return context
            
        except Exception as e:
            logger.warning(f"获取知识库上下文失败: {str(e)}")
            return ""
    
    def get_example_code_context(self, example_dir: str) -> str:
        """
        从example/code目录获取示例代码上下文
        
        Args:
            example_dir: 示例代码目录
            
        Returns:
            示例代码上下文
        """
        try:
            context_parts = []
            
            # 读取vrf.py作为参考
            vrf_path = os.path.join(example_dir, 'vrf.py')
            if os.path.exists(vrf_path):
                with open(vrf_path, 'r', encoding='utf-8') as f:
                    vrf_content = f.read()
                    newline = chr(10)
                    context_parts.append(f"参考测试用例代码:{newline}```python{newline}{vrf_content}{newline}```")
            
            return "\n\n".join(context_parts)
            
        except Exception as e:
            logger.warning(f"获取示例代码上下文失败: {str(e)}")
            return ""
    
    def generate_test_cases_text(self, method_info: Dict[str, Any], proto_content: str, 
                                 knowledge_context: str = "", example_context: str = "") -> List[Dict[str, Any]]:
        """
        生成测试用例文本描述
        
        Args:
            method_info: 方法信息
            proto_content: proto文件内容
            knowledge_context: 知识库上下文
            example_context: 示例代码上下文
            
        Returns:
            测试用例列表
        """
        prompt = f"""你是一个专业的gRPC接口测试工程师。请根据以下gRPC接口定义生成详细的测试用例。

## gRPC接口信息
- 服务名: {method_info['service']}
- 方法名: {method_info['method']}
- 请求类型: {method_info['request_type']}
- 响应类型: {method_info['response_type']}

## Proto文件内容
```protobuf
{proto_content}
```

{'## 知识库参考' + chr(10) + knowledge_context + chr(10) if knowledge_context else ""}

{'## 示例代码参考' + chr(10) + example_context + chr(10) if example_context else ""}

## 要求
请生成全面的测试用例，包括但不限于：
1. 基本功能测试（正常流程）
2. 参数合法性测试（边界值、非法值）
3. 幂等性测试
4. 并发测试
5. 异常场景测试

## 输出格式
请以JSON数组格式输出，每个测试用例包含：
- description: 测试用例描述
- test_steps: 测试步骤列表
- expected_results: 预期结果列表
- test_data: 测试数据（可选）

示例：
```json
[
    {{
        "description": "测试创建VRF的基本功能",
        "test_steps": [
            "1. 准备VRF创建请求参数",
            "2. 调用CreateVrf接口",
            "3. 验证返回结果"
        ],
        "expected_results": [
            "1. 接口调用成功",
            "2. 返回码为0",
            "3. VRF创建成功"
        ],
        "test_data": {{
            "vrf_name": "test_vrf",
            "vrf_type": 1
        }}
    }}
]
```

请直接输出JSON数组，不要包含其他说明文字。
"""
        
        try:
            response = self.llm_service.generate(prompt)
            
            # 提取JSON内容
            json_match = re.search(r'\[[\s\S]*\]', response)
            if json_match:
                test_cases = json.loads(json_match.group(0))
                return test_cases
            else:
                logger.error("无法从LLM响应中提取JSON")
                return []
                
        except Exception as e:
            logger.error(f"生成测试用例文本失败: {str(e)}")
            raise
    
    def generate_test_code(self, method_info: Dict[str, Any], test_cases: List[Dict[str, Any]], 
                          base_class_content: str = "") -> str:
        """
        生成测试用例代码
        
        Args:
            method_info: 方法信息
            test_cases: 测试用例列表
            base_class_content: 基类代码内容
            
        Returns:
            生成的测试代码
        """
        test_cases_json = json.dumps(test_cases, ensure_ascii=False, indent=2)
        
        prompt = f"""你是一个专业的Python测试代码生成专家。请根据以下信息生成gRPC接口测试代码。

## gRPC接口信息
- 服务名: {method_info['service']}
- 方法名: {method_info['method']}
- 请求类型: {method_info['request_type']}
- 响应类型: {method_info['response_type']}

## 测试用例
```json
{test_cases_json}
```

{'## 基类参考' + chr(10) + '基类中已经封装了gRPC调用的基础方法，你可以直接使用。' + chr(10) if base_class_content else ""}

## 代码要求
1. 继承自NTBTestBase类
2. 参考example/code/vrf.py的代码风格
3. 在基类中封装对应的增删改查接口方法（如create_{method_info['method'].lower()}, delete_{method_info['method'].lower()}等）
4. 在run_test方法中实现所有测试用例
5. 使用self.start_step()标记测试步骤
6. 每个测试用例都要有清晰的注释
7. 代码要规范、可读性强

## 输出格式
请直接输出完整的Python测试代码，包括：
1. 文件头注释
2. 必要的import语句
3. 测试类定义
4. pre_test、run_test、post_test方法
5. 辅助方法

请确保代码可以直接运行，不要包含任何说明文字。
"""
        
        try:
            response = self.llm_service.generate(prompt)
            
            # 提取Python代码
            code_match = re.search(r'```python\n([\s\S]*?)\n```', response)
            if code_match:
                code = code_match.group(1)
            else:
                # 如果没有代码块标记，直接使用全部内容
                code = response
            
            return code
            
        except Exception as e:
            logger.error(f"生成测试代码失败: {str(e)}")
            raise
    
    def generate_base_methods(self, method_info: Dict[str, Any], proto_content: str) -> str:
        """
        生成基类方法代码（增删改查接口封装）
        
        Args:
            method_info: 方法信息
            proto_content: proto文件内容
            
        Returns:
            基类方法代码
        """
        prompt = f"""你是一个专业的Python gRPC客户端开发专家。请为以下gRPC接口生成基类封装方法。

## gRPC接口信息
- 服务名: {method_info['service']}
- 方法名: {method_info['method']}
- 请求类型: {method_info['request_type']}
- 响应类型: {method_info['response_type']}

## Proto文件内容
```protobuf
{proto_content}
```

## 要求
1. 生成一个封装方法，方法名为{method_info['method'].lower()}
2. 方法应该接收必要的参数，并构造gRPC请求
3. 调用gRPC接口并返回结果
4. 包含错误处理和日志记录
5. 参考ntb_test_base.py的代码风格

## 输出格式
请直接输出Python方法代码，包含完整的文档字符串。

示例：
```python
def create_vrf(self, vrf_name, expect_res="success", **kwargs):
    \"\"\"
    创建VRF
    
    Args:
        vrf_name: VRF名称
        expect_res: 期望结果
        **kwargs: 其他参数
        
    Returns:
        响应结果
    \"\"\"
    try:
        # 构造请求
        request = VrfRequest()
        request.vrf.vrf_name = vrf_name
        
        # 调用gRPC接口
        response = self.ntb_grpc_client.CreateVrf(request)
        
        # 验证结果
        if expect_res == "success":
            self.assert_equal(response.result.code, 0, "创建VRF失败")
        else:
            self.assert_in(expect_res, response.result.message, "错误信息不匹配")
            
        return response
        
    except Exception as e:
        self.log_error(f"创建VRF异常: {{str(e)}}")
        raise
```

请直接输出方法代码，不要包含其他说明文字。
"""
        
        try:
            response = self.llm_service.generate(prompt)
            
            # 提取Python代码
            code_match = re.search(r'```python\n([\s\S]*?)\n```', response)
            if code_match:
                code = code_match.group(1)
            else:
                code = response
            
            return code
            
        except Exception as e:
            logger.error(f"生成基类方法失败: {str(e)}")
            raise
    
    def generate_complete_test_suite(self, method_info: Dict[str, Any], 
                                    grpc_dir: str, example_dir: str) -> Dict[str, Any]:
        """
        生成完整的测试套件（包括文本用例和代码）
        
        Args:
            method_info: 方法信息
            grpc_dir: gRPC proto文件目录
            example_dir: 示例代码目录
            
        Returns:
            包含测试用例文本和代码的字典
        """
        try:
            # 1. 解析proto文件
            proto_info = self.parse_proto_file(method_info['proto_path'])
            proto_content = proto_info['raw_content']
            
            # 2. 获取知识库上下文
            knowledge_context = self.get_knowledge_context(method_info['method'])
            
            # 3. 获取示例代码上下文
            example_context = self.get_example_code_context(example_dir)
            
            # 4. 生成测试用例文本
            logger.info(f"开始生成测试用例文本: {method_info['method']}")
            test_cases = self.generate_test_cases_text(
                method_info, proto_content, knowledge_context, example_context
            )
            
            # 5. 生成基类方法
            logger.info(f"开始生成基类方法: {method_info['method']}")
            base_methods = self.generate_base_methods(method_info, proto_content)
            
            # 6. 生成测试代码
            logger.info(f"开始生成测试代码: {method_info['method']}")
            test_code = self.generate_test_code(method_info, test_cases, base_methods)
            
            return {
                'success': True,
                'method_info': method_info,
                'test_cases': test_cases,
                'base_methods': base_methods,
                'test_code': test_code
            }
            
        except Exception as e:
            logger.error(f"生成测试套件失败: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
