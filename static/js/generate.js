// 测试用例生成页面专用脚本

document.addEventListener('DOMContentLoaded', function() {
    const generateForm = document.getElementById('generate-form');
    const inputTypeRadios = document.querySelectorAll('input[name="input_type"]');
    const inputTextLabel = document.getElementById('input-text-label');
    const inputText = document.getElementById('input-text');
    const generateButton = document.getElementById('generate-button');
    const loadingIndicator = document.getElementById('loading-indicator');
    const resultContainer = document.getElementById('result-container');
    const saveButton = document.getElementById('save-button');
    
    // 根据输入类型更改标签文本
    if (inputTypeRadios && inputTypeRadios.length > 0) {
        inputTypeRadios.forEach(radio => {
            radio.addEventListener('change', function() {
                if (this.value === 'requirement') {
                    inputTextLabel.textContent = '需求描述:';
                    inputText.placeholder = '请输入需求描述...';
                } else {
                    inputTextLabel.textContent = '代码片段:';
                    inputText.placeholder = '请输入代码片段...';
                }
            });
        });
    }
    
    // 保存用户选择的大模型到本地存储
    const llmProviderSelect = document.getElementById('llm-provider');
    if (llmProviderSelect) {
        llmProviderSelect.addEventListener('change', function() {
            localStorage.setItem('preferred-llm-provider', this.value);
        });
        
        // 页面加载时恢复用户之前的选择（如果后端没有指定值）
        if (!llmProviderSelect.options[llmProviderSelect.selectedIndex].hasAttribute('selected')) {
            const savedProvider = localStorage.getItem('preferred-llm-provider');
            if (savedProvider) {
                // 确保保存的值在当前选项中存在
                for (let i = 0; i < llmProviderSelect.options.length; i++) {
                    if (llmProviderSelect.options[i].value === savedProvider) {
                        llmProviderSelect.value = savedProvider;
                        break;
                    }
                }
            }
        }
    }
    
    // 表单提交时显示加载指示器
    const form = document.querySelector('form');
    if (form) {
        form.addEventListener('submit', function() {
            if (loadingIndicator) {
                loadingIndicator.style.display = 'block';
            }
            if (generateButton) {
                generateButton.disabled = true;
            }
        });
    }
    
    // 提交表单生成测试用例 (原有功能，保留以兼容API调用方式)
    if (generateForm) {
        generateForm.addEventListener('submit', function(e) {
            e.preventDefault();
            console.log('表单提交事件触发');
            
            // 获取必要的 DOM 元素
            const loadingIndicator = document.getElementById('loading-indicator');
            const generateButton = document.getElementById('generate-button');
            const resultContainer = document.getElementById('result-container');
            const inputText = document.getElementById('input-text');
            
            // 获取输入文本
            const inputTextValue = inputText?.value?.trim();
            
            // 获取选择框元素
            const designMethodsSelect = document.getElementById('case_design_methods');
            const caseCategoriesSelect = document.getElementById('case_categories');
            
            if (!designMethodsSelect || !caseCategoriesSelect) {
                console.error('找不到选择框元素');
                return;
            }
            
            // 获取选中的值
            const selectedDesignMethods = Array.from(designMethodsSelect.selectedOptions || []).map(option => option.textContent);
            const selectedCaseCategories = Array.from(caseCategoriesSelect.selectedOptions || []).map(option => option.textContent);
            
            if (!inputTextValue) {
                showNotification('请输入需求描述', 'error');
                return;
            }
            
            // 显示加载指示器和清空结果容器（添加空值检查）
            if (loadingIndicator) {
                loadingIndicator.style.display = 'block';
            }
            if (resultContainer) {
                resultContainer.innerHTML = '';
            }
            if (generateButton) {
                generateButton.disabled = true;
            }
            
            // 获取测试类型
            const testType = document.getElementById('test-type')?.value || 'requirement';
            
            // 构造请求数据
            const requestData = {
                test_type: testType,
                llm_provider: document.getElementById('llm-provider')?.value || 'deepseek'
            };
            
            if (testType === 'grpc') {
                // gRPC测试用例
                const grpcMethod = document.getElementById('grpc-method')?.value;
                if (!grpcMethod) {
                    showNotification('请选择gRPC方法', 'error');
                    if (loadingIndicator) loadingIndicator.style.display = 'none';
                    if (generateButton) generateButton.disabled = false;
                    return;
                }
                requestData.grpc_method = grpcMethod;
            } else {
                // 需求测试用例
                requestData.requirements = inputTextValue;
                requestData.case_design_methods = selectedDesignMethods;
                requestData.case_categories = selectedCaseCategories;
                requestData.case_count = document.getElementById('case_count')?.value || '10';
            }
            
            console.log('发送的数据:', requestData);
            
            // 发送请求
            fetch('/generate/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken')
                },
                body: JSON.stringify(requestData)
            })
            .then(response => {
                console.log('收到服务器响应:', response.status);
                return response.json();
            })
            .then(data => {
                console.log('解析后的响应数据:', data);
                
                // 隐藏加载指示器
                if (loadingIndicator) {
                    loadingIndicator.style.display = 'none';
                }
                if (generateButton) {
                    generateButton.disabled = false;
                }
                
                if (data.success) {
                    // 创建或获取 result-container
                    let resultContainer = document.getElementById('result-container');
                    if (!resultContainer) {
                        resultContainer = document.createElement('div');
                        resultContainer.id = 'result-container';
                        resultContainer.className = 'mt-4';
                        generateForm.parentNode.insertBefore(resultContainer, generateForm.nextSibling);
                    }
                    
                    // 使用已有的 displayTestCases 函数显示测试用例
                    displayTestCases(data.test_cases, data.test_code);
                    
                    // 保存生成的测试用例到会话存储
                    sessionStorage.setItem('generatedTestCases', JSON.stringify(data.test_cases));
                    sessionStorage.setItem('inputText', inputTextValue);
                    
                    // 如果有测试代码，也保存
                    if (data.test_code) {
                        sessionStorage.setItem('testCode', data.test_code);
                        sessionStorage.setItem('codeFilename', data.code_filename || 'test_case.py');
                    }
                    
                    // 重新绑定保存按钮事件
                    const saveButton = document.getElementById('save-button');
                    if (saveButton) {
                        saveButton.disabled = false;
                    }
                } else {
                    console.error('服务器返回错误:', data.message);
                    if (resultContainer) {
                        resultContainer.innerHTML = `<div class="alert alert-danger">${data.message || '生成测试用例时出错'}</div>`;
                    }
                }
            })
            .catch(error => {
                console.error('请求发生错误:', error);
                if (loadingIndicator) {
                    loadingIndicator.style.display = 'none';
                }
                if (resultContainer) {
                    resultContainer.innerHTML = `<div class="alert alert-danger">请求失败: ${error.message}</div>`;
                }
            });
        });
    }
    
    // 显示测试用例
    function displayTestCases(testCases, testCode) {
        // 获取或创建 resultContainer
        let resultContainer = document.getElementById('result-container');
        if (!resultContainer) {
            // 如果不存在，创建一个新的
            resultContainer = document.createElement('div');
            resultContainer.id = 'result-container';
            resultContainer.className = 'mt-4';
            // 将新创建的容器插入到表单后面
            const generateForm = document.getElementById('generate-form');
            if (generateForm) {
                generateForm.parentNode.insertBefore(resultContainer, generateForm.nextSibling);
            } else {
                // 如果找不到表单，插入到body
                document.body.appendChild(resultContainer);
            }
        }

        if (!testCases || !testCases.length) {
            resultContainer.innerHTML = '<div class="alert alert-info">没有生成测试用例</div>';
            return;
        }
        
        let html = `
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">生成的测试用例</h5>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-bordered table-hover">
                            <thead class="thead-light">
                                <tr>
                                    <th width="5%">编号</th>
                                    <th width="25%">测试用例描述</th>
                                    <th width="35%">测试步骤</th>
                                    <th width="35%">预期结果</th>
                                </tr>
                            </thead>
                            <tbody>
        `;

        testCases.forEach((testCase, index) => {
            // 确保test_steps和expected_results是数组
            const testSteps = Array.isArray(testCase.test_steps) 
                ? testCase.test_steps 
                : testCase.test_steps.split('\n').filter(step => step.trim());
            
            const expectedResults = Array.isArray(testCase.expected_results)
                ? testCase.expected_results
                : testCase.expected_results.split('\n').filter(result => result.trim());

            html += `
                <tr>
                    <td>${index + 1}</td>
                    <td>${testCase.description || ''}</td>
                    <td>
                        ${testSteps.map(step => `<div class="mb-2">${step}</div>`).join('')}
                    </td>
                    <td>
                        ${expectedResults.map(result => `<div class="mb-2">${result}</div>`).join('')}
                    </td>
                </tr>
            `;
        });

        html += `
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <div class="text-right mt-3">
                <button id="save-button" class="btn btn-success">保存测试用例</button>
        `;
        
        // 如果有测试代码，添加下载和查看按钮
        if (testCode) {
            html += `
                <button id="download-code-button" class="btn btn-primary ml-2">下载测试代码</button>
                <button id="view-code-button" class="btn btn-info ml-2">查看测试代码</button>
            `;
        }
        
        html += `</div>`;
        
        // 如果有测试代码，添加代码查看模态框
        if (testCode) {
            html += `
            <div class="modal fade" id="codeModal" tabindex="-1" role="dialog">
                <div class="modal-dialog modal-xl" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">生成的测试代码</h5>
                            <button type="button" class="close" data-dismiss="modal">
                                <span>&times;</span>
                            </button>
                        </div>
                        <div class="modal-body">
                            <pre><code class="language-python">${escapeHtml(testCode)}</code></pre>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-dismiss="modal">关闭</button>
                            <button type="button" class="btn btn-primary" id="copy-code-button">复制代码</button>
                        </div>
                    </div>
                </div>
            </div>
            `;
        }

        resultContainer.innerHTML = html;

        // 绑定代码下载按钮事件
        const downloadCodeButton = document.getElementById('download-code-button');
        if (downloadCodeButton && testCode) {
            downloadCodeButton.addEventListener('click', function() {
                const filename = sessionStorage.getItem('codeFilename') || 'test_case.py';
                const blob = new Blob([testCode], { type: 'text/plain;charset=utf-8' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
            });
        }
        
        // 绑定代码查看按钮事件
        const viewCodeButton = document.getElementById('view-code-button');
        if (viewCodeButton && testCode) {
            viewCodeButton.addEventListener('click', function() {
                $('#codeModal').modal('show');
            });
        }
        
        // 绑定代码复制按钮事件
        const copyCodeButton = document.getElementById('copy-code-button');
        if (copyCodeButton && testCode) {
            copyCodeButton.addEventListener('click', function() {
                navigator.clipboard.writeText(testCode).then(function() {
                    alert('代码已复制到剪贴板');
                }).catch(function(err) {
                    console.error('复制失败:', err);
                    alert('复制失败，请手动复制');
                });
            });
        }
        
        // 重新绑定保存按钮事件
        const saveButton = document.getElementById('save-button');
        if (saveButton) {
            saveButton.disabled = false;
            
            // 添加保存按钮的点击事件监听器
            saveButton.addEventListener('click', function() {
                console.log('保存按钮被点击');
                
                // 尝试从会话存储获取数据
                let testCases = null;
                try {
                    testCases = JSON.parse(sessionStorage.getItem('generatedTestCases') || '[]');
                } catch (error) {
                    console.error('解析测试用例数据失败:', error);
                    alert('解析测试用例数据失败，请查看控制台获取详细信息');
                    return;
                }
                
                if (!testCases || testCases.length === 0) {
                    alert('没有可保存的测试用例');
                    return;
                }
                
                // 获取其他必要数据
                const requirementElement = document.getElementById('input-text');
                const llmProviderElement = document.getElementById('llm-provider');
                
                if (!requirementElement || !llmProviderElement) {
                    console.error('缺失必要的页面元素');
                    alert('页面元素缺失，无法保存数据');
                    return;
                }
                
                // 准备请求数据
                const requestData = {
                    test_cases: testCases,
                    requirement: requirementElement.value,
                    llm_provider: llmProviderElement.value
                };
                
                // 禁用按钮防止重复提交
                saveButton.disabled = true;
                saveButton.textContent = '保存中...';
                
                // 发送保存请求
                fetch('/core/save-test-case/', {
                    method: 'POST',
                    headers: {
                        'X-CSRFToken': getCookie('csrftoken'),
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(requestData)
                })
                .then(response => response.json())
                .then(data => {
                    saveButton.textContent = '保存测试用例';
                    
                    if (data.success) {
                        alert('测试用例保存成功！');
                        // 清除会话存储
                        sessionStorage.removeItem('generatedTestCases');
                        sessionStorage.removeItem('inputText');
                    } else {
                        saveButton.disabled = false;
                        alert('保存失败：' + (data.message || '未知错误'));
                    }
                })
                .catch(error => {
                    saveButton.disabled = false;
                    saveButton.textContent = '保存测试用例';
                    console.error('保存失败:', error);
                    alert('保存失败，请查看控制台获取详细信息');
                });
            });
        }
    }
    
    // 获取CSRF Token的辅助函数
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }
    
    // HTML转义函数
    function escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    }
});