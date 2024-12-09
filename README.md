# jwt_sec

jwt自动化测试，放入请求的URL、jwt和请求参数，自动化测试jwt，先原始访问，再未授权访问，再jwt的alg改为none测试，最后再jwt爆破测试。

测试webgoat靶场。

正常提交token会提示用户不对，需要伪造成WebGoat用户访问。
![webgoat1](https://github.com/user-attachments/assets/24c4b9f2-59f8-4249-9e20-0a55445928b1)

使用工具测试并伪造。
![webgoat2](https://github.com/user-attachments/assets/6110310b-7dea-4f0a-94ac-bdcae03faa06)
