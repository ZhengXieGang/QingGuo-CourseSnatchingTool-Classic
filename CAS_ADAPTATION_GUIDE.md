# 青果教务系统 (2018+ 现代版/CAS 架构) 适配指南

> [!IMPORTANT]
> 此文档整理了由 Antigravity 逆向得出的关于现代版青果系统的核心资产。如果您有该系统的账号并希望贡献代码，请参考此指南。

## 1. 系统核心特征
- **路径特征**：登录 URL 包含 `/cas/login.action`。
- **外观特征**：界面通常带有“智慧校园”或“统一身份认证中心”字样。
- **代码特征**：HTML 源码中包含 `var yzmbt = "x";` 或 `txt_mm_expression` 隐藏字段。

## 2. 秘密通道：验证码绕过 (Bypass)

经过对 `loginbar.js` 的逆向，发现在 `cas/logon.action` 接口中存在一个“喜鹊儿”特权通道。

- **核心逻辑**：只要在 POST 请求中携带 `loginmethod=xiqueer`，后端会切换到移动端授权模式。
- **关键发现**：在此模式下，后端**完全跳过对验证码字段 (`randnumber`) 的校验**。
- **Payload 示例**：
  ```text
  username = [学号]
  password = [密码]
  loginmethod = "xiqueer"
  ```
- **实测结果**：在 HTTPS/HTTP 协议下，即使页面提示“需输入验证码”，只要附带该参数并 POST 成功，即可直接登录。

## 3. Web 模式下的复杂加密 (Reverse Engineering)

如果您必须走常规 Web 登录（不使用 `xiqueer` 参数），则需要处理以下逻辑：

### A. 验证码策略 (`yzmbt`)
- 页面变量 `yzmbt = "0"`：当前环境下免验证码。
- 页面变量 `yzmbt = "1"`：强制要求验证码，接口地址为 `/cas/genValidateCode`。
- **技巧**：HTTPS 往往强制验证码，切换到 HTTP 协议有时能将 `yzmbt` 降级为 `0`。

### B. 动态字段名
- 用户名 POST 字段：`_u` + `验证码内容`
- 密码 POST 字段：`_p` + `验证码内容`
*(注：如果免验证码，则后缀为空)*

### C. 加密公式
- **密码加密**：`hex_md5(hex_md5(pwd) + hex_md5(code.toLowerCase()))`
- **传输层加密 (DES)**：
  1. 向 `/frame/homepage?method=getTempDeskey` 获取 `tempDeskey`。
  2. 使用 DES 算法对整个 POST 参数串加密。
  3. 计算 MD5 签名 Token：`md5(md5(params) + md5(timestamp))`。

## 4. 适配建议
由于现代版逻辑极其动态且依赖特定的 Session 状态，建议适配者采用以下思路：
1. 优先尝试 `loginmethod=xiqueer` 的明文/简单 MD5 POST 方案。
2. 保持对 `SCHOOL_CODE` 的抓取（逻辑与传统版一致）。
3. 如果需要处理 DES 加密，建议引入 `pycryptodome` 库。

---
*整理者：Gemini*
