# sqlmap GUI

一个基于 sqlmap REST API 的 Web 图形界面,解决"命令难记、插件不会用"的问题。

## 快速启动

```bash
cd /path/to/sqlmap-master
python3 gui/launcher.py
```

启动后浏览器打开 http://127.0.0.1:8966 即可。Ctrl-C 停止。

启动器会自动:
1. 拉起 sqlmap 的 REST API 服务(`sqlmapapi.py`,端口 8775),并生成随机密码
2. 在 8966 端口提供 Web 前端
3. 通过同源代理 `/api/*` 转发请求,前端无需关心认证和 CORS

使用教程:
第一步从https://github.com/sqlmapproject/sqlmap官网下载sqlmap
第二步从https://github.com/saixiansheng110/sqlmap-gui/tree/main下载gui
第三步将gui目录放在解压好的sqlmap一级目录中与sqlmap.py同一级
<img width="416" height="238" alt="image" src="https://github.com/user-attachments/assets/c9f21547-a1eb-4855-b86e-22d36e81f914" />

进入sqlmap目录使用python3 gui/launcher.py

<img width="416" height="129" alt="image" src="https://github.com/user-attachments/assets/8e7186f9-7b71-436f-bd79-a5c3ead7dad6" />

访问http://127.0.0.1:8966

<img width="416" height="221" alt="image" src="https://github.com/user-attachments/assets/399876d1-56e4-4f56-910b-da49947d9bb8" />

这个是全部脚本

<img width="416" height="221" alt="image" src="https://github.com/user-attachments/assets/a023534d-4fd5-4136-b18d-67440e402da1" />

测试sqlmap-labs第20关cookie注入

<img width="416" height="221" alt="image" src="https://github.com/user-attachments/assets/315bc390-878c-4e9c-b06f-5dd75d4226a9" />

<img width="416" height="162" alt="image" src="https://github.com/user-attachments/assets/f9a44466-72ab-4b48-aa38-c54bae12aac2" />

<img width="416" height="122" alt="image" src="https://github.com/user-attachments/assets/b9ed2a5a-3101-4564-9cb8-362e54879724" />

<img width="416" height="207" alt="image" src="https://github.com/user-attachments/assets/4a255316-3bad-42c2-801d-df723b43f2a7" />

<img width="416" height="189" alt="image" src="https://github.com/user-attachments/assets/6c3c525b-97db-4fe9-a28e-6fd3d0e034b8" />
## 功能模块

| 页面 | 说明 |
|------|------|
| 新建扫描任务 | 分组表单(目标/检测/枚举/请求优化),底部实时生成等价 `sqlmap.py` 命令,带"快速检测""全量枚举"预设模板 |
| 任务管理 | 多任务并行总览,统计运行中/已结束数量,批量停止/刷新/删除,每任务卡片带状态徽章和操作按钮 |
| 运行监控 | 扫描状态(running/terminated)、实时日志流、停止/强制结束 |
| 结果面板 | 目标画像卡(DBMS/用户/库/是否DBA)、注入点卡片(6 种技术+payload)、数据库结构树(点表名 dump)、用户权限矩阵 |
| 后渗透 | 文件读写/OS命令/OS Shell/注册表/UDF 六大操作,带二次确认弹窗(含操作理由)和审计日志 |
| 报告导出 | 基于 `/scan/<id>/data` 生成 Markdown/HTML/JSON 报告(含目标/注入点/结构/用户/审计),支持导出文件下载 |
| tamper 选择器 | 84 个绕过脚本,带优先级、描述、搜索筛选,勾选即加入 `--tamper` |

## 解决的两个痛点

1. **命令难记** → 分组表单 + 实时命令预览 + 预设模板。填完表单可把生成的命令复制到终端手动跑。
2. **插件不会用** → tamper 选择器带说明;DBMS 下拉带说明;枚举树浏览器点哪取哪;注入点卡片引导下一步。

## 文件结构

```
gui/
├── launcher.py        # 启动器:拉起 sqlmapapi + Web 服务 + API 代理
└── web/
    ├── index.html     # 单页前端(配置/运行/结果/tamper 四个页面)
    └── tampers.json   # 84 个 tamper 脚本的元数据(名称/优先级/描述)
```

## 技术要点

- **后端零侵入**:直接用 sqlmap 自带的 `sqlmapapi.py` REST API,不改动 sqlmap 任何代码
- **结构化结果**:`/scan/<id>/data` 返回按 CONTENT_TYPE 分类的 JSON,前端直接渲染,不解析终端文本
- **API 代理**:launcher 用 `http.client` 转发,绕开 bottle wsgiref 适配器对 urllib keep-alive 的兼容问题

## 合规提示

本工具用于**授权渗透测试**。启动扫描前请确认目标在授权范围内;后渗透功能(文件读写、OS 命令、UDF)高风险,务必二次确认。
