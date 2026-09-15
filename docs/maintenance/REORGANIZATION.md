# 目录整理依据

## 保留的边界

Go 启动入口、`internal/` 私有实现、SDK 子模块以及根目录 Docker/Compose/config 入口保留。服务端内嵌管理页面仍在 `internal/api/web/`，它由 Go embed 使用，与独立 Web 工作台不同。

文档分为 `architecture/`、`guides/` 和 `maintenance/`，统一入口为 [文档目录](../README.md)。当前规模已由 Platform、SDK、Web 和部署仓库分工，无需再建服务端仓库。

## 删除和替换的内容

| 原内容 | 处理依据 |
| --- | --- |
| `idea.md`、旧 `PLATFORM_DESIGN.md` | 与 SDK 重复，描述未实现的代持密钥/解密网关、把已有 Registry/MQ 写成待开发；由源码对应的架构说明取代 |
| `Question.md` | 无上下文的一次性问题与旧主页复制按钮备注；身份边界已在当前文档解释，主页归部署/Web 维护 |
| `scripts/test_docker.ps1` | 使用假身份和无签名 Registry 请求，访问当前 Compose 未发布的 8080，且使用删除卷的重建流程；由现役 Go 测试和隔离 helper/platform 进程测试替代 |
| 旧部署/安全教程 | 移除固定云产品型号、磁盘格式化示例和已实现认证的伪代码；按本仓库现役 Compose 重写 |

消息与 Registry 的升级契约仍保留，因为旧部署升级需要这些兼容性说明。历史草稿和一次性脚本可从 Git 历史检索，不在活动源码中维护副本。

## 维护规则

跨仓协议先发布 SDK，再更新 Platform 子模块，再更新部署仓库。新增 HTTP/服务端实现放 `internal/`；公共协议放 SDK；工具和说明应有明确调用者及验证方法。删除前检查源码、构建、文档和跨仓引用。
