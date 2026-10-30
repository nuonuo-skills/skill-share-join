# Skill Share 自助加入入口

此公开仓库仅处理加密的入库申请；Skill 内容保存在独立私有共享库中。

成员使用安装助手并输入管理员发放的邀请码。助手用当前 GitHub 身份提交加密申请，自动程序核对后发送 Read 邀请；安装助手随后接受指定仓库的邀请并继续连接。成员无需逐个联系管理员。

**不要在公开 Issue、评论或日志里填写邀请码、令牌、密码或私钥。** 请由安装助手生成完整加密申请。公开申请会显示申请者的 GitHub 用户名和处理记录。

## 管理员一次性配置

使用共享助手的管理向导部署此模板，生成 `.github/skill-share/join-policy.json` 和独立的请求加密密钥。配置记录目标库与入口库的名称、固定数字 ID、请求公钥及 keyId；可选 `deniedUserIds` 阻止已移除账号重新加入。

将专用 GitHub App 仅安装到目标私有共享库，授予仓库 `Administration: write`。App 用于发送 Read 邀请，不申请 Contents 写入权限。App 签名私钥与请求解密密钥分别维护。

仅在此入口仓库配置以下 Actions Secrets：

| Secret | 用途 |
| --- | --- |
| `APP_ID` | 专用 GitHub App ID |
| `APP_PRIVATE_KEY` | App RSA 签名私钥 |
| `ENROLLMENT_PRIVATE_KEY` | 独立 X25519 请求解密私钥 |
| `ENROLLMENT_CODES_JSON` | 邀请码记录数组：`id`、十六进制 `salt`、32 字节 scrypt `hash`、`expiresAt`、`enabled` |

邀请码哈希规则：`scryptSync(code, Buffer.from(salt, 'hex'), 32)`；每个盐至少16字节。原始邀请码仅发送给获准加入的成员，不提交到本仓库。过期或禁用的邀请码不能加入。更新 hash/盐可轮换邀请码。

## 自动处理与恢复

工作流仅处理 `issues: opened`，只读取默认分支可信事件 SHA 的程序，不执行申请者提交的代码。请求绑定实际 GitHub 数字用户 ID、目标库、nonce、keyId，并在15分钟内有效。伪造身份、修改密文、已过期申请和无效邀请码统一拒绝，不输出解密错误或邀请码。

工作流先检查现有权限和待接受邀请，已有访问直接返回成功，不降低权限。仅在不存在访问或邀请时发送 `pull` 邀请。网络结果不确定时先查询现有状态；无法确认则保留申请供重试，不宣称邀请成功。确定结果写入官方 bot 回执后自动关闭 Issue。安装助手只接受真实 `github-actions[bot]` 的匹配回执。

应保持组织允许此仓库运行 Actions，且不给此工作流增加人工审批 environment。公开 Issue 工作流不采用首次 fork PR 的批准流程。未收到处理结果时核对 Actions 状态，重试原请求，避免重复提交。

GitHub 对每个仓库24小时内的外部协作者邀请有限额；受限时需等额度恢复。管理员仍可停止工作流、禁用邀请码、移除成员或撤销 App。移除成员后，将其数字用户 ID 加入 `deniedUserIds`，防止其凭仍有效的邀请码再次加入。

本仓库公开不等于 Skill 库公开；任何持有有效邀请码的人都能申请加入，请按实际成员范围发放邀请码。
