# IEC 60870-5-104 会话取证核验服务

面向变电站取证场景的会话核验 API。抓包工具可以逐帧解析 IEC 104 报文，但
双向确认号失序、传输阶段错乱等问题会让遥控记录不可采信。本服务对一段按
采集时间排序的完整会话做**有状态核验**：任何违反协议时序的帧都会被定位，
合法会话则输出可用于取证报告的统计数据。

## 快速开始

```bash
# 一键核验：构建镜像、启动 API（含健康检查）、运行 verify 一次性服务。
# verify 依次核对代码测试、镜像构建、合法/非法会话冒烟，并以退出码报告结果。
docker compose up --build --exit-code-from verify
echo $?   # 0 = 全部通过，1 = 存在失败项

# 仅启动 API（宿主机端口可通过 API_PORT 配置，默认 8080）
API_PORT=9000 docker compose up --build -d api
curl http://127.0.0.1:9000/health
```

清洁环境下建议先 `docker compose down -v` 再执行核验。

## API

### `POST /api/iec104/sessions/audit`

请求体：

```json
{
  "maxUnackedWindow": 12,
  "frames": [
    {"capturedAtUs": 1000000, "direction": "clientToServer", "apduHex": "680407000000"},
    {"capturedAtUs": 1001000, "direction": "serverToClient", "apduHex": "68040B000000"}
  ]
}
```

* `frames`：1–5000 帧，必须按 `capturedAtUs`（微秒）**非递减**排列；
* `direction`：`clientToServer` 或 `serverToClient`；
* `apduHex`：完整 APDU 的十六进制（起始符 `68`、长度、控制域、无尾随字节）；
* `maxUnackedWindow`：最大未确认窗口 k，1–16383。

合法会话（HTTP 200）：

```json
{
  "verdict": "VALID",
  "stats": {
    "perDirection": {
      "clientToServer": {"iFrames": 2, "unacked": 0},
      "serverToClient": {"iFrames": 1, "unacked": 0}
    },
    "handshakes": {
      "startdt": {"act": 1, "con": 1},
      "stopdt":   {"act": 1, "con": 1},
      "testfr":   {"act": 1, "con": 1}
    }
  },
  "error": null
}
```

非法会话（HTTP 200，**首次违规即终止**，不含后续裁决）：

```json
{
  "verdict": "INVALID",
  "stats": null,
  "error": {
    "code": "WINDOW_EXCEEDED",
    "frameIndex": 3,
    "message": "clientToServer leaves 2 unacknowledged I frame(s), window allows at most 1"
  }
}
```

请求本身不合法（帧数越界、窗口越界、时间戳倒序、字段缺失等）返回
HTTP 400：`{"error": {"code": "INVALID_REQUEST" | "FRAMES_NOT_ORDERED", ...}}`。

### `GET /health`

返回 `{"status": "ok", "service": "iec104-session-audit", "version": "..."}`，
供 Docker Compose 健康检查与 verify 的镜像一致性核对使用。

## 核验规则

1. **APDU 结构**：起始符必须为 `0x68`；长度域须能容纳 4 字节控制域且与
   实际字节数完全一致（不允许截断或尾随字节）；仅接受控制域合法的
   I/S/U 三种格式（S/U 长度必须为 4，保留位必须为 0，U 格式须且仅须
   置一个功能位）。
2. **发送序号**：两个方向的 I 帧发送序号均从 0 开始连续编号（单次核验
   至多 5000 帧，远小于 32768 模数，不存在回绕歧义）。
3. **确认号**：不得倒退；不得越过对端已发送的 I 帧数；任一 I 帧发出后，
   该方向未确认数不得超过 k。
4. **握手配对**：STARTDT / STOPDT / TESTFR 的每个 `act` 必须由**相反方向**
   的 `con` 应答；`act` 未确认前不得重复发起；会话结束时不得遗留未配对
   的 `act`（报错定位于该 `act` 帧）。
5. **传输阶段**：I 帧只能出现在 STARTDT 握手完成（已确认）且 STOPDT 握手
   尚未完成的阶段；STOPDT 完成后允许再次 STARTDT 重启传输。

核验按采集顺序逐帧进行，遇到首个违例即终止，因此报告的下标永远是
**最早受影响帧**。

## 稳定错误码

| 代码 | 含义 |
| --- | --- |
| `APDU_HEX_INVALID` | 非偶数长度十六进制串 |
| `APDU_START_BYTE` | 起始符不是 `0x68` |
| `APDU_LENGTH` | 长度域非法 / 截断 / 尾随字节 |
| `APDU_CONTROL` | 控制域非法（S/U 长度、保留位、U 功能位） |
| `SEQ_MISMATCH` | I 帧发送序号不连续 |
| `ACK_REGRESSION` | 确认号倒退 |
| `ACK_BEYOND_SENT` | 确认号越过对端已发送数据 |
| `WINDOW_EXCEEDED` | 未确认窗口超过 k |
| `I_NOT_STARTED` | 启动未确认前出现 I 帧 |
| `I_STOPPED` | 停止确认后出现 I 帧 |
| `HANDSHAKE_ACT_REPEATED` | act 未确认前重复发起 |
| `HANDSHAKE_CON_WITHOUT_ACT` | con 无对应 act |
| `HANDSHAKE_SAME_DIRECTION` | con 与 act 同方向 |
| `HANDSHAKE_UNPAIRED_ACT` | 会话结束仍有未配对的 act |
| `FRAMES_NOT_ORDERED` | 帧未按采集时间非递减排列（HTTP 400） |
| `INVALID_REQUEST` | 请求体违反契约（HTTP 400） |

## verify 一次性服务

`verify` 与 `api` 共用同一镜像，在 `api` 健康检查通过后执行三步核验，
全部通过以退出码 0 结束，否则为 1：

1. **代码测试**：镜像内运行 `pytest` 套件（APDU 解析、状态机、HTTP API）；
2. **镜像构建**：`docker compose --build` 完成两个服务的镜像构建，verify
   再核对 `api` 容器 `/health` 报告的版本与源码版本一致；
3. **冒烟**：对在线 API 各发起一例合法会话（校验统计输出）与多例非法
   会话（校验错误码与帧下标），以及一例 400 契约校验。

## 本地开发

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q                    # 单元/接口测试
.venv/bin/python -m uvicorn app.main:app --port 8080
API_BASE_URL=http://127.0.0.1:8080 .venv/bin/python verify.py
```

## 目录结构

```
app/
  apdu.py     # APDU（APCI）解析
  audit.py    # 有状态会话核验（序列号、确认号、窗口、握手、阶段）
  models.py   # 请求/响应模式
  main.py     # FastAPI 入口与错误处理
tests/        # pytest 套件
verify.py     # 一次性核验服务入口
Dockerfile / docker-compose.yml
```
