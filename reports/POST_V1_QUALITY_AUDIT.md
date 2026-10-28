# 第二轮 V1.0.1 输入校验修复 — B

2026-10-28。本轮只处理上一轮遗留缺陷，不改变R001及V0.7/V0.8/V0.9/V1.0研究边界。

## 基线及原工作区保护

原目录 main / HEAD `b95fa321983bd1cffcf4face53334a91e29ddb74`。50项均为未暂存的已跟踪修改，新文件0、删除0、其他0。路径、状态、逐文件SHA-256保存在仓库外 `audit-round2/B_ORIGINAL_WORKTREE.json`。结束时逐项对比完全不变。未stash/clean/reset/覆盖/提交未知修改。

新worktree `/mnt/d/Cybersecurity-Portfolio/security-log-analyzer-v101` 从原HEAD建立，分支 `improve/v101-input-validation`。原目录未新增未知文件。v1.0.0 annotated Tag对象 `eb77af1b5631a0ca089c9d18b96c57fff240310e` 解引用为上述HEAD，未改动。只有新worktree分支产生提交。

## 已确认缺陷与修复

|ID|优先级/状态|位置|解释、影响与修复|
|---|---|---|---|
|B-001|P1 Confirmed/FIXED|src/log_analyzer/zeek_parser.py normalize_record|bool经float变为0/1，制造伪时间；显式排除bool及非int/float/str类型。合法秒数仍可有小数并输出UTC|
|B-002|P1 Confirmed/FIXED|同文件port_value|int截断小数或接受bool，污染端口证据；仅接受严格int或ASCII十进制字符串，范围0..65535；显式畸形值报ZeekParseError，缺失/null/空字段仍未知|
|B-003|P2 Confirmed/FIXED|同文件decoded_lines/parse_zeek|非法UTF-8溢出CLI异常处理；严格解码并转换为带路径及UTF-8诊断的ZeekParseError，CLI退出1，无traceback，不替换字节、不改变输入或已有输出|

JSON的445.0不是整数类型，拒绝；数字时间戳1760000000.25仍有效。ASCII unset先转换None。Windows已有bool/float端口和非字符串时间戳拒绝；Linux公开适配器通过正则限定整数端口文本，时间戳需显式时区；schema要求严格整数端口，correlation要求字符串时间。新增测试确认这些入口，无需改动其源码。检测条件没有放宽。

## 失败回归及实际验证

原基线380/380 PASS。先新增16项 `tests/test_input_contract_v101.py`：旧实现产生23个子测试失败、2个错误（不是25个测试方法），记录在仓库外 `audit-round2/B_REGRESSION_BEFORE.txt`。修复后16/16 PASS，全套396/396 PASS，优化模式396/396 PASS。本机3.12.3，3.11 NOT RUN。

覆盖：bool及其他异常时间戳、合法小数秒、两端bool/小数端口、类型和范围、0/65535边界、ASCII unset、非法UTF-8、CLI诊断/退出码/输入及输出不变、Windows/Linux/schema/correlation入口。

V0.4两项数据哈希与manifest匹配。历史数据/结果/文档不变；现有研究和性能断言通过。V1.0合成benchmark三次测量：32/320/1600事件分别6/60/300候选；候选不是已证实会话或攻击。

5000条正常合成JSON日志，基线/当前解析结果逐项相同；5轮中位时长约0.079/0.075秒。仅此次小样本未观察明显退化，不声称性能提高或生产吞吐。原始测量在仓库外 `audit-round2/B_PARSER_PERFORMANCE.json`、`B_SYNTHETIC_PERFORMANCE.json`，未改历史benchmark。

复用原 `.github/workflows/tests.yml`，仅增加优化模式输入回归步骤，保留3.11/3.12矩阵和只读权限。YAML及两个run块Bash语法PASS；70个Python AST检查PASS，git diff --check PASS。云端CI、生产性能及真实认证环境验证NOT RUN。

## 候选结论

达到本地离线v1.0.1候选标准，可审查本地提交；未达到发布门禁：需3.11/3.12云端CI、评审更严格输入契约，并确认原脏工作区如何整合。NAT/共享IP、未知端口及热点键性能限制仍保留。修改仅解析器、新测试、原CI、本报告，无新运行依赖，无Push/Merge/Tag/Release。
