# sf/ — stalefuzz QEMU fork 架构文档(权威 · 中文)

> 本文件是 `sf/`(stalefuzz 在 QEMU v11 自有 fork 内的 restore 引擎)的**架构真相源**。
> 目的:让维护者不必逐行读代码就能理解**目标、设计思路、模块分工、关键决策与现状**。
> 代码变了就来更新本文件(随代码走的活文档)。上层研究背景见主仓
> `research/plans/2026-07-04-02-m0s-restore-spike-design.md`(设计 spec)与
> `research/plans/2026-07-04-03-m0s-restore-spike-impl-plan.md`(实现计划,进度真相源)。

## 1. 目标(M0-S restore spike)

在 QEMU v11 的自有 fork 里,用**干净模型**证明两件事,作为整套 fresh-backend 的可行性闸:

1. **快**:单 VM 的 restore(回退到快照点)≤ ~3.5ms(= 2× Nyx 基线 1.77ms,见 `research/log/2026-07-04-02-m0-nyx-baseline.md`)。restore 延迟直接决定 fuzzing 的 races/s,是一等指标。
2. **对**:restore 正确性 selftest 在故障注入下**必须变红**(有辨别力),正常路径全绿。含老 Nyx 漏过的 ring-full 链。

非目标(本 spike 不做):N=64 并行、blind 快路径工程化、时间冻结的完整实现、真集群、M1 的 channel/oracle-harness。

## 2. 设计思路(为什么这么做)

- **预解析一次 / 回放多次**:设备状态的 stock 迁移路径(`vmstate_load_state`)每次都要重新解析 VMSD 树、跑每个字段的 `info->get`。我们**只解析一次**,把"每个字段该落到哪块内存 / 该重放哪个副作用 / 该跑哪个 hook"压成**三张扁平表**,之后每次 restore 只重放表 → 省掉重复解析开销。
- **RAM 脏页显式策略**:哪些页 restore 后重保护是**显式策略**而非隐式副作用——hot 页(不进 ring、无条件回拷)、cold 页(ring 追踪 + 回拷后重保护)。**ring-full 是一等状态、零丢页**(老 Nyx 在这条链上出过错)。
- **blind = reprotect 策略**:blind 不是独立机制、不依赖时间冻结(I.3);它就是"这批页选择性重保护"的一个策略取值。
- **clean-room 不照搬 Nyx**:`sf/` 不叫 `nyx/`、不 include 任何 Nyx 头、不逐行搬 Nyx。Nyx(`vendor/nyx/QEMU-Nyx/nyx/snapshot/devices/state_reallocation.c`)**只读思想不搬码**——它验证了"三表 + 带记录真加载"的配方可行,我们据此在 v11 上干净重写。
- **selftest 有辨别力**:接口存在性测试不写;每个 selftest 用例必须能在故意破坏时变红。

## 3. 与 stock QEMU 的关系 / 改动面

`sf/` 是**新增子目录**,源码编进 `system_ss`(见 `sf/meson.build` + 顶层 `meson.build` 的 `subdir('sf')`)。对 stock 代码的侵入**集中成一个 patch**:`sf/patch/unstatic-vmstate.patch`(DP-C1),内容 = 把 restore 引擎需要的内部符号暴露出来,便于日后 rebase v11:

| 暴露的符号 | 出处 | 用途 |
|---|---|---|
| `vmstate_n_elems` / `vmstate_size` / `vmstate_handle_alloc` | `migration/vmstate.c`(去 static)+ `include/migration/vmstate.h`(extern) | 预解析时算数组元素数 / 字段字节数 / 处理 VMS_ALLOC |
| `sf_savevm_for_each_vmsd(visit, user)` | `migration/savevm.c` | 回调迭代 `savevm_state.handlers`,拿每个 section 的 `(idstr, instance_id, vmsd, opaque)`,**不泄漏 `SaveStateEntry` 布局** |
| `sf_qemu_file_input_pos` / `sf_qemu_file_input_bufsize` | `migration/qemu-file.c/.h` | 读 input QEMUFile 的 buf 读位 / fill 大小,用来量每个 get 字段消费了多少流字节 |

触发面只用 **HMP**(`hmp-commands.hx` 注册 `sf_snapshot` / `sf_restore` / `sf_selftest`,声明在 `include/monitor/hmp.h`);不碰 oracle-harness / rsdrv / channel(那是 M1)。

## 4. 模块划分(`sf/` 目录)

```
sf/
├── ARCHITECTURE.md          本文件
├── sf.h / sf.c              HMP 入口(hmp_sf_snapshot / _restore / _selftest),粘合各模块
├── meson.build             sf 源集,并入 system_ss
├── patch/unstatic-vmstate.patch   DP-C1:对 stock 的全部暴露改动(rebase 用)
├── vmstate_replay/         设备状态:预解析一次 / 回放多次
│   ├── buffer.{c,h}        内存 buffer <-> QEMUFile(QIOChannelBuffer,替代 v11 已删的 qemu_fopen_ops)
│   ├── preparse.{c,h}      带记录的真加载 → 三表(SfMblock / SfGet / SfPost)
│   └── replay.{c,h}        [Task5] 重放三表 + 对拍 stock qemu_load_device_state
├── dirty/                  [Task6] RAM 脏页引擎:hot/cold 策略 + collect/restore/reset + ring-full
│   └── engine.{c,h}
├── clock/                  [Task9] 跨 restore 时钟矩阵测量(rdtsc/kvmclock/clock_gettime)
│   └── probe.{c,h}
└── selftest/               [Task7] 故障注入自检(HMP sf_selftest 汇总用例①–⑤)
    └── selftest.{c,h}
```

主仓侧(不在 fork 内):`tools/sf-rig/` [Task8] 独立微型 rig(微 guest 两档负载 fast/dbsim + QMP 驱动 + 单VM 延迟对拍)。

### 4.1 设备状态回放(`vmstate_replay/`)—— 已实现 Task3–4

**三表**(`preparse.h`):
- `SfMblock { ptr, copy, size }` —— 一段设备内存,restore 时 `memcpy(ptr, copy, size)` 拍回。相邻自动合并成大块(少 memcpy 次数)。
- `SfGet { info, field, ptr, captured, captured_len, size }` —— 有副作用的字段(timer/tmp/…),restore 时对 `captured` 原始流字节重跑 `info->get` 重放副作用(重挂定时器等)。
- `SfPost { vmsd, opaque, is_pre, version_id }` —— pre_load / post_load hook,restore 时按序重跑。

**预解析 = 带记录的真加载**(`sf_preparse`,`preparse.c`):
1. `global_state_store()` 补当前 runstate(否则 globalstate 的 post_load 拒空)。
2. `qemu_save_device_state` 把当前设备态存进 Task3 的 output buffer → reopen 成 input。
3. clean-room 走流:`sf_record_vmsd`(镜像 `vmstate_load_state`)+ `sf_record_subsections`(镜像 `vmstate_subsection_load`)+ FULL-section 读头循环(`find_se` 用 Task2 迭代器建 `(idstr,inst)->(vmsd,opaque)` 查表)。
4. 每个字段**先跑 stock `info->get`**(流→内存、端序转好、副作用发生),再按类型登记:标量/buffer→mblock;timer/tmp/…→get;跳过 unused_buffer/nullptr。pre/post_load 走一遍并记表。

**回放顺序**(Task5 `sf_replay`,配方同 Nyx `fdl_fast_reload`):pre_load hooks → memcpy 所有 mblock → 重放所有 get → post_load hooks。

## 5. 关键设计决策(有争议 / 易踩坑,单独记)

- **端序**:迁移流是**大端**编码,设备内存是**主机端序**;`info->get` 同时做反序列化+端序转换+副作用。故 **mblock.copy 一律从 get 之后的内存取**(不是流字节),端序天然正确。这也是"mblock = 跳过 get 直接 memcpy"的唯一自洽读法。证据:Nyx `state_reallocation.c:416`。
- **走流方式 = 带记录的真加载**(人类 2026-07-04 定):不自己啃流字节的分帧,而是跑一遍真 load 顺手记表。代价:snapshot 时刻会把设备副作用(如 `timer_mod`)以相同值再触发一次;M0-S 接受。
  - **[PLANNED FEATURE / 提速方向,人类提]**:未来若要压 snapshot 延迟,研究**绕开 save→load 往返**,直接就地从设备内存 + VMSD 元数据取三表(免序列化/反序列化)。后置优化,依赖先跑通正确路径。
- **mblock.copy 抓取时机**:必须在 walk 中**逐字段即时抓、在该 section 的 post_load 之前**(抓的是 mem_raw);replay 再重跑 post_load 还原 mem_final。这样非幂等 post_load 也对。放到 walk 后统一抓 = 错(抓成 post_load 之后的值)。
- **单 buffer 假设**:量 get 字节数依赖"整条设备流一次 fill 装完"(buf_index 即绝对读位)。microvm 设备流 <32K 成立;`sf_preparse` 有硬断言,超了会报错提示需泛化。

## 6. 构建 / 触发 / 测试

- **build dir**:`/data/nvme2/db2/stalefuzz/build/qemu-v11.0.0`(已 configure)。增量编:`ninja -C <builddir> qemu-system-x86_64`(改 meson 会自动 reconfigure)。非交互 shell 先 `. "$HOME/.cargo/env"`。
- **快测 HMP**(无需 guest,microvm 设备/section 远少于 pc):
  `printf 'sf_snapshot\nquit\n' | ./qemu-system-x86_64 -M microvm -accel tcg -S -display none -nodefaults -monitor stdio`
- **单测**:`sf/vmstate_replay/buffer` 挂在 `tests/unit/test-sf-buffer`(纯 host,`ninja tests/unit/test-sf-buffer` 后跑二进制)。
- **提交纪律**:C 代码 commit 到本 submodule(分支 `sf-m0s-restore-spike`),再更主仓 gitlink;每步回填计划 checkbox。

## 7. 现状(逐 Task)

| Task | 内容 | 状态 | submodule commit |
|---|---|---|---|
| 1 | sf/ 骨架 + HMP 触发 + 构建接通 | ✅ | `0ee6723` |
| 2 | DP-C1 un-static + handlers 迭代器 | ✅ | `d056288` |
| 3 | buffer <-> QEMUFile helper(5 单测绿) | ✅ | `116947e` |
| 4 | 三表预解析(microvm:mblocks=119/gets=10/posts=14) | ✅ | `07c60d2` |
| 5 | 三表重放 + 对拍 stock load(selftest ⑤) | ⏳ 待做 | — |
| 6 | 脏页引擎 hot/cold + ring-full | ⏳ | — |
| 7 | restore 正确性 selftest ①–④ | ⏳ | — |
| 8 | 微型 rig + 单VM 延迟对拍(**门槛判定**) | ⏳ | — |
| 9 | 时钟矩阵 | ⏳ | — |
| 10 | 收口报告 | ⏳ | — |

> 进度权威在实现计划的 checkbox;本表是速览,更新时两处同步。
