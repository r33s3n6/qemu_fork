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
| `sf_kvm_dirty_ring_enabled` / `sf_kvm_collect_dirty` / `sf_kvm_dirty_reset_all` | `accel/kvm/kvm-all.c` + `include/system/kvm.h`(记录 `sf/patch/kvm-dirty-expose.patch`) | Task6 脏页引擎:drain 全部 vCPU dirty ring → 遍历 per-slot bitmap 交出每个脏页 host 地址 / 清 bitmap 起新一轮。需 KVMSlot 布局 + static reap,故实现落在 kvm-all.c |

触发面只用 **HMP**(`hmp-commands.hx` 注册 `sf_snapshot` / `sf_restore` / `sf_selftest`,声明在 `include/monitor/hmp.h`);不碰 oracle-harness / rsdrv / channel(那是 M1)。

## 4. 模块划分(`sf/` 目录)

```
sf/
├── ARCHITECTURE.md          本文件
├── sf.h / sf.c              HMP + terminal 入口(hmp_sf_snapshot / _restore / _selftest /
│                            _tree + sf_checkpoint_snapshot / _restore),薄胶水:vm_stop 拐杖 +
│                            debug-knob 解析;核心在 snap/
├── meson.build             sf 源集,并入 system_ss
├── patch/unstatic-vmstate.patch   DP-C1:对 stock 的全部暴露改动(rebase 用)
├── vmstate_replay/         设备状态:预解析一次 / 回放多次
│   ├── buffer.{c,h}        内存 buffer <-> QEMUFile(QIOChannelBuffer,替代 v11 已删的 qemu_fopen_ops)
│   ├── preparse.{c,h}      带记录的真加载 → 三表(SfMblock / SfGet / SfPost)
│   └── replay.{c,h}        [Task5] 重放三表 + 对拍 stock qemu_load_device_state
├── dirty/                  RAM 脏页引擎(机制层):collect/restore/reset + hot/cold + ring-full
│   └── engine.{c,h}        (已实现 Task6;M3 起 dirty engine 借用 root 节点 backing)
├── snap/                   [M3] 多层快照树(策略 + 存储层;设计 plans/2026-07-06-03)
│   ├── node.{c,h}          SfSnapNode 树生命周期 + SfBlockDesc 块表 + SfPageKey +
│   │                       SfRamStore(diff 存储) + sf_resolve(owner 解析,≤dst 最近 owner)
│   └── restore.{c,h}       sf_snap_save / sf_snap_restore / _delete / _tree + 时钟收尾
│                            (T1:只 root,RAM/device 委托 engine+preparse;T2/T3 上 diff+delta)
├── clock/                  [Task9] 跨 restore 时钟矩阵测量(rdtsc/kvmclock/clock_gettime)
│   └── probe.{c,h}
└── selftest/               故障注入自检(HMP sf_selftest 汇总用例①–⑤,已实现 Task7)
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

**回放顺序**(Task5 `sf_replay`):pre_load hooks → memcpy 所有 mblock → **重放所有 get** → post_load hooks。
> ⚠️ **与 Nyx 的关键差异(修它漏的链)**:Nyx 的 `fdl_fast_reload` 建了 get 表却**从不重放**(只 memcpy + pre/post hooks),等于跳过 timer 重挂。对我们不行——`QEMUTimer` 若被 memcpy 会拷进过期的 timerlist 链接指针;timer 必须走 `timer_get`→`timer_mod_ns` 重新入表。故 sf **一定重放 get**(timer 字段也因此归 get 表、不进 mblock)。

### 4.2 RAM 脏页引擎(`dirty/`)—— 已实现 Task6

**模型**(设计 spec §C,`engine.c`):
- `sf_dirty_snapshot`:开全局 dirty logging(一次)→ 遍历所有 RAMBlock 存**全量影子**(每块 `memcpy` 一份)→ drain + reset 起干净一轮。
- `sf_dirty_collect`:`sf_kvm_collect_dirty` 把脏页 host 地址 append 进**扁平 vector `g_dirty`**(非 hashtable——KVM dirty ring 每页每代只入一次,无需去重;从不查 membership,只 add/iterate/clear)。**实测:collect ~370µs 大头是 `kvm_dirty_ring_flush()` 的 drain+reprotect(∝脏页的内核活),vector 相对旧 GHashTable 只省 ~135µs 哈希那部分——reprotect 才是待治项(blind/keep-writable KVM 扩展)。**
- `sf_dirty_restore`:待恢复集 ∪ **所有 HOT 页**(无条件回拷)逐页 `memcpy(影子→host)`,返回回拷页数;清空待恢复集。
- `sf_dirty_reset_ring`:清 per-slot bitmap 起新一轮。
- `sf_reprotect_policy` / `sf_dirty_mark_hot`:hot/cold 策略表(默认 cold;key = host 页地址)。

**collect 从 per-slot bitmap 取,不读 live ring**(Task6 首个实现决策,见 §5)。HOT/COLD 在 stock KVM 6.8 下:所有 RAM slot 都被 track,HOT = "永远进待恢复集"的安全网,"永不进 ring"的快路径留 I.3 KVM 扩展。

**接进 HMP**(`sf.c`):`sf_snapshot` = RAM 影子(必成)+ 设备三表(best-effort,失败只告警不阻断,以免设备预解析的 KVM 缺口掩盖 RAM 结果);`sf_restore` = 设备重放(若有)→ collect → restore → reset。

### 4.3 故障注入自检(`selftest/`)—— 已实现 Task7

`sf_selftest_all`(HMP `sf_selftest`)汇总设计 spec §G 五用例,**每个 fault 注入必须被检出(有辨别力)**:

| 用例 | 内容 | teeth(注入→必红) | accel |
|---|---|---|---|
| ⑤ | replay 三表 vs stock load 逐字节对拍 | 篡改 `mblocks[0].copy` → 对拍 RED | TCG |
| ④ | get-handler(timer/tmp)重放正确 | 篡改 `gets[0].captured` → 对拍 RED | TCG |
| ① | guest 改 N 页 → restore 全回快照 | 内建(要求 changed>0 且 0 wrong) | KVM |
| ② | 丢一个脏页(`sf_dirty_inject_collect_skip`)→ 该页留错被检出 | 内建 | KVM |
| ③ | ring-full(4096 页 / 1024 ring)零丢 + 丢页被检出 | 内建 | KVM |

**accel 拆分(重要)**:设备对拍(④⑤)走 `qemu_load_device_state` 重载迁移流,**KVM 下会 assert(`kvm_put_apicbase`)**——把 CPU/apic MSR 经 ioctl 推回活 VM 太脆(重载第二次即崩)。设备对拍本质与 accel 无关且 Task5 已在 TCG 验证,故 `sf_selftest_all` 在 `kvm_enabled()` 时跳过 ④⑤;RAM ①②③ 需 KVM dirty ring。**一次 full pass = 两次触发**(TCG 拿 ④⑤ + KVM 拿 ①②③),见 `tools/sf-rig/README.md`。

**RAM 用例编排**:host 侧写 guest RAM 不经 KVM 写保护(不进 ring),故必须让 vcpu 真跑——selftest 内部 `vm_stop → sf_dirty_snapshot → vm_start + bql_unlock/usleep/bql_lock → vm_stop → collect+restore → 逐页核验`。负载 = `tools/sf-rig/guest/dirty.elf`(契约 BASE=0x300000/NPAGES=4096 硬编码在 `selftest.c`)。

**实测**(全 GREEN):①64/64 回滚;②丢页 wrong-after=1 检出;③4096 页改(>ring 1024)0 丢 + 丢页检出;③-info **跳过显式 drain 仍丢 0 页**(ring-full 退出 + 后台 reaper 冗余 drain;live-ring-only 会丢 ~3072——量化了本设计相对 Nyx 的价值);④gets=22 篡改检出;⑤对拍 + 篡改检出。

### 4.4 restore 正确性:in-kernel 状态恢复矩阵 —— 定案 2026-07-05

**真凶(2026-07-05 真实 TiDB rig 实测)**:不是"缺某个状态",而是**捕获/回放非自洽**。HMP 触发下 vcpu 在跑,10GB RAM 影子横跨数秒 + CPU 取自陈旧 CPUState 缓存 → 存下内部矛盾的快照,restore 一喂必崩(`#PF`/栈腐化,落点全在 timer/RCU/scheduler:`__hrtimer_run_queues`/`try_to_wake_up`/`rcu_core`)。**只 quiesce restore 不够**(仍崩);snapshot 与 restore 两侧都静止才活。→ coherence 是第一必需,机制见 §5。

**状态恢复矩阵**(microvm 实测 section:`apic/ioapic×2/kvmclock/kvm-tpr-opt/cpu/cpu_common/serial/fw_cfg/acpi-ged/timer/globalstate`):

| in-kernel 状态 | ① QEMU stock | ② Nyx fast_reload | ③ sf 最小集 |
|---|---|---|---|
| vCPU 寄存器/MSR/xsave/events/mp_state/nested | `cpu_synchronize_all_post_init`→`kvm_arch_put_registers(FULL_STATE)` | 同,`FULL_STATE_FAST`(略 `set_tsc_khz`)+ 略 debugregs + 单独 `set_tsc` | `cpu_synchronize_post_init` + **TSC 单独强制回拨**(见下)✅ |
| **LAPIC**(每vCPU中断控制器/定时器/IRR·ISR) | `apic` post_load→`KVM_SET_LAPIC` | 同(post_fptr 回放) | replay `apic` post_load ✅ |
| **IOAPIC×2** | `ioapic` post_load→`KVM_SET_IRQCHIP` | 同 | replay `ioapic` post_load ✅ |
| **kvmclock**(KVM 宿主 master clock) | `vm_start`→handler→`KVM_SET_CLOCK`+`KVMCLOCK_CTRL` | `call_fast_change_handlers` 显式 | **显式 `KVM_SET_CLOCK`**(kvmclock 无 post_load,唯一缺口) |
| **vapic/TPR 加速** | `kvm-tpr-opt` post_load + vapic handler(resume 重激活) | post_load | replay post_load + **保留 vapic handler 重激活**(TPR 性能,人类定 2026-07-05) |
| guest pvclock 页 | 随 RAM 回滚(+KVM 重刷) | 同 | 随 RAM 回滚 ✅ |
| PIT | `vm_start`→`KVM_SET_PIT2` | 显式 | N/A(`pit=off`) |
| CPU内部fixup / serial / fw_cfg / globalstate | 各自 post_load | 同 | replay post_load ✅ |

**pre_load(3个:kvmclock/apic/serial)**:纯 QEMU 结构体"设默认值"(`clock_is_reliable=false` / `wait_for_sipi=0` / `thr_ipending=-1`),无 KVM 副作用、幂等,重放保留。kvmclock 的含义 = "别信存下的 clock 标量,从内存 pvclock 页重推",与 RAM 回滚一致。

**为什么不用 `vm_start` 全 handler 扫**:实际注册的 handler 只有——kvmclock(补)、`cpu_update_state`(仅 `tsc_valid=false`,可忽略)、vapic(保留,TPR 性能)、`memory` dirty-log-stop(迁移用,与我方 dirty 引擎无关)、`blk`(无块设备)。故 **sf 最小集 = replay post_load + `cpu_synchronize_post_init` + TSC 强制回拨 + 显式 `KVM_SET_CLOCK` + vapic 重激活**,正确性等价全扫、更清晰更快。`KVM_SET_CLOCK` 恢复的是 KVM 宿主侧 master clock(否则下次刷 pvclock 时 guest 时间基于"现在"→大跳变),不是 guest 可见态。

**TSC 强制回拨(`sf_kvm_force_tsc`,2026-07-06)**:`cpu_synchronize_post_init` 的 `KVM_SET_MSRS(MSR_IA32_TSC=T0)` **不可靠**——stock KVM `kvm_synchronize_tsc`(`arch/x86/kvm/x86.c`)把落在自由前进值 ±1s 内的 host TSC 写当成 CPU sync-up、保留旧 offset、**不回拨**,于是 guest TSC 停在墙钟而 kvmclock 冻在 T0 → guest clocksource watchdog 报 `cs`(kvmclock)≈快照 vs `wd`(TSC)≈墙钟 的偏斜。修法:restore 与 snapshot 冻结两处在 post_init 后调 `sf_kvm_force_tsc()`——一次 `KVM_SET_MSRS` 双写 MSR_IA32_TSC(先 bogus 值毒化 `last_tsc_write` 使真值不再像 sync-up,再写真值取新 offset),vcpu 泊住时原子落、guest 不见 bogus 值。**stock-KVM 行为,非 patched sentinel**(QEMU-Nyx magic 同招,不绑 KVM-Nyx)。双层验证:host `sf_selftest` ⑦ + guest phase1.5 **T-TSC**(`SF_CP_SKIP_TSC=1` 证牙齿)。

## 5. 关键设计决策(有争议 / 易踩坑,单独记)

- **coherence / 静止机制 = vcpu 线程 hypercall CHECKPOINT 边界(定案 2026-07-05,类 Nyx,不走 vm_stop)**:snapshot 与 restore 都必须在 guest 完全静止的自洽瞬间完成(见 §4.4 真凶)。Nyx 靠 guest 的 acquire/CHECKPOINT hypercall 把 vcpu 泊在 KVM run loop 的 exit handler 里——`fast_reload_restore` 在 **vcpu 线程**跑(QEMU-Nyx `nyx/synchronization.c:1767`;主线程只置 flag+signal、绝不碰 VM/vCPU 态,`:1783`),天然静止、在正确线程、免 `vm_stop` 的 pause/resume 与全 handler 扫开销。sf 采同法:CHECKPOINT hypercall 边界做 snapshot;host 请求 restore 经 flag 交 vcpu 线程在下一个 hypercall 边界应用 §4.4 最小集。**当前 `hmp_sf_snapshot/_restore` 的 `vm_stop`/`vm_start` 包裹是过渡拐杖**(2026-07-05 验证:两侧都包才能正确 restore 真实 TiDB),仅为在 hypercall 通道就位前拿正确性/延迟基线;终态删 `vm_stop`,走 §4.4 显式最小集。
- **端序**:迁移流是**大端**编码,设备内存是**主机端序**;`info->get` 同时做反序列化+端序转换+副作用。故 **mblock.copy 一律从 get 之后的内存取**(不是流字节),端序天然正确。这也是"mblock = 跳过 get 直接 memcpy"的唯一自洽读法。证据:Nyx `state_reallocation.c:416`。
- **走流方式 = 带记录的真加载**(人类 2026-07-04 定):不自己啃流字节的分帧,而是跑一遍真 load 顺手记表。代价:snapshot 时刻会把设备副作用(如 `timer_mod`)以相同值再触发一次;M0-S 接受。
  - **[PLANNED FEATURE / 提速方向,人类提]**:未来若要压 snapshot 延迟,研究**绕开 save→load 往返**,直接就地从设备内存 + VMSD 元数据取三表(免序列化/反序列化)。后置优化,依赖先跑通正确路径。
- **mblock.copy 抓取时机**:必须在 walk 中**逐字段即时抓、在该 section 的 post_load 之前**(抓的是 mem_raw);replay 再重跑 post_load 还原 mem_final。这样非幂等 post_load 也对。放到 walk 后统一抓 = 错(抓成 post_load 之后的值)。
- **单 buffer 假设**:量 get 字节数依赖"整条设备流一次 fill 装完"(buf_index 即绝对读位)。microvm 设备流 <32K 成立;`sf_preparse` 有硬断言,超了会报错提示需泛化。
- **脏页 collect = drain ring 后读 per-slot bitmap,不读 live ring**(Task6 首个实现决策,handoff 里"暴露 stock reap vs 自读 raw ring"的二选一,选前者):脏页的权威记录是**累积的 KVMSlot.dirty_bmap**——KVM reap 往里 set_bit,`KVM_RESET_DIRTY_RINGS` 重保护。先 `kvm_dirty_ring_flush`(drain)再读 bitmap,天然包含**已被后台 reaper 或 `KVM_EXIT_DIRTY_RING_FULL` 退出提前收走**的页(它们已落 bitmap),这正是"ring-full 一等 / 零丢页"不变式,也正是 Nyx 只读 live ring 漏掉的链。reap 不是热路径(restore 才是),复用 stock reap 不影响延迟指标。
- **设备预解析 best-effort 接进 snapshot**:RAM(Task6 主体)必成,设备三表失败只 `WARNING` 不阻断——避免 Task4 的字段覆盖缺口(若有,只在 KVM 下暴露)掩盖 RAM 结果。实测 pc+KVM 下设备预解析反而正常(mblocks≈509/gets=22,无 unhandled)。

## 6. 构建 / 触发 / 测试

- **build dir**:`/data/nvme2/db2/stalefuzz/build/qemu-v11.0.0`(已 configure)。增量编:`ninja -C <builddir> qemu-system-x86_64`(改 meson 会自动 reconfigure)。非交互 shell 先 `. "$HOME/.cargo/env"`。
- **快测 HMP**(无需 guest,microvm 设备/section 远少于 pc):
  `printf 'sf_snapshot\nquit\n' | ./qemu-system-x86_64 -M microvm -accel tcg -S -display none -nodefaults -monitor stdio`
- **单测**:`sf/vmstate_replay/buffer` 挂在 `tests/unit/test-sf-buffer`(纯 host,`ninja tests/unit/test-sf-buffer` 后跑二进制)。
- **RAM 脏页 smoke(Task6,需 KVM + 真跑 vcpu)**:host 侧写内存不经 KVM 写保护,故必须让 vcpu 真跑。用极小 multiboot stub(循环把递增计数器写进 phys 0x300000)当 guest,`-machine pc` 秒起:
  ```
  # 建 stub(seed for Task8 tools/sf-rig/guest;无 nasm 用 as/ld):
  cat > boot.S <<'EOF'
  .set MB_MAGIC,0x1BADB002; .set MB_FLAGS,0x0; .set MB_CKSUM,-(MB_MAGIC+MB_FLAGS)
  .section .text; .align 4
  mbhdr: .long MB_MAGIC; .long MB_FLAGS; .long MB_CKSUM
  .global _start
  _start: movl $0x300000,%edi; xorl %eax,%eax
  1: incl %eax; movl %eax,(%edi); jmp 1b
  EOF
  as --32 -o boot.o boot.S && ld -m elf_i386 -Ttext 0x100000 -e _start -o boot.elf boot.o
  # 驱动:跑一会 → stop → 记 A → sf_snapshot → cont → stop → 记 B(≠A)→ sf_restore → 记应==A
  QEMU=<builddir>/qemu-system-x86_64
  ( sleep .5; echo stop; sleep .3; echo 'xp /1xw 0x300000'; echo sf_snapshot; sleep .3;
    echo cont; sleep .6; echo stop; sleep .3; echo 'xp /1xw 0x300000'; echo sf_restore; sleep .3;
    echo 'xp /1xw 0x300000'; echo quit ) \
  | $QEMU -machine pc -accel kvm,dirty-ring-size=4096 -m 64 -kernel boot.elf \
      -display none -nodefaults -monitor stdio | grep -aE '00300000:|snapshot ok|restore ok'
  ```
  期望:A(如 `0x5b19f141`)→ B(`0xcedc2b3c`,变了)→ **回到 A**;`restore ok: ... ram collected=N copied-back=N`(相等=零丢)。
- **selftest ①–⑤(Task7)**:`HMP sf_selftest`。两次触发(TCG 拿 ④⑤ + KVM+`dirty.elf` 拿 ①②③),命令 + 期望见主仓 `tools/sf-rig/README.md`。负载 stub 源在 `tools/sf-rig/guest/{boot,dirty}.S`(`bash build.sh` 构建)。
- **延迟探针 `SF_TIME=1`**(env,平时零开销):`sf_snapshot_core`/`sf_restore_core` 按阶段打 ns 到 stderr——`sf-time: snapshot ram-shadow=… device-preparse=…`、`sf-time: restore device=… collect=… copy+reset=… cpusync=… total=…`。用来给 M0-S 止损闸与快照优化优先级摆真数(见主仓 `log/2026-07-06-01`:phase2 真 TiDB 稳态 restore ≈1.4ms、ram-shadow 8.9s/10GB、device-preparse ≈211µs)。
- **提交纪律**:C 代码 commit 到本 submodule(分支 `sf-m0s-restore-spike`),再更主仓 gitlink;每步回填计划 checkbox。

## 7. 现状(逐 Task)

| Task | 内容 | 状态 | submodule commit |
|---|---|---|---|
| 1 | sf/ 骨架 + HMP 触发 + 构建接通 | ✅ | `0ee6723` |
| 2 | DP-C1 un-static + handlers 迭代器 | ✅ | `d056288` |
| 3 | buffer <-> QEMUFile helper(5 单测绿) | ✅ | `116947e` |
| 4 | 三表预解析(microvm:mblocks=119/gets=10/posts=14) | ✅ | `07c60d2` |
| 5 | 三表重放 + 对拍 stock load(selftest ⑤ GREEN + 负例有辨别力) | ✅ | 见下 |
| 6 | 脏页引擎 hot/cold + ring-full(smoke:snapshot→改页→restore 逐字节回滚,collected=copied,零丢) | ✅ | 见下 |
| 7 | restore 正确性 selftest ①–④(汇总 ①–⑤;全 GREEN 且注入必红;accel 拆分 TCG④⑤/KVM①②③) | ✅ | 见下 |
| 8 | 微型 rig + 单VM 延迟对拍(**门槛判定**) | ⏳ | — |
| 9 | 时钟矩阵 | ⏳ | — |
| 10 | 收口报告 | ⏳ | — |

> 进度权威在实现计划的 checkbox;本表是速览,更新时两处同步。
