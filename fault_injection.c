/*
 * fault_injection.c
 * * eBPF program containing handlers for various USDT probes.
 * This includes functions for modifying arguments in memory and functions
 * for injecting sleep delays by pausing the target thread.
 * This file is intended to be loaded by a user-space controller script.
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/types.h>


/*
 * =================================================================
 * Multi-Argument Handlers with Enhanced "Read-Write-Verify" Logging
 * =================================================================
 */

/**
 * @brief DmgChangeWear 的注入处理函数 (合并版本).
 * 接收3个参数, 分别为: &wearPercentage, &wearType, &wearValue
 * 通过 -p val1,val2,val3 参数注入指定的整数值。
 * 例如:
 * -p 10,0,3000      (模拟 NormalDay)
 * -p 90,0,17270      (模拟 90Day)
 * -p 90,0,5390       (模拟 30Day)
 * -p 99,0,1970       (模拟 1Day)
 */
int DmgChangeWear(struct pt_regs *ctx) {
#ifdef PARAMS_DmgChangeWear
    bpf_trace_printk("Probe DmgChangeWear: Fired.\\n");

    // --- 1. 在 eBPF 中解析字符串参数 ---
    char params[] = PARAMS_DmgChangeWear;
    long values[3] = {0}; // 存储解析出的三个整数
    int param_idx = 0;

    // BPF 验证器友好的字符串解析循环
    #pragma unroll
    for (int i = 0; i < sizeof(params); i++) {
        char c = params[i];
        if (c == '\0') break;
        if (c == ',') {
            param_idx++;
            if (param_idx >= 3) break;
        } else if (c >= '0' && c <= '9') {
            if (param_idx < 3) {
                values[param_idx] = values[param_idx] * 10 + (c - '0');
            }
        }
    }

    // 检查是否成功解析出3个参数
    if (param_idx != 2) {
        bpf_trace_printk("DmgChangeWear Error: Expected 3 params, but parsed %d. Input: %s\\n",
                         param_idx + 1, params);
        return 0;
    }

    // --- 2. 依次修改探针的三个参数 ---
    void *ptr = NULL;
    int original_val, verified_val;
    int new_val;

    // 修改第一个参数
    bpf_usdt_readarg(1, ctx, &ptr);
    if (ptr) {
        new_val = (int)values[0];
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Arg1: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    // 修改第二个参数
    bpf_usdt_readarg(2, ctx, &ptr);
    if (ptr) {
        new_val = (int)values[1];
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Arg2: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    // 修改第三个参数
    bpf_usdt_readarg(3, ctx, &ptr);
    if (ptr) {
        new_val = (int)values[2];
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Arg3: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

#else
    bpf_trace_printk("BPF Compile Error: DmgChangeWear requires -p \"val1,val2,val3\"\\n");
#endif
    return 0;
}

// 定义解析器可以处理的最大字符串长度和期望的参数数量
#define MAX_DHA_PARAMS_STRING_LEN 80
#define EXPECTED_DHA_PARAMS_COUNT 5 // 更新：现在期望 5 个参数
#define IO_ERR_EVENT 5              // 新增：根据要求定义事件类型

// 定义 DrmSetDiskDiagMonthLifeCount 函数的参数
#define MAX_DIAG_COUNT_STRING_LEN 32
#define EXPECTED_DIAG_COUNT_PARAMS 2

// 定义 DrmDprSetNvmeEntrysPrefail 函数的参数
#define MAX_NVME_PREFAIL_PARAM_LEN 128
#define READ_ONLY_BIT_MASK 0x08 // 对应 DrmNvmeCriticalWarning.bits.readOnly (第4个bit)

/**
 * @brief DhaAnlyIoErrorParam 的 eBPF 侧定义。
 * 使用与应用程序完全匹配的固定宽度类型，以避免任何大小或对齐问题。
 */
typedef struct {
    u8  opcode;
    u8  protocol;
    u32 senseKey;
    u32 senseCode;
    u64 backUstime;
    u64 procUsTime;
    u64 lba;
} DhaAnlyIoErrorParam;


/**
 * @brief DhasTriggerIoerr 的注入处理函数。
 * 此版本根据参考代码逻辑进行重构，在 eBPF 内核空间解析字符串并修改所有三个探针参数。
 * 输入参数格式: -p "diskId,opcode,protocol,senseKey,senseCode"
 */
int DhasTriggerIoerr(struct pt_regs *ctx) {
    // 将所有逻辑包裹在 #ifdef 中，以避免在未定义宏时发生编译错误
#ifdef PARAMS_DhasTriggerIoerr
    // --- 1. 从 USDT 探针读取参数指针 ---
    void *diskIdPtr = NULL;
    void *eventPtr = NULL;
    void *ioErrorParamPtr = NULL;
    bpf_usdt_readarg(1, ctx, &diskIdPtr);
    bpf_usdt_readarg(2, ctx, &eventPtr);
    bpf_usdt_readarg(3, ctx, &ioErrorParamPtr);

    if (!diskIdPtr || !eventPtr || !ioErrorParamPtr) {
        bpf_trace_printk("DhasTriggerIoerr Error: Failed to read pointers from probe.\\n");
        return 0;
    }

    // --- 2. 在 eBPF 中解析字符串参数 ---
    char params[MAX_DHA_PARAMS_STRING_LEN] = PARAMS_DhasTriggerIoerr;
    long values[EXPECTED_DHA_PARAMS_COUNT] = {0};
    int param_idx = 0;

    #pragma unroll
    for (int i = 0; i < MAX_DHA_PARAMS_STRING_LEN; i++) {
        char c = params[i];
        if (c == '\0') break;
        if (c == ',') {
            param_idx++;
            if (param_idx >= EXPECTED_DHA_PARAMS_COUNT) break;
        } else if (c >= '0' && c <= '9') {
            if (param_idx < EXPECTED_DHA_PARAMS_COUNT) {
                values[param_idx] = values[param_idx] * 10 + (c - '0');
            }
        }
    }

    if (param_idx != EXPECTED_DHA_PARAMS_COUNT - 1) {
        bpf_trace_printk("DhasTriggerIoerr Error: Expected %d params, but parsed %d. Input: %s\\n",
                         EXPECTED_DHA_PARAMS_COUNT, param_idx + 1, params);
        return 0;
    }

    // --- 3. 在 BPF 栈上准备修改后的数据 ---
    int newEvent = IO_ERR_EVENT; // 更新：使用宏定义的值
    u32 newDiskId = (u32)values[0]; // 更新：索引从 0 开始

    DhaAnlyIoErrorParam newIoErrorParam = {};
    u64 currentTimeUs = bpf_ktime_get_ns() / 1000;

    newIoErrorParam.opcode     = (u8)values[1];  // 更新：索引
    newIoErrorParam.protocol   = (u8)values[2];  // 更新：索引
    newIoErrorParam.senseKey   = (u32)values[3]; // 更新：索引
    newIoErrorParam.senseCode  = (u32)values[4]; // 更新：索引
    newIoErrorParam.backUstime = currentTimeUs;
    newIoErrorParam.procUsTime = currentTimeUs;
    newIoErrorParam.lba        = 0;

    // --- 4. 将修改后的数据写回用户空间 ---
    if (bpf_probe_write_user(diskIdPtr, &newDiskId, sizeof(newDiskId)) < 0) {
        bpf_trace_printk("DhasTriggerIoerr Error: Failed to write modified diskId.\\n");
        return 0;
    }
    if (bpf_probe_write_user(eventPtr, &newEvent, sizeof(newEvent)) < 0) {
        bpf_trace_printk("DhasTriggerIoerr Error: Failed to write modified event.\\n");
        return 0;
    }
    if (bpf_probe_write_user(ioErrorParamPtr, &newIoErrorParam, sizeof(newIoErrorParam)) < 0) {
        bpf_trace_printk("DhasTriggerIoerr Error: Failed to write modified ioErrorParam struct.\\n");
        return 0;
    }

    // --- 5. 验证写入是否成功 (应避免bpf_trace_printk 参数过多的问题) ---
    u32 verifiedDiskId = 0;
    int verifiedEvent = 0;
    DhaAnlyIoErrorParam verifiedIoErrorParam = {};
    bpf_probe_read_user(&verifiedDiskId, sizeof(verifiedDiskId), diskIdPtr);
    bpf_probe_read_user(&verifiedEvent, sizeof(verifiedEvent), eventPtr);
    bpf_probe_read_user(&verifiedIoErrorParam, sizeof(verifiedIoErrorParam), ioErrorParamPtr);
    
    bpf_trace_printk("DhasTriggerIoerr Verified -> diskId: %u, event: %d, opcode: %u\\n",
                     verifiedDiskId, verifiedEvent, verifiedIoErrorParam.opcode);
    bpf_trace_printk("DhasTriggerIoerr Verified -> senseKey: %u, senseCode: %u, time(us): %llu\\n",
                     verifiedIoErrorParam.senseKey, verifiedIoErrorParam.senseCode, verifiedIoErrorParam.backUstime);
#else
    bpf_trace_printk("BPF Compile Error: DhasTriggerIoerr requires a parameter string via -p.\\n");
#endif
    return 0;
}

/**
 * @brief DrmSetDiskDiagMonthLifeCount 的注入处理函数。
 * 通过解析逗号分隔的字符串来修改月诊断次数和生命周期诊断次数。
 * 输入参数格式: -p "diagMonthCount,diagLifeCount"
 */
int DrmSetDiskDiagMonthLifeCount(struct pt_regs *ctx) {
    // 将所有逻辑包裹在 #ifdef 中，以避免在未定义宏时发生编译错误
#ifdef PARAMS_DrmSetDiskDiagMonthLifeCount
    // --- 1. 从 USDT 探针读取参数指针 ---
    void *monthCountPtr = NULL;
    void *lifeCountPtr = NULL;
    bpf_usdt_readarg(1, ctx, &monthCountPtr);
    bpf_usdt_readarg(2, ctx, &lifeCountPtr);

    if (!monthCountPtr || !lifeCountPtr) {
        bpf_trace_printk("DrmSetDiskDiagMonthLifeCount Error: Failed to read pointers from probe.\\n");
        return 0;
    }

    // --- 2. 在 eBPF 中解析字符串参数 ---
    char params[MAX_DIAG_COUNT_STRING_LEN] = PARAMS_DrmSetDiskDiagMonthLifeCount;
    long values[EXPECTED_DIAG_COUNT_PARAMS] = {0};
    int param_idx = 0;

    #pragma unroll
    for (int i = 0; i < MAX_DIAG_COUNT_STRING_LEN; i++) {
        char c = params[i];
        if (c == '\0') break;
        if (c == ',') {
            param_idx++;
            if (param_idx >= EXPECTED_DIAG_COUNT_PARAMS) break;
        } else if (c >= '0' && c <= '9') {
            if (param_idx < EXPECTED_DIAG_COUNT_PARAMS) {
                values[param_idx] = values[param_idx] * 10 + (c - '0');
            }
        }
    }

    if (param_idx != EXPECTED_DIAG_COUNT_PARAMS - 1) {
        bpf_trace_printk("DrmSetDiskDiagMonthLifeCount Error: Expected %d params, but parsed %d. Input: %s\\n",
                         EXPECTED_DIAG_COUNT_PARAMS, param_idx + 1, params);
        return 0;
    }

    // --- 3. 准备修改后的数据 ---
    int newMonthCount = (int)values[0];
    int newLifeCount = (int)values[1];

    // --- 4. 将修改后的数据写回用户空间 ---
    if (bpf_probe_write_user(monthCountPtr, &newMonthCount, sizeof(newMonthCount)) < 0) {
        bpf_trace_printk("DrmSetDiskDiagMonthLifeCount Error: Failed to write modified monthCount.\\n");
        return 0;
    }
    if (bpf_probe_write_user(lifeCountPtr, &newLifeCount, sizeof(newLifeCount)) < 0) {
        bpf_trace_printk("DrmSetDiskDiagMonthLifeCount Error: Failed to write modified lifeCount.\\n");
        return 0;
    }

    // --- 5. 验证写入是否成功 ---
    int verifiedMonthCount = 0;
    int verifiedLifeCount = 0;
    bpf_probe_read_user(&verifiedMonthCount, sizeof(verifiedMonthCount), monthCountPtr);
    bpf_probe_read_user(&verifiedLifeCount, sizeof(verifiedLifeCount), lifeCountPtr);
    bpf_trace_printk("DrmSetDiskDiagMonthLifeCount Verified -> monthCount: %d, lifeCount: %d\\n",
                     verifiedMonthCount, verifiedLifeCount);
#else
    // 如果没有提供参数，打印错误信息
    bpf_trace_printk("BPF Compile Error: DrmSetDiskDiagMonthLifeCount requires -p 'monthCount,lifeCount'\\n");
#endif
    return 0;
}

/**
 * @brief DrmDprSetNvmeEntrysPrefail 的注入处理函数。
 * 接收2个参数: diskId, &criticalWarning。
 * - 如果不提供 -p 参数, 则对所有 diskId 注入故障。
 * - 如果提供 -p "id1,id2,..." 参数, 则仅对匹配的 diskId 注入故障。
 */
int DrmDprSetNvmeEntrysPrefail(struct pt_regs *ctx) {
#ifdef PARAMS_DrmDprSetNvmeEntrysPrefail
    // --- 1. 从 USDT 探针读取所有参数 ---
    u32 currentDiskId = 0;
    void *criticalWarningPtr = NULL;

    bpf_usdt_readarg(1, ctx, &currentDiskId);
    bpf_usdt_readarg(2, ctx, &criticalWarningPtr);

    if (!criticalWarningPtr) {
        bpf_trace_printk("DrmDprSetNvmeEntrysPrefail Error: Failed to read pointers.\\n");
        return 0;
    }

    char params[MAX_NVME_PREFAIL_PARAM_LEN] = PARAMS_DrmDprSetNvmeEntrysPrefail;

    // --- 2. 根据是否提供参数，决定注入逻辑 ---

    // 情况 A: 未提供 -p 参数 (params 为空字符串), 对所有 diskId 注入
    if (params[0] == '\0') {
        u8 originalByte = 0;
        bpf_probe_read_user(&originalByte, sizeof(originalByte), criticalWarningPtr);
        
        // 使用位掩码设置 readOnly 位并写回
        u8 newByte = originalByte | READ_ONLY_BIT_MASK;
        bpf_probe_write_user(criticalWarningPtr, &newByte, sizeof(newByte));
        bpf_trace_printk("DrmDprSetNvmeEntrysPrefail Injected (no params) -> diskId: %u, newByte: 0x%x\\n", currentDiskId, newByte);
        return 0; // 完成注入，退出
    }

    // 情况 B: 提供了 -p 参数, 解析 diskId 列表并匹配
    bool shouldInject = false;
    u32 parsedId = 0;
    #pragma unroll
    for (int i = 0; i < MAX_NVME_PREFAIL_PARAM_LEN; i++) {
        char c = params[i];
        if (c == '\0' || c == ',') {
            if (parsedId == currentDiskId) {
                shouldInject = true;
                break;
            }
            parsedId = 0; // 为下一个数字重置
            if (c == '\0') break;
        } else if (c >= '0' && c <= '9') {
            parsedId = parsedId * 10 + (c - '0');
        }
    }
    // 检查最后一个数字
    if (!shouldInject && parsedId != 0 && parsedId == currentDiskId) {
        shouldInject = true;
    }

    // 如果匹配，则执行注入
    if (shouldInject) {
        u8 originalByte = 0;
        bpf_probe_read_user(&originalByte, sizeof(originalByte), criticalWarningPtr);
        u8 newByte = originalByte | READ_ONLY_BIT_MASK;
        bpf_probe_write_user(criticalWarningPtr, &newByte, sizeof(newByte));
        bpf_trace_printk("DrmDprSetNvmeEntrysPrefail Injected (matched) -> diskId: %u, newByte: 0x%x\\n", currentDiskId, newByte);
    }
#endif
    return 0;
}

/*
 * ==================================================================
 * Single-Argument Handlers with Enhanced "Read-Write-Verify" Logging
 * ==================================================================
 */

/**
 * @brief DmgChangeCheckWhitelist 的注入处理函数
 * 接收1个参数: &rc
 * 通过 -p "value" (0 对应旧的 True 逻辑, 1 对应旧的 False 逻辑) 参数注入指定的返回值。
 */
int DmgChangeCheckWhitelist(struct pt_regs *ctx) {
#ifdef PARAMS_DmgChangeCheckWhitelist
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) {
        bpf_trace_printk("Probe DmgChangeCheckWhitelist: Fired, but pointer is NULL.\\n");
        return 0;
    }
    // 从宏解析参数
    char params[] = PARAMS_DmgChangeCheckWhitelist;
    int new_value = 0; // 默认值为 0 (对应旧的 True 逻辑)

    // 一个对 BPF 验证器友好的简单解析方法
    if (params[0] == '1') {
        new_value = 1; // 对应旧的 False 逻辑
    }
    int original_val, verified_val = -99;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);    
    bpf_trace_printk("Probe DmgChangeCheckWhitelist: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);

#else
    bpf_trace_printk("BPF Compile Error: DmgChangeCheckWhitelist requires a parameter via -p, e.g., -p \"0\" or -p \"1\"\\n");
#endif
    return 0;
}

/**
 * @brief DmgChangeCheckWhitelistCache 的注入处理函数 (合并版本).
 * 接收1个参数: &rc (类型为 bool)
 * 通过 -p "value" (1 代表 true, 0 代表 false) 参数注入指定的布尔值。
 */
int DmgChangeCheckWhitelistCache(struct pt_regs *ctx) {
#ifdef PARAMS_DmgChangeCheckWhitelistCache
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) {
        bpf_trace_printk("Probe DmgChangeCheckWhitelistCache: Fired, but pointer is NULL.\\n");
        return 0;
    }

    // 从宏解析参数
    char params[] = PARAMS_DmgChangeCheckWhitelistCache;
    bool new_value = false; // 默认值为 false

    // 期望的参数是 "0" (false) 或 "1" (true)
    if (params[0] == '1') {
        new_value = true;
    }

    bool original_val, verified_val;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);

    bpf_trace_printk("Probe DmgChangeCheckWhitelistCache: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);

#else
    bpf_trace_printk("BPF Compile Error: DmgChangeCheckWhitelistCache requires a parameter via -p, e.g., -p \"0\" or -p \"1\"\\n");
#endif
    return 0;
}

/**
 * @brief DcmReturnLinkErr 的注入处理函数 (合并版本)。
 * 适配 LVOS_INJECT1，接收2个参数: &ret, &__lvos_skip_flag
 * 通过 -p "errorCode" 参数注入指定的错误码。
 */
int DcmReturnLinkErr(struct pt_regs *ctx) {
#ifdef PARAMS_DcmReturnLinkErr
    void *retPtr = NULL;
    void *skipFlagPtr = NULL;
    bpf_usdt_readarg(1, ctx, &retPtr);
    bpf_usdt_readarg(2, ctx, &skipFlagPtr);

    if (!retPtr || !skipFlagPtr) {
        bpf_trace_printk("DcmReturnLinkErr Error: Failed to read pointers from probe.\\n");
        return 0;
    }

    // 从宏解析参数
    char params[] = PARAMS_DcmReturnLinkErr;
    int newValue = 0;
    #pragma unroll
    for (int i = 0; i < sizeof(params); i++) {
        char c = params[i];
        if (c == '\0') break;
        if (c >= '0' && c <= '9') {
            newValue = newValue * 10 + (c - '0');
        }
    }
    
    // 注入故障码
    bpf_probe_write_user(retPtr, &newValue, sizeof(newValue));
    
    // 设置跳过标志
    int one = 1;
    bpf_probe_write_user(skipFlagPtr, &one, sizeof(one));
    
    bpf_trace_printk("Probe DcmReturnLinkErr: Injected %d and signaled skip.\\n", newValue);
#else
    bpf_trace_printk("BPF Compile Error: DcmReturnLinkErr requires -p 'errorCode'\\n");
#endif
    return 0;
}

int DrmReturnErr(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = -1;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DrmReturnErr: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DrmDiskDiagReponseParseFail(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    bool original_val, verified_val = true;
    bool new_value = false;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DrmDiskDiagReponseParseFail: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DcaCreatePipeFail(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = -1;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DcaCreatePipeFail: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DcaClosePipeFail(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = -1;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DcaClosePipeFail: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DcaGetPohFail(struct pt_regs *ctx) {
    void *ptr = NULL;
    char buf[64] = {};

    bpf_usdt_readarg(2, ctx, &ptr);
    if (!ptr) { return 0; }
    bpf_probe_read_user_str(buf, sizeof(buf), ptr);

#ifdef PARAMS_DcaGetPohFail
    #pragma unroll
    for (int i = 0; i < sizeof(PARAMS_DcaGetPohFail) - 1; i++) {
        if (i >= sizeof(buf) || buf[i] != PARAMS_DcaGetPohFail[i]) {
            return 0;
        }
    }
    if (buf[sizeof(PARAMS_DcaGetPohFail) - 1] != '\0') {
        return 0;
    }
#endif

    bpf_trace_printk("Probe DcaGetPohFail: Matched path, injecting fault.\\n");
    int original_val, verified_val, new_val;
    
    bpf_usdt_readarg(1, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = -1;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Probe DcaGetPohFail: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    return 0;
}

int DcaGetDhaSingleFail(struct pt_regs *ctx) {
    void *ptr = NULL;
    char buf[64] = {};

    bpf_usdt_readarg(2, ctx, &ptr);
    if (!ptr) { return 0; }
    bpf_probe_read_user_str(buf, sizeof(buf), ptr);

#ifdef PARAMS_DcaGetDhaSingleFail
    #pragma unroll
    for (int i = 0; i < sizeof(PARAMS_DcaGetDhaSingleFail) - 1; i++) {
        if (i >= sizeof(buf) || buf[i] != PARAMS_DcaGetDhaSingleFail[i]) {
            return 0;
        }
    }
    if (buf[sizeof(PARAMS_DcaGetDhaSingleFail) - 1] != '\0') {
        return 0;
    }
#endif

    bpf_trace_printk("Probe DcaGetDhaSingleFail: Matched path, injecting fault.\\n");
    int original_val, verified_val, new_val;
    
    bpf_usdt_readarg(1, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = -1;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Probe DcaGetDhaSingleFail: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    return 0;
}

int CliEnableCollect(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    bool original_val, verified_val = false;
    bool new_value = true;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe CliEnableCollect: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DhaEbpfCheckEvent(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = 2;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DhaEbpfCheckEvent: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DhaEbpfGetSnErr(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = -1;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DhaEbpfGetSnErr: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DhaEbpfCorruptShm(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = 0;
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DhaEbpfCorruptShm: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DhaEbpfReaderLockUp(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = -6;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DhaEbpfReaderLockUp: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DhaEbpfProducerLockUp(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = -1;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DhaEbpfProducerLockUp: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DrmDiskDiagOfflineDiskFail(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = -1;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DrmDiskDiagOfflineDiskFail: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DrmDiskDiagOnlineDiskFail(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = -1;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DrmDiskDiagOnlineDiskFail: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

#define TP_DISK_DIAG_RES_LEN 50
int DrmDiskDiagSelfTestDiskFail(struct pt_regs *ctx) {
    void *user_ptr = NULL;

    char new_value[TP_DISK_DIAG_RES_LEN] = "SELF_TEST_FAILED";
    bpf_usdt_readarg(1, ctx, &user_ptr);
    if (!user_ptr){ return 0; }

    char original_val[TP_DISK_DIAG_RES_LEN], verified_val[TP_DISK_DIAG_RES_LEN];
    // 先清零
    __builtin_memset(original_val, 0, sizeof(original_val));
    __builtin_memset(verified_val, 0, sizeof(verified_val));
    bpf_probe_read_user(original_val, sizeof(original_val), user_ptr);
    bpf_probe_write_user(user_ptr, new_value, sizeof(new_value));
    bpf_probe_read_user(verified_val, sizeof(verified_val), user_ptr);
    bpf_trace_printk("Probe DrmDiskDiagOnlineDiskFail: Read=\"%s\, Wrote=\"%s\, Verified=\"%s\\\n", original_val, new_value, verified_val);
    return 0;
}

int DrmDiskDiagChangeLimitFail(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = -1;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DrmDiskDiagChangeLimitFail: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DrmDiskDiagOnlineDiagFail(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = -1;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DrmDiskDiagOnlineDiagFail: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DrmDiskDiagUpdateDiagStatusFail(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = -1;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DrmDiskDiagUpdateDiagStatusFail: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DrmDiskDiagGetDiagInfoFail(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = -1;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DrmDiskDiagGetDiagInfoFail: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DrmDiskDiagFormatInfoFail(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = -1;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DrmDiskDiagFormatInfoFail: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int CliReturnTimeOut30S(struct pt_regs *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    bpf_trace_printk("Probe 'CliReturnTimeOut30S' hit. Sending SIGSTOP to TID %u.\\n", tid);
    bpf_send_signal(SIGSTOP);
    return 0;
}

int CliReturnTimeOut90S(struct pt_regs *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    bpf_trace_printk("Probe 'CliReturnTimeOut90S' hit. Sending SIGSTOP to TID %u.\\n", tid);
    bpf_send_signal(SIGSTOP);
    return 0;
}

#define CMD_BUFFER_SIZE 256  // 用于从用户空间读取命令的缓冲区大小
#define TARGET_CMD "python3 /opt/spdk_2401/scripts/rpc.py bdev_get_bdevs --name"
#define FAULTY_CMD "python3 /opt/spdk_2401/scripts/rpc.py bdev_get_bdevs --name FailNvme -t 100"

/**
 * @brief 当 SpdkReturnJsonTimeOut 探针被触发时调用。
 * 使用简化的、验证器友好的循环来检查命令字符串，如果匹配，
 * 则将其替换为一个会超时的命令，以实现故障注入。
 */
int SpdkReturnJsonTimeOut(struct pt_regs *ctx) {
    void *cmd_ptr = NULL;
    bpf_usdt_readarg(1, ctx, &cmd_ptr);
    if (!cmd_ptr) {
        return 0;
    }

    char user_cmd[CMD_BUFFER_SIZE] = {};
    bpf_probe_read_user_str(user_cmd, sizeof(user_cmd), cmd_ptr);

    // 使用简化的循环结构来模拟 strstr，更容易被 BPF 验证器接受。
    const char target[] = TARGET_CMD;
    bool found = true;
    #pragma unroll
    for (int i = 0; i < sizeof(target) - 1; ++i) {
        if (user_cmd[i] != target[i]) {
            found = false;
            break;
        }
    }
    
    if (found) {
        bpf_trace_printk("SpdkReturnJsonTimeOut: Found target command. Injecting timeout fault.\\n");
        char faulty_cmd[] = FAULTY_CMD;
        
        long ret = bpf_probe_write_user(cmd_ptr, faulty_cmd, sizeof(faulty_cmd));
        if (ret != 0) {
            bpf_trace_printk("SpdkReturnJsonTimeOut: bpf_probe_write_user failed with code %d\\n", ret);
        }
    } else {
        bpf_trace_printk("SpdkReturnJsonTimeOut: Probe hit, but command did not match. Skipping.\\n");
    }

    return 0;
}

#define DHA_SATA_HDD_SMART_ATTR_CNT (6)
#define SATA_HDD_ATTR_NUM 5
int DcaGetSataHddDhaInfo(struct pt_regs *ctx) {

#ifdef PARAMS_DcaGetSataHddDhaInfo

    // 修改探针位置的变量值
    void *ptr_pot = NULL;
    void *ptr_attrs = NULL;

    // 读取参数
    int user_pot = 0, user_smartAttr[DHA_SATA_HDD_SMART_ATTR_CNT] = {};
    if (bpf_usdt_readarg(1, ctx, &ptr_pot) < 0 || !ptr_pot) {
        bpf_trace_printk("readarg(1) error\\n");
        return 0;
    }
    if (bpf_probe_read_user(&user_pot, sizeof(user_pot), ptr_pot) < 0) {
        bpf_trace_printk("read_user pot error\\n");
        return 0;
    }

    if (bpf_usdt_readarg(2, ctx, &ptr_attrs) < 0 || !ptr_attrs) {
        bpf_trace_printk("readarg(2) error\\n");
        return 0;
    }
    if (bpf_probe_read_user(&user_smartAttr, sizeof(user_smartAttr), ptr_attrs) < 0) {
        bpf_trace_printk("read_user attrs error\\n");
        return 0;
    }
    bpf_trace_printk("Read: ");
    bpf_trace_printk("user_pot: %d", user_pot);
    bpf_trace_printk("Attr0: %d, Attr1: %d, Attr2: %d", user_smartAttr[0], user_smartAttr[1], user_smartAttr[2]);
    bpf_trace_printk("Attr3: %d, Attr4: %d, Attr5: %d", user_smartAttr[3], user_smartAttr[4], user_smartAttr[5]);

    // 解析用户输入的参数
    char params[] = PARAMS_DcaGetSataHddDhaInfo;        // 准备一个可修改的本地缓冲区，存放传入的字符串
    int values[DHA_SATA_HDD_SMART_ATTR_CNT] = {0};
    int idx = 0;

    // 遍历 params , 将逗号分隔的数字转为 int
    #pragma unroll
    for (int j = 0; j < sizeof(params); j++) {
        char c = params[j];
        if (c >= '0' && c <= '9') {
            values[idx] = values[idx] * 10 + (c - '0'); // 当前数字累加
        } else if (c == ',') {
            idx++;                                      // 遇到逗号，切换到下一个槽位
            if (idx >= DHA_SATA_HDD_SMART_ATTR_CNT) break;                        // 为安全起见：防止越界
        } else {
            if (c == '\0') break;                       // 既不是数字也不是逗号，忽略(如字符串末尾 '\0')
        }
    }

    // 将解析结果分配给 pot 和 smartAttr
    int pot = values[0];
    int smartAttr[SATA_HDD_ATTR_NUM] = {};
    #pragma unroll
    for (int k = 0; k < SATA_HDD_ATTR_NUM; k++) {
        smartAttr[k] = values[k + 1];
    }
    // 将 pot 和 smartAttr 通过 BPF map、bpf_trace_printk 等输出
    bpf_trace_printk("Write: ");
    bpf_trace_printk("pot=%d, s0=%d, s1=%d", pot, smartAttr[0], smartAttr[1]);
    bpf_trace_printk("s2=%d, s3=%d, s4=%d", smartAttr[2], smartAttr[3], smartAttr[4]);


    // 修改参数
    bpf_probe_write_user(ptr_pot, &pot, sizeof(pot));
    if (bpf_probe_read_user(&user_pot, sizeof(user_pot), ptr_pot) < 0) {
        bpf_trace_printk("read_user pot error\\n");
        return 0;
    }
    for (int i = 0; i < SATA_HDD_ATTR_NUM; i++) {
        bpf_probe_write_user(ptr_attrs + i*sizeof(int), &smartAttr[i], sizeof(smartAttr[i]));
    }
    if (bpf_probe_read_user(&user_smartAttr, sizeof(user_smartAttr), ptr_attrs) < 0) {
        bpf_trace_printk("read_user attrs error\\n");
        return 0;
    }

    bpf_trace_printk("Verified: ");
    bpf_trace_printk("user_pot: %d", user_pot);
    bpf_trace_printk("Attr0: %d, Attr1: %d, Attr2: %d", user_smartAttr[0], user_smartAttr[1], user_smartAttr[2]);
    bpf_trace_printk("Attr3: %d, Attr4: %d, Attr5: %d", user_smartAttr[3], user_smartAttr[4], user_smartAttr[5]);

    return 0;

#endif

    bpf_trace_printk("DcaGetSataHddDhaInfo must have 6 params, like 1,2,3,4,5,6 \\n");
    return 0;
}

int DmgGetDhaInfoFail(struct pt_regs *ctx) {
#ifndef PARAMS_DmgGetDhaInfoFail
    bpf_trace_printk("Need input diskId");
    return 0;
#endif

    void *ptr = NULL;
    int diskId = 0;

    bpf_usdt_readarg(2, ctx, &ptr);
    if (!ptr) { return 0; }
    bpf_probe_read_user(&diskId, sizeof(diskId), ptr);

#ifdef PARAMS_DmgGetDhaInfoFail
    // 解析用户输入的参数
    char params[] = PARAMS_DmgGetDhaInfoFail;        // 准备一个可修改的本地缓冲区，存放传入的字符串
    int values = 0;
    int idx = 0;

    // 遍历 params , 将逗号分隔的数字转为 int
    #pragma unroll
    for (int j = 0; j < sizeof(params); j++) {
        char c = params[j];
        if (c >= '0' && c <= '9') {
            values = values * 10 + (c - '0'); // 当前数字累加
        } else if (c == ',') {
            idx++;                                      // 遇到逗号，切换到下一个槽位
            if (idx >= DHA_SATA_HDD_SMART_ATTR_CNT) break;                        // 为安全起见：防止越界
        } else {
            if (c == '\0') break;                       // 既不是数字也不是逗号，忽略(如字符串末尾 '\0')
        }
    }
    if (values != diskId) {
        return 0;
    }
#endif

    int original_val, verified_val, new_val;
    bpf_usdt_readarg(1, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = -1;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Probe DmgGetDhaInfoFail: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    return 0;
}

int DrmSmartTpSkipFeatureIdHook(struct pt_regs *ctx) {
#ifndef PARAMS_DrmSmartTpSkipFeatureIdHook
    bpf_trace_printk("Need input diskId");
    return 0;
#endif

#ifdef PARAMS_DrmSmartTpSkipFeatureIdHook
    void *ptr = NULL;

    // 解析用户输入的参数
    char params[] = PARAMS_DrmSmartTpSkipFeatureIdHook;        // 准备一个可修改的本地缓冲区，存放传入的字符串
    int values = 0;
    int idx = 0;

    // 遍历 params , 将逗号分隔的数字转为 int
    #pragma unroll
    for (int j = 0; j < sizeof(params); j++) {
        char c = params[j];
        if (c >= '0' && c <= '9') {
            values = values * 10 + (c - '0'); // 当前数字累加
        } else if (c == ',') {
            idx++;                                      // 遇到逗号，切换到下一个槽位
            if (idx >= DHA_SATA_HDD_SMART_ATTR_CNT) break;                        // 为安全起见：防止越界
        } else {
            if (c == '\0') break;                       // 既不是数字也不是逗号，忽略(如字符串末尾 '\0')
        }
    }

    int original_val, verified_val, new_val;
    bpf_usdt_readarg(1, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = values;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Probe DrmSmartTpSkipFeatureIdHook: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }
#endif

    return 0;
}

int DrmSlowDiskDetectSkipUpdateDiskPerfTp(struct pt_regs *ctx) {
#ifndef PARAMS_DrmSlowDiskDetectSkipUpdateDiskPerfTp
    bpf_trace_printk("Need input diskId");
    return 0;
#endif

    void *ptr = NULL;
    int diskId = 0;

    bpf_usdt_readarg(1, ctx, &ptr);
    if (!ptr) { return 0; }
    bpf_probe_read_user(&diskId, sizeof(diskId), ptr);

#ifdef PARAMS_DrmSlowDiskDetectSkipUpdateDiskPerfTp
    // 解析用户输入的参数
    char params[] = PARAMS_DrmSlowDiskDetectSkipUpdateDiskPerfTp;        // 准备一个可修改的本地缓冲区，存放传入的字符串
    int values = 0;
    int idx = 0;

    // 遍历 params , 将逗号分隔的数字转为 int
    #pragma unroll
    for (int j = 0; j < sizeof(params); j++) {
        char c = params[j];
        if (c >= '0' && c <= '9') {
            values = values * 10 + (c - '0'); // 当前数字累加
        } else if (c == ',') {
            idx++;                                      // 遇到逗号，切换到下一个槽位
            if (idx >= DHA_SATA_HDD_SMART_ATTR_CNT) break;                        // 为安全起见：防止越界
        } else {
            if (c == '\0') break;                       // 既不是数字也不是逗号，忽略(如字符串末尾 '\0')
        }
    }
    if (values != diskId) {
        return 0;
    }
#endif

    bool original_val, verified_val, new_val;
    bpf_usdt_readarg(2, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = true;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Probe DrmSlowDiskDetectSkipUpdateDiskPerfTp: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    return 0;
}

int DrmSlowDiskDetectGetIostatFailTp(struct pt_regs *ctx) {
#ifndef PARAMS_DrmSlowDiskDetectGetIostatFailTp
    bpf_trace_printk("Need input diskId");
    return 0;
#endif

    void *ptr = NULL;
    int diskId = 0;

    bpf_usdt_readarg(1, ctx, &ptr);
    if (!ptr) { return 0; }
    bpf_probe_read_user(&diskId, sizeof(diskId), ptr);

#ifdef PARAMS_DrmSlowDiskDetectGetIostatFailTp
    // 解析用户输入的参数
    char params[] = PARAMS_DrmSlowDiskDetectGetIostatFailTp;        // 准备一个可修改的本地缓冲区，存放传入的字符串
    int values = 0;
    int idx = 0;

    // 遍历 params , 将逗号分隔的数字转为 int
    #pragma unroll
    for (int j = 0; j < sizeof(params); j++) {
        char c = params[j];
        if (c >= '0' && c <= '9') {
            values = values * 10 + (c - '0'); // 当前数字累加
        } else if (c == ',') {
            idx++;                                      // 遇到逗号，切换到下一个槽位
            if (idx >= DHA_SATA_HDD_SMART_ATTR_CNT) break;                        // 为安全起见：防止越界
        } else {
            if (c == '\0') break;                       // 既不是数字也不是逗号，忽略(如字符串末尾 '\0')
        }
    }
    if (values != diskId) {
        return 0;
    }
#endif

    int original_val, verified_val, new_val;
    bpf_usdt_readarg(2, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = -1;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Probe DrmSlowDiskDetectGetIostatFailTp: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    return 0;
}

#define DRM_SATA_SSD_DISK_GROUP 0
int DrmDprDiskInPrefail(struct pt_regs *ctx) {
#ifndef PARAMS_DrmDprDiskInPrefail
    bpf_trace_printk("Need input diskId");
    return 0;
#endif

    void *ptr = NULL;
    int diskId = 0;

    bpf_usdt_readarg(1, ctx, &ptr);
    if (!ptr) { return 0; }
    bpf_probe_read_user(&diskId, sizeof(diskId), ptr);

#ifdef PARAMS_DrmDprDiskInPrefail
    // 解析用户输入的参数
    char params[] = PARAMS_DrmDprDiskInPrefail;        // 准备一个可修改的本地缓冲区，存放传入的字符串
    int values = 0;
    int idx = 0;

    // 遍历 params , 将逗号分隔的数字转为 int
    #pragma unroll
    for (int j = 0; j < sizeof(params); j++) {
        char c = params[j];
        if (c >= '0' && c <= '9') {
            values = values * 10 + (c - '0'); // 当前数字累加
        } else if (c == ',') {
            idx++;                                      // 遇到逗号，切换到下一个槽位
            if (idx >= DHA_SATA_HDD_SMART_ATTR_CNT) break;                        // 为安全起见：防止越界
        } else {
            if (c == '\0') break;                       // 既不是数字也不是逗号，忽略(如字符串末尾 '\0')
        }
    }
    if (values != diskId) {
        return 0;
    }
#endif

    int original_val, verified_val, new_val;
    bpf_usdt_readarg(2, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = DRM_SATA_SSD_DISK_GROUP;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Probe DrmDprDiskInPrefail: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    return 0;
}
