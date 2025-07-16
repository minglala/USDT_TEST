/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Description: BOOSTER USDT HEADER
 * Create: 2025-7-16
 */

#ifndef BOOSTER_USDT_H
#define BOOSTER_USDT_H

#if defined(_DEBUG)

#include <sys/sdt.h>

/**
 * @brief 检查一个 BOOSTER USDT 探针是否被追踪工具启用。
 *
 * 工作原理:
 * 这是一个使用 GNU C 语句表达式 (Statement Expression) 实现的宏。
 * 1. 在栈上定义一个局部变量 is_enabled_flag = 0。
 * 2. 触发一个专用的“检查”探针 (约定为 探针名 + "_check")，
 * 并将 is_enabled_flag 的地址作为参数传递出去。
 * 3. 追踪工具如果启用，会通过该地址将 is_enabled_flag 的值修改为 1。
 * 4. 宏的最终值就是 is_enabled_flag 的值 (0 或 1)。
 *
 * @note 这依赖于 GNU C 编译器扩展。
 * @param name 探针的名称 (Probe Name)，无需加 "_check" 后缀，宏会自动添加。
 * @return 如果探针已启用，则返回非零值；否则返回 0。
 */
#define BOOSTER_PROBE_IS_ENABLED(name) \
    ({ \
        int is_enabled_flag = 0; \
        DTRACE_PROBE1(BOOSTER, name##_check, &is_enabled_flag); \
        is_enabled_flag; \
    })

/* DTrace 探针的封装宏 */
#define BOOSTER_DTRACE_PROBE1(name, a1)                 DTRACE_PROBE1(BOOSTER, name, a1)
#define BOOSTER_DTRACE_PROBE2(name, a1, a2)             DTRACE_PROBE2(BOOSTER, name, a1, a2)
#define BOOSTER_DTRACE_PROBE3(name, a1, a2, a3)         DTRACE_PROBE3(BOOSTER, name, a1, a2, a3)
#define BOOSTER_DTRACE_PROBE4(name, a1, a2, a3, a4)     DTRACE_PROBE4(BOOSTER, name, a1, a2, a3, a4)

/**
 * @brief DEBUG 模式下的探针代码块起始宏。
 *
 * @param condition 判断一个或多个探针是否启用的表达式。
 * 例如: BOOSTER_PROBE_IS_ENABLED(MyProbe)
 * @param probeCall 包含一个或多个 BOOSTER_DTRACE_PROBE* 调用的代码块。
 *
 * 工作原理：
 * 1. 首先，无条件执行 probeCall 代码块，以确保探针被触发。
 * 2. 然后，检查 condition。如果 condition 为 true（探针已启用），
 * 则跳过 LVOS_START_DTRACE 和 LVOS_END 之间的代码块。
 * 如果 condition 为 false（探针未启用），则执行该代码块。
 *
 * 这种设计允许通过探针注入故障，既可以通过修改探针参数来改变程序行为，
 * 也可以通过完全跳过某段原始代码来实现。
 */
#define LVOS_START_DTRACE(condition, probeCall) \
    do {                                        \
        probeCall;                              \
    } while (0);                                \
    if (condition) {} else {

#define LVOS_END \
    }

#else /* Release Mode */

/* 在非 DEBUG 模式下，所有探针相关的宏都为空定义或返回 false，以消除对性能的影响。 */
#define BOOSTER_PROBE_IS_ENABLED(name)                  (0)
#define BOOSTER_DTRACE_PROBE1(...)                      ((void)0)
#define BOOSTER_DTRACE_PROBE2(...)                      ((void)0)
#define BOOSTER_DTRACE_PROBE3(...)                      ((void)0)
#define BOOSTER_DTRACE_PROBE4(...)                      ((void)0)

/**
 * @brief 非 DEBUG 模式：探针调用(probeCall)被优化掉，原始代码块总是被执行。
 */
#define LVOS_START_DTRACE(condition, probeCall) \
    if (1) {

#define LVOS_END \
    }

#endif /* defined(_DEBUG) */

#endif /* BOOSTER_USDT_H */
