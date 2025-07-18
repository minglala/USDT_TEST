/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Description: BOOSTER USDT HEADER (全新设计)
 * Create: 2025-7-18
 */

#ifndef BOOSTER_USDT_H
#define BOOSTER_USDT_H

#if defined(_DEBUG)

#include <sys/sdt.h>

/* DTrace 探针的底层封装宏 */
#define BOOSTER_DTRACE_PROBE1(name, a1)                 DTRACE_PROBE1(BOOSTER, name, a1)
#define BOOSTER_DTRACE_PROBE2(name, a1, a2)             DTRACE_PROBE2(BOOSTER, name, a1, a2)
#define BOOSTER_DTRACE_PROBE3(name, a1, a2, a3)         DTRACE_PROBE3(BOOSTER, name, a1, a2, a3)
#define BOOSTER_DTRACE_PROBE4(name, a1, a2, a3, a4)     DTRACE_PROBE4(BOOSTER, name, a1, a2, a3, a4)

/**
 * @brief (全新设计) 故障注入代码块起始宏。
 *
 * 工作原理:
 * 1. 在代码块开始处定义一个 __lvos_skip_flag = 0 的局部变量。
 * 2. 触发一个探针，将用户提供的参数和 __lvos_skip_flag 的地址一起传递出去。
 * 3. eBPF 程序接收到所有参数，执行注入逻辑，并根据条件决定是否通过指针将 __lvos_skip_flag 修改为 1。
 * 4. 宏会创建一个 if (!__lvos_skip_flag) { ... } 块。
 * 5. 如果标志位为 0 (未被 eBPF 修改)，则 if 块内的原始代码被执行。
 * 6. 如果标志位为 1 (已被 eBPF 修改)，则 if 块被跳过。
 *
 * @param name 探针的名称。
 * @param ...  传递给探针的原始参数。
 */
#define LVOS_START_DTRACE1(name, arg1) \
    do { \
        volatile int __lvos_skip_flag = 0; \
        BOOSTER_DTRACE_PROBE2(name, arg1, &__lvos_skip_flag); \
        if (!__lvos_skip_flag) {

#define LVOS_START_DTRACE2(name, arg1, arg2) \
    do { \
        volatile int __lvos_skip_flag = 0; \
        BOOSTER_DTRACE_PROBE3(name, arg1, arg2, &__lvos_skip_flag); \
        if (!__lvos_skip_flag) {

#define LVOS_START_DTRACE3(name, arg1, arg2, arg3) \
    do { \
        volatile int __lvos_skip_flag = 0; \
        BOOSTER_DTRACE_PROBE4(name, arg1, arg2, arg3, &__lvos_skip_flag); \
        if (!__lvos_skip_flag) {

#define LVOS_END \
        } \
    } while (0);

#else /* Release Mode */

/* 在非 DEBUG 模式下，所有探针宏都为空定义，原始代码总是被执行。 */
#define BOOSTER_DTRACE_PROBE1(...)                      ((void)0)
#define BOOSTER_DTRACE_PROBE2(...)                      ((void)0)
#define BOOSTER_DTRACE_PROBE3(...)                      ((void)0)
#define BOOSTER_DTRACE_PROBE4(...)                      ((void)0)
#define LVOS_START_DTRACE1(name, ...)                   if (1) {
#define LVOS_START_DTRACE2(name, ...)                   if (1) {
#define LVOS_START_DTRACE3(name, ...)                   if (1) {
#define LVOS_END                                        }

#endif /* defined(_DEBUG) */

#endif /* BOOSTER_USDT_H */
