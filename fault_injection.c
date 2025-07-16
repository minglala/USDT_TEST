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

int DmgChangeWearNormalDay(struct pt_regs *ctx) {
    void *ptr = NULL;
    int original_val, verified_val, new_val;

    bpf_trace_printk("Probe DmgChangeWearNormalDay: Fired.\\n");

    bpf_usdt_readarg(1, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = 10;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Arg1: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    bpf_usdt_readarg(2, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = 0;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Arg2: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    bpf_usdt_readarg(3, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = 3000;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Arg3: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }
    return 0;
}

int DmgChangeWear90Day(struct pt_regs *ctx) {
    void *ptr = NULL;
    int original_val, verified_val, new_val;

    bpf_trace_printk("Probe DmgChangeWear90Day: Fired.\\n");

    bpf_usdt_readarg(1, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = 90;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Arg1: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    bpf_usdt_readarg(2, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = 0;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Arg2: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    bpf_usdt_readarg(3, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = 17270;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Arg3: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }
    return 0;
}

int DmgChangeWear30Day(struct pt_regs *ctx) {
    void *ptr = NULL;
    int original_val, verified_val, new_val;

    bpf_trace_printk("Probe DmgChangeWear30Day: Fired.\\n");

    bpf_usdt_readarg(1, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = 90;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Arg1: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    bpf_usdt_readarg(2, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = 0;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Arg2: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    bpf_usdt_readarg(3, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = 5390;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Arg3: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }
    return 0;
}

int DmgChangeWear1Day(struct pt_regs *ctx) {
    void *ptr = NULL;
    int original_val, verified_val, new_val;

    bpf_trace_printk("Probe DmgChangeWear1Day: Fired.\\n");

    bpf_usdt_readarg(1, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = 99;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Arg1: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    bpf_usdt_readarg(2, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = 0;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Arg2: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }

    bpf_usdt_readarg(3, ctx, &ptr);
    if (ptr) {
        bpf_probe_read_user(&original_val, sizeof(original_val), ptr);
        new_val = 1970;
        bpf_probe_write_user(ptr, &new_val, sizeof(new_val));
        bpf_probe_read_user(&verified_val, sizeof(verified_val), ptr);
        bpf_trace_printk("Arg3: read=%d, wrote=%d, verified=%d\\n", original_val, new_val, verified_val);
    }
    return 0;
}


/*
 * ==================================================================
 * Single-Argument Handlers with Enhanced "Read-Write-Verify" Logging
 * ==================================================================
 */

int DmgChangeCheckWhitelistTrue(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) {
        bpf_trace_printk("Probe DmgChangeCheckWhitelistTrue: Fired, but pointer is NULL.\\n");
        return 0;
    }
    int original_val, verified_val = -99;
    int new_value = 0;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DmgChangeCheckWhitelistTrue: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DmgChangeCheckWhitelistFalse(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = 1;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DmgChangeCheckWhitelistFalse: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DmgChangeCheckWhitelistCacheTrue(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    bool original_val, verified_val = false;
    bool new_value = true;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DmgChangeCheckWhitelistCacheTrue: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DmgChangeCheckWhitelistCacheFalse(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    bool original_val, verified_val = true;
    bool new_value = false;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DmgChangeCheckWhitelistCacheFalse: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DcmReturnLinkErrEinal(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = 22;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DcmReturnLinkErrEinal: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DcmReturnLinkErrEpipe(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(1, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = 32;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DcmReturnLinkErrEpipe: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
    return 0;
}

int DcmReturnLinkErrEnosys(struct pt_regs *ctx) {
    void *rc_pointer = NULL;
    bpf_usdt_readarg(2, ctx, &rc_pointer);
    if (!rc_pointer) { return 0; }
    int original_val, verified_val = -99;
    int new_value = 38;
    bpf_probe_read_user(&original_val, sizeof(original_val), rc_pointer);
    bpf_probe_write_user(rc_pointer, &new_value, sizeof(new_value));
    bpf_probe_read_user(&verified_val, sizeof(verified_val), rc_pointer);
    bpf_trace_printk("Probe DcmReturnLinkErrEnosys: Read=%d, Wrote=%d, Verified=%d\\n", original_val, new_value, verified_val);
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
